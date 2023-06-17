#include "thread.h"
#include "console.h"
#include "debug.h"
#include "global.h"
#include "interrupt.h"
#include "list.h"
#include "memory.h"
#include "print.h"
#include "stdint.h"
#include "string.h"

#define PG_SIZE 4096

struct task_struct *main_thread; // 主线程pcb
struct list thread_ready_list;
struct list thread_all_list;
static struct list_elem *thread_tag; // 保存队列中的线程结点

// 保存cur线程的寄存器映像，将下个线程next的寄存器映像装载到处理器
extern void switch_to(struct task_struct *cur, struct task_struct *next);

// 获取当前线程的pcb指针
struct task_struct *running_thread() {
  uint32_t esp;
  asm("mov %%esp, %0" : "=g"(esp));
  return (struct task_struct *)(esp &
                                0xfffff000); // 取esp整数部分，即pcb起始地址
}

// 由kernel_thread去执行func(func_arg)
static void kernel_thread(thread_func *func, void *func_arg) {
  intr_enable(); // 开中断避免func独享处理器
  func(func_arg);
}

// 初始化线程栈，将待执行func和func_arg放到栈中相应位置
void thread_create(struct task_struct *pthread, thread_func func,
                   void *func_arg) {
  // pthread->self_kstack -= sizeof(struct intr_stack); // 预留中断使用栈的空间
  pthread->self_kstack -= sizeof(struct thread_stack); // 预留线程栈空间

  struct thread_stack *kthread_stack =
      (struct thread_stack *)pthread->self_kstack;

  // kernel_thread使用ret方式调用
  kthread_stack->eip = kernel_thread;
  kthread_stack->function = func;
  kthread_stack->func_arg = func_arg;

  kthread_stack->ebp = kthread_stack->ebx = kthread_stack->esi =
      kthread_stack->edi = 0;
}

// 初始化线程基本信息
void init_thread(struct task_struct *pthread, char *name, int prio) {
  memset(pthread, 0, sizeof(*pthread)); // PCB一页清0
  strcpy(pthread->name, name);

  if (pthread == main_thread) {
    pthread->status = TASK_RUNNING;
  } else {
    pthread->status = TASK_READY;
  }

  pthread->self_kstack =
      (uint32_t *)((uint32_t)pthread + PG_SIZE); // 线程的内核栈顶地址
  pthread->priority = prio;
  pthread->ticks = prio;
  pthread->elapsed_ticks = 0;
  pthread->pgdir = NULL;
  pthread->stack_magic = 0x20021112; // 自定义魔数
}

// 创建线程，线程执行函数是function(func_arg)
struct task_struct *thread_start(char *name, int prio, thread_func func,
                                 void *func_arg) {
  struct task_struct *thread = get_kernel_pages(1); // PCB指针->最低地址
  init_thread(thread, name, prio);
  thread_create(thread, func, func_arg);

  ASSERT(!elem_find(&thread_ready_list, &thread->general_tag));
  list_append(&thread_ready_list, &thread->general_tag); // 加入就绪线程队列
  ASSERT(!elem_find(&thread_all_list, &thread->all_list_tag));
  list_append(&thread_all_list, &thread->all_list_tag); // 加入全部线程队列

  return thread;
}

// 将kernel中的main函数完善为主线程
static void make_main_thread(void) {
  main_thread = running_thread();
  init_thread(main_thread, "main", 31);

  ASSERT(!elem_find(&thread_all_list, &main_thread->all_list_tag));
  list_append(&thread_all_list, &main_thread->all_list_tag);
}

// 调度函数
void schedule() {
  ASSERT(intr_get_status() == INTR_OFF); // 关中断状态

  struct task_struct *cur = running_thread();
  if (cur->status == TASK_RUNNING) { // 时间片到了-> 加入就绪队列队尾
    ASSERT(!elem_find(&thread_ready_list, &cur->general_tag));
    list_append(&thread_ready_list, &cur->general_tag);
    cur->ticks = cur->priority;
    cur->status = TASK_READY;
  } else {
    // TODO：阻塞情况-> 加入阻塞队列
  }

  ASSERT(!list_empty(&thread_ready_list));
  thread_tag = NULL;
  thread_tag =
      list_pop(&thread_ready_list); // 弹出就绪队列中的下一个处理线程结点（tag）
  struct task_struct *next =
      elem2entry(struct task_struct, general_tag, thread_tag);
  next->status = TASK_RUNNING;
  switch_to(cur, next); // 任务切换
}

// 初始化线程环境
void thread_init(void) {
  put_str("thread_init start\n");
  list_init(&thread_ready_list);
  list_init(&thread_all_list);
  make_main_thread(); // 为当前main函数创建线程，在其pcb中写入线程信息
  put_str("thread_init done\n");
}

// 线程自愿阻塞，标志状态为stat
void thread_block(enum task_status stat) {
  // TASK_BLOCKED、TASK_WAITING、TASK_HANGING三种状态不会被调度
  ASSERT(((stat == TASK_BLOCKED) || (stat == TASK_WAITING) ||
          (stat == TASK_HANGING)));
  enum intr_status old_status = intr_disable();
  struct task_struct *cur_thread = running_thread();
  cur_thread->status = stat; // 修改状态为非RUNNING，不让其回到ready_list中
  schedule();                // 将当前线程换下处理器
  intr_set_status(old_status); // 待当前线程被解除阻塞后才继续运行
}

// 线程唤醒
void thread_unblock(struct task_struct *pthread) {
  enum intr_status old_status = intr_disable();
  ASSERT(((pthread->status == TASK_BLOCKED) ||
          (pthread->status == TASK_WAITING) ||
          (pthread->status == TASK_HANGING)));
  if (pthread->status != TASK_READY) {
    ASSERT(!elem_find(&thread_ready_list, &pthread->general_tag));
    if (elem_find(&thread_ready_list, &pthread->general_tag)) {
      PANIC("thread_unblock: blocked thread in ready_list\n");
    }
    list_push(&thread_ready_list,
              &pthread->general_tag); // 放在就绪队列最前面(尽快调度
    pthread->status = TASK_READY;
  }
  intr_set_status(old_status);
}