#include "thread.h"
#include "bitmap.h"
#include "console.h"
#include "debug.h"
#include "file.h"
#include "fs.h"
#include "global.h"
#include "interrupt.h"
#include "list.h"
#include "memory.h"
#include "print.h"
#include "process.h"
#include "stdint.h"
#include "stdio.h"
#include "string.h"
#include "sync.h"

#define PG_SIZE 4096

struct task_struct *main_thread; // 主线程pcb
struct list thread_ready_list;
struct list thread_all_list;
static struct list_elem *thread_tag; // 保存队列中的线程结点
struct lock pid_lock;                // 分配pid锁
struct task_struct *idle_thread;     // idle线程
uint8_t pid_bitmap_bits[128] = {0};  // pid位图，最多支持1024个pid

struct pid_pool {
  struct bitmap pid_bitmap;
  uint32_t pid_start;
  struct lock pid_lock;
} pid_pool;

// 保存cur线程的寄存器映像，将下个线程next的寄存器映像装载到处理器
extern void switch_to(struct task_struct *cur, struct task_struct *next);
extern void init(void);

// 获取当前线程的pcb指针
struct task_struct *running_thread() {
  uint32_t esp;
  asm("mov %%esp, %0" : "=g"(esp));
  return (struct task_struct *)(esp &
                                0xfffff000); // 取esp整数部分，即pcb起始地址
}

// 系统空闲时运行的线程
static void idle(void *arg UNUSED) {
  while (1) {
    thread_block(TASK_BLOCKED); // 阻塞自己
    asm volatile("sti; hlt" ::: "memory");
  }
}

static void pid_pool_init(void) {
  pid_pool.pid_start = 1;
  pid_pool.pid_bitmap.bits = pid_bitmap_bits;
  pid_pool.pid_bitmap.btmp_bytes_len = 128;
  bitmap_init(&pid_pool.pid_bitmap);
  lock_init(&pid_pool.pid_lock);
}

// 分配pid
static pid_t allocate_pid(void) {
  lock_acquire(&pid_pool.pid_lock);
  int32_t bit_idx = bitmap_scan(&pid_pool.pid_bitmap, 1);
  bitmap_set(&pid_pool.pid_bitmap, bit_idx, 1);
  lock_release(&pid_pool.pid_lock);
  return (bit_idx + pid_pool.pid_start);
}

// 释放pid
void release_pid(pid_t pid) {
  lock_acquire(&pid_pool.pid_lock);
  int32_t bit_idx = pid - pid_pool.pid_start;
  bitmap_set(&pid_pool.pid_bitmap, bit_idx, 0);
  lock_release(&pid_pool.pid_lock);
}

// 由kernel_thread去执行func(func_arg)
static void kernel_thread(thread_func *func, void *func_arg) {
  intr_enable(); // 开中断避免func独享处理器
  func(func_arg);
}

// 初始化线程栈，将待执行func和func_arg放到栈中相应位置
void thread_create(struct task_struct *pthread, thread_func func,
                   void *func_arg) {
  pthread->self_kstack -= sizeof(struct intr_stack); // 预留中断使用栈的空间
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
  pthread->pid = allocate_pid();
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
  pthread->fd_table[0] = 0; // 标准输入
  pthread->fd_table[1] = 1; // 标准输出
  pthread->fd_table[2] = 2; // 标准错误
  uint8_t fd_idx = 3;
  while (fd_idx < MAX_FILES_OPEN_PER_PROC) { // 其余全部置-1
    pthread->fd_table[fd_idx] = -1;
    fd_idx++;
  }
  pthread->cwd_inode_nr = 0;         // 以根目录为默认工作路径
  pthread->stack_magic = 0x20021112; // 自定义魔数
  pthread->parent_pid = -1;
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
  }

  // 就绪队列中没有可运行任务-> 唤醒idle
  if (list_empty(&thread_ready_list)) {
    thread_unblock(idle_thread);
  }
  thread_tag = NULL;
  thread_tag =
      list_pop(&thread_ready_list); // 弹出就绪队列中的下一个处理线程结点（tag）
  struct task_struct *next =
      elem2entry(struct task_struct, general_tag, thread_tag);
  next->status = TASK_RUNNING;

  /* 激活页表，并根据任务是否为进程来修改tss.esp0 */
  process_active(next);
  // 从此之后进程/线程一律作为内核线程去处理（0特权级、使用内核页表）

  switch_to(cur, next); // 任务切换
}

// 主动让出cpu，换其他线程运行
void thread_yield(void) {
  struct task_struct *cur = running_thread();
  enum intr_status old_status = intr_disable();
  ASSERT(!elem_find(&thread_ready_list, &cur->general_tag));
  list_append(&thread_ready_list, &cur->general_tag);
  cur->status = TASK_READY; // 与thread_block区别
  schedule();
  intr_set_status(old_status);
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

// 回收线程的pcb和页表，并将其从调度队列中删除
void thread_exit(struct task_struct *thread_over, bool need_schedule) {
  intr_disable(); // 要保证schedule在关中断情况下调用
  thread_over->status = TASK_DIED;

  // 不是当前线程-> 可能还在就绪队列中，删除
  if (elem_find(&thread_ready_list, &thread_over->general_tag)) {
    list_remove(&thread_over->general_tag);
  }
  if (thread_over->pgdir) { // 是进程-> 回收进程页表
    mfree_page(PF_KERNEL, thread_over->pgdir, 1);
  }

  list_remove(&thread_over->all_list_tag);
  if (thread_over != main_thread) { // 主线程pcb在内核低1MB而不在堆中，跳过
    mfree_page(PF_KERNEL, thread_over, 1); // 回收pcb所在页
  }

  release_pid(thread_over->pid);
  // 如果需要下一轮调度则主动调schedule
  if (need_schedule) {
    schedule();
    PANIC("thread_exit: should not be here\n");
  }
}

// 比对任务的pid (回调函数
static bool pid_check(struct list_elem *pelem, int32_t pid) {
  struct task_struct *pthread =
      elem2entry(struct task_struct, all_list_tag, pelem);
  if (pthread->pid == pid) {
    return true;
  }
  return false;
}

// 根据pid找pcb
struct task_struct *pid2thread(int32_t pid) {
  struct list_elem *pelem = list_traversal(&thread_all_list, pid_check, pid);
  if (pelem == NULL) {
    return NULL;
  }
  struct task_struct *thread =
      elem2entry(struct task_struct, all_list_tag, pelem);
  return thread;
}

// 为fork分配一个pid
pid_t fork_pid(void) { return allocate_pid(); }

// 对齐输出
static void pad_print(char *buf, int32_t buf_len, void *ptr, char format) {
  memset(buf, 0, buf_len);
  uint8_t out_pad_0idx = 0;

  switch (format) {
  case 's': // 字符串
    out_pad_0idx = sprintf(buf, "%s", ptr);
    break;
  case 'd': // 16位整数
    out_pad_0idx = sprintf(buf, "%d", *((int16_t *)ptr));
  case 'x': // 32位整数
    out_pad_0idx = sprintf(buf, "%x", *((uint32_t *)ptr));
  }

  while (out_pad_0idx < buf_len) { // 以空格填充
    buf[out_pad_0idx] = ' ';
    out_pad_0idx++;
  }
  sys_write(stdout_no, buf, buf_len - 1);
}

// list_traversal中的回调函数，针对线程队列处理
static bool elem2thread_info(struct list_elem *pelem, int arg UNUSED) {
  struct task_struct *pthread =
      elem2entry(struct task_struct, all_list_tag, pelem);
  char out_pad[16] = {0};
  pad_print(out_pad, 16, &pthread->pid, 'd');
  if (pthread->parent_pid == -1) {
    pad_print(out_pad, 16, "NULL", 's');
  } else {
    pad_print(out_pad, 16, &pthread->parent_pid, 'd');
  }

  switch (pthread->status) {
  case 0:
    pad_print(out_pad, 16, "RUNNING", 's');
    break;
  case 1:
    pad_print(out_pad, 16, "READY", 's');
    break;
  case 2:
    pad_print(out_pad, 16, "BLOCKED", 's');
    break;
  case 3:
    pad_print(out_pad, 16, "WAITING", 's');
    break;
  case 4:
    pad_print(out_pad, 16, "HANGING", 's');
    break;
  case 5:
    pad_print(out_pad, 16, "DIED", 's');
  }
  pad_print(out_pad, 16, &pthread->elapsed_ticks, 'x');
  memset(out_pad, 0, 16);
  ASSERT(strlen(pthread->name) < 17);
  memcpy(out_pad, pthread->name, strlen(pthread->name));
  strcat(out_pad, "\n");
  sys_write(stdout_no, out_pad, strlen(out_pad));
  return false; // 主调函数中继续调用此函数
}

// 打印任务列表
void sys_ps(void) {
  char *ps_title = "PID       PPID        STAT        TICKS       COMMAND\n";
  sys_write(stdout_no, ps_title, strlen(ps_title));
  list_traversal(&thread_all_list, elem2thread_info, 0);
}

// 初始化线程环境
void thread_init(void) {
  put_str("thread_init start\n");

  list_init(&thread_ready_list);
  list_init(&thread_all_list);
  pid_pool_init();

  //process_execute(init, "init"); // 第一个初始化，这是第一个进程，init进程pid为1
  make_main_thread(); // 为当前main函数创建线程，在其pcb中写入线程信息
  idle_thread = thread_start("idle", 10, idle, NULL); // 创建idle线程
  put_str("thread_init done\n");
}