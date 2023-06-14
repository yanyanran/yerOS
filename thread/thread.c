#include "thread.h"
#include "global.h"
#include "memory.h"
#include "stdint.h"
#include "string.h"

#define PG_SIZE 4096

// 由kernel_thread去执行function(func_arg)
static void kernel_thread(thread_func *func, void *func_arg) { func(func_arg); }

// 初始化线程栈，将待执行func和func_arg放到栈中相应位置
void thread_creat(struct task_struct *pthread, thread_func func,
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
  strcpy(pthread->name, name);
  pthread->status = TASK_RUNNING;
  pthread->priority = prio;
  pthread->self_kstack =
      (uint32_t *)((uint32_t)pthread + PG_SIZE); // 线程的内核栈顶地址
  pthread->stack_magic = 0x20021112;             // 自定义魔数
}

// 创建线程，线程执行函数是function(func_arg)
struct task_struct *thread_start(char *name, int prio, thread_func func,
                                 void *func_arg) {
  struct task_struct *thread = get_kernel_pages(1); // PCB指针->最低地址
  init_thread(thread, name, prio);
  thread_creat(thread, func, func_arg);

  asm volatile(
      "movl %0, %%esp; pop %%ebp; pop %%ebx; pop %%edi; pop %%esi; ret" ::"g"(
          thread->self_kstack)
      : "memory");
  return thread;
}