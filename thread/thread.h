#ifndef THREAD_THREAD
#define THREAD_THREAD
#include "bitmap.h"
#include "list.h"
#include "memory.h"
#include "stdint.h"

// 自定义通用函数类型，它将在很多线程函数中作为形参类型
typedef void thread_func(void *);

// 进程/线程状态
enum task_status {
  TASK_RUNNING,
  TASK_READY,
  TASK_BLOCKED,
  TASK_WAITING,
  TASK_HANGING,
  TASK_DIED
};

/**************************** 中断栈 intr_stack ***************************
 * 中断时保护程序（线程/进程）的上下文环境，在线程自己的内核栈中位置固定->页最顶端
 ************************************************************************/
struct intr_stack {
  uint32_t vec_no; // kernel.S宏VECTOR中push %1压入的中断号
  uint32_t edi;
  uint32_t esi;
  uint32_t ebp;
  uint32_t esp_dummy;
  uint32_t ebx;
  uint32_t edx;
  uint32_t ecx;
  uint32_t eax;
  uint32_t gs;
  uint32_t fs;
  uint32_t es;
  uint32_t ds;

  // 以下由cpu从低特权级进入高特权级时压入
  uint32_t err_code; // err_code会被压入在eip之后
  void (*eip)(void);
  uint32_t cs;
  uint32_t eflags;
  void *esp;
  uint32_t ss;
};

/***************** 线程栈 thread_stack*************************
 * 线程自己的栈，位置不固定（当前执行函数没有线程栈，调度切换线程时才创建，被调度时被pop弹出）
 *******************************************************************************/
struct thread_stack {
  uint32_t ebp;
  uint32_t ebx;
  uint32_t edi;
  uint32_t esi;

  // 线程第一次执行时eip保存待调用函数地址，其他时候eip指向switch_to（任务切换）返回地址
  void (*eip)(thread_func *func, void *func_arg);

  /***** 以下仅供第一次被调度上cpu时使用 ****/
  void(*unused_retaddr); // 参数只为占位置充数为返回地址
  thread_func *function; // 由 kernel_thread 所调用的函数名
  void *func_arg;        // 调用函数所需的参数
};

// 进程/线程pcb，程序控制块
struct task_struct {
  uint32_t *self_kstack; // 栈顶指针
  enum task_status status;
  char name[16];
  uint8_t priority; // 线程优先级

  uint8_t ticks;          // 上cpu执行的时间（优先级越高ticks越大
  uint32_t elapsed_ticks; // 上cpu运行后占用的时间（任务执行了多久
  struct list_elem general_tag;  // 一般list队列中的结点
  struct list_elem all_list_tag; // thread_all_list中的结点

  uint32_t *pgdir;                    // 进程页目录表的虚拟地址
  struct virtual_addr userprog_vaddr; // 用户进程的虚拟地址
  uint32_t stack_magic;               // 栈的边界标记，检测栈的溢出
};

extern struct list thread_ready_list;
extern struct list thread_all_list;

struct task_struct *thread_start(char *name, int prio, thread_func func,
                                 void *func_arg);
struct task_struct *running_thread();
void schedule();
void thread_init(void);
void thread_block(enum task_status stat);
void thread_unblock(struct task_struct *pthread);
void init_thread(struct task_struct *pthread, char *name, int prio);
void thread_create(struct task_struct *pthread, thread_func func,
                   void *func_arg);

#endif /* THREAD_THREAD */
