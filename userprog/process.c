#include "bitmap.h"
#include "console.h"
#include "debug.h"
#include "global.h"
#include "interrupt.h"
#include "list.h"
#include "memory.h"
#include "stdint.h"
#include "string.h"
#include "thread.h"
#include "tss.h"
#include "userprog.h"

extern void intr_exit(void);

// 创建用户进程filename的上下文（填充用户进程的中断栈intr_stack
void start_process(void *filename_) {
  void *func = filename_;
  struct task_struct *cur = running_thread();
  cur->self_kstack +=
      sizeof(struct thread_stack); // 此时self_kstack指向中断栈栈顶
  /*
   *【创建线程的时候没预留但是运行正常的原因猜测】
   * 此时处与内核态，指针可能指向了内核空间。
   * PCB放在内核空间中，导致越界的空间可能是刚好初始化预留过的
   */
  struct intr_stack *proc_stack = (struct intr_stack *)cur->self_kstack;
  proc_stack->edi = 0;
  proc_stack->esi = 0;
  proc_stack->ebp = 0;
  proc_stack->esp_dummy = 0;

  proc_stack->ebx = 0;
  proc_stack->edx = 0;
  proc_stack->ecx = 0;
  proc_stack->eax = 0;

  proc_stack->gs = 0; // 显存段用户态用不上

  proc_stack->ds = SELECTOR_U_DATA;
  proc_stack->es = SELECTOR_U_DATA;
  proc_stack->fs = SELECTOR_U_DATA;

  proc_stack->eip = func; // 待执行的用户程序
  proc_stack->cs = SELECTOR_U_CODE;
  proc_stack->eflags = (EFLAGS_IOPL_0 | EFLAGS_MBS | EFLAGS_IF_1);

  // 为用户进程分配3特权级栈->（esp指向从用户内存池中分配的地址
  proc_stack->esp =
      (void *)((uint32_t)get_a_page(PF_USER, USER_STACK3_VADDR) + PG_SIZE);
  proc_stack->ss = SELECTOR_U_DATA; // 栈段

  asm volatile("movl %0, %%esp; jmp intr_exit" ::"g"(proc_stack) : "memory");
}

// 激活进程/线程页表-> 更新cr3
void page_dir_activate(struct task_struct *p_thread) {
  // 内核线程，默认为内核页目录物理地址
  uint32_t pagedir_phy_addr = 0x100000;
  if (p_thread->pgdir != NULL) { // 用户进程有自己的页目录表
    pagedir_phy_addr = addr_v2p((uint32_t)p_thread->pgdir);
  }
  asm volatile("movl %0, %%cr3" ::"r"(pagedir_phy_addr) : "memory");
}

// 激活页表，并根据任务是否为进程来修改tss.esp0
void process_active(struct task_struct *p_thread) {
  ASSERT(p_thread != NULL);
  page_dir_activate(p_thread);

  if (p_thread->pgdir) {
    // 更新tss.esp0-> 进程的特权级0栈，用于此进程中断进入内核态下保留上下文
    update_tss_esp(p_thread);
  }
}

// 创建页目录表，返回页目录虚拟地址
uint32_t *create_page_dir(void) {
  uint32_t *page_dir_vaddr = get_kernel_pages(1); // 内核空间申请
  if (page_dir_vaddr == NULL) {
    console_put_str("create_page_dir: get_kernel_page failed!");
    return NULL;
  }

  // 为让所有进程共享内核：将内核所在页目录项（访问内核的入口）复制到进程页目录项目的同等位置
  // 1、复制页表（page_dir_vaddr + 0x300*4 ：内核页目录第768项
  memcpy((uint32_t *)((uint32_t)page_dir_vaddr + 0x300 * 4),
         (uint32_t *)(0xfffff000 + 0x300 * 4), 1024);
  // 2、更新页目录地址
  uint32_t new_page_dir_phy_addr = addr_v2p((uint32_t)page_dir_vaddr);
  page_dir_vaddr[1023] =
      new_page_dir_phy_addr | PG_US_U | PG_RW_W | PG_P_1; // 最后一项指向自己

  return page_dir_vaddr;
}

// 创建用户进程的虚拟内存池（bitmap
void create_user_vaddr_bitmap(struct task_struct *user_prog) {
  user_prog->userprog_vaddr.vaddr_start = USER_VADDR_START;
  uint32_t bitmap_pg_cnt =
      DIV_ROUND_UP((0xc0000000 - USER_VADDR_START) / PG_SIZE / 8, PG_SIZE);
  user_prog->userprog_vaddr.vaddr_bitmap.bits = get_kernel_pages(bitmap_pg_cnt);
  user_prog->userprog_vaddr.vaddr_bitmap.btmp_bytes_len =
      (0xc0000000 - USER_VADDR_START) / PG_SIZE / 8;
  bitmap_init(&user_prog->userprog_vaddr.vaddr_bitmap);
}

// 创建用户进程
void process_execute(void *filename, char *name) { // filename：用户进程地址
  struct task_struct *thread = get_kernel_pages(1);
  init_thread(thread, name, default_prio);
  create_user_vaddr_bitmap(thread);
  thread_create(thread, start_process, filename);
  thread->pgdir = create_page_dir();

  enum intr_status old_status = intr_disable();
  ASSERT(!elem_find(&thread_ready_list, &thread->general_tag));
  list_append(&thread_ready_list, &thread->general_tag);

  ASSERT(!elem_find(&thread_all_list, &thread->all_list_tag));
    list_append(&thread_all_list, &thread->all_list_tag);
  intr_set_status(old_status);
}