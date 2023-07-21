#include "assert.h"
#include "debug.h"
#include "fs.h"
#include "global.h"
#include "list.h"
#include "memory.h"
#include "stdint.h"
#include "thread.h"

/*
 * 释放用户进程资源：
 * 1、页表中的物理页
 * 2、虚拟内存池占物理页
 * 3、关闭打开的文件
 */
static void release_prog_resource(struct task_struct *release_thread) {
  uint32_t *pgdir_vaddr = release_thread->pgdir;
  uint16_t user_pde_num = 768, pde_idx = 0; // 页目录项
  uint32_t pde = 0;
  uint32_t *v_pde_ptr = NULL;

  uint16_t user_pte_num = 1024, pte_idx = 0; // 页表项
  uint32_t pte = 0;
  uint32_t *v_pte_ptr = NULL;

  uint32_t *first_pte_vaddr_in_pde = NULL; // pde中第0个pte的地址
  uint32_t pg_phy_addr = 0;

  // 回收页表中用户空间的页
  while (pde_idx < user_pde_num) {
    v_pde_ptr = pgdir_vaddr + pde_idx;
    pde = *v_pde_ptr;
    if (pde & 0x00000001) { // 页目录项p位为1-> 该页目录项下可能有页表项
      first_pte_vaddr_in_pde =
          pte_ptr(pde_idx * 0x400000); // 一个页表内存容量4MB
      pte_idx = 0;
      while (pte_idx < user_pte_num) {
        v_pte_ptr = first_pte_vaddr_in_pde + pte_idx;
        pte = *v_pte_ptr;
        if (pte & 0x00000001) {
          // 将pte中记录的物理页框直接在相应内存池的位图中清0
          pg_phy_addr = pte & 0xfffff000; // pte低12位为属性，高位为物理地址
          free_a_phy_page(pg_phy_addr);
        }
        pte_idx++;
      }
      // 将pde中记录的物理页框直接在相应内存池的位图中清0
      pg_phy_addr = pde & 0xfffff000;
      free_a_phy_page(pg_phy_addr);
    }
    pde_idx++;
  }
  // 回收用户虚拟地址池所占的物理内存
  uint32_t bitmap_pg_cnt =
      (release_thread->userprog_vaddr.vaddr_bitmap.btmp_bytes_len) / PG_SIZE;
  uint8_t *user_vaddr_pool_bitmap =
      release_thread->userprog_vaddr.vaddr_bitmap.bits;
  mfree_page(PF_KERNEL, user_vaddr_pool_bitmap, bitmap_pg_cnt);

  uint8_t fd_idx = 3;
  while (fd_idx < MAX_FILES_OPEN_PER_PROC) {
    if (release_thread->fd_table[fd_idx] != -1) { // 关闭进程打开的文件
      sys_close(fd_idx);
    }
    fd_idx++;
  }
}

// 查找pelem的parent_pid是否是ppid（回调函数
static bool find_child(struct list_elem *pelem, int32_t ppid) {
  // elem2entry 中间的参数 all_list_tag 取决于 pelem 对应的变量名
  struct task_struct *pthread =
      elem2entry(struct task_struct, all_list_tag, pelem);
  if (pthread->parent_pid == ppid) {
    return true; // 停止遍历
  }
  return false;
}

// 查找状态为TASK_HANGING的任务（回调函数
static bool find_hanging_child(struct list_elem *pelem, int32_t ppid) {
  struct task_struct *pthread =
      elem2entry(struct task_struct, all_list_tag, pelem);
  if (pthread->parent_pid == ppid && pthread->status == TASK_HANGING) {
    return true;
  }
  return false;
}

// 将一个子进程过继给init（回调函数
static bool init_adopt_a_child(struct list_elem *pelem, int32_t pid) {
  struct task_struct *pthread =
      elem2entry(struct task_struct, all_list_tag, pelem);
  if (pthread->parent_pid == pid) {
    pthread->parent_pid = 1;
  }
  return false;
}

pid_t sys_wait(int32_t *status) {
  struct task_struct *parent_thread = running_thread();
  while (1) {
    struct list_elem *child_elem = list_traversal( // 优先处理已是挂起状态任务
        &thread_all_list, find_hanging_child, parent_thread->pid);
    if (child_elem != NULL) {
      struct task_struct *child_thread =
          elem2entry(struct task_struct, all_list_tag, child_elem);
      *status = child_thread->exit_status;
      uint16_t child_pid = child_thread->pid; // 提前保存pid
      thread_exit(child_thread,
                  false); // 传入false-> 使thread_exit调用后回到此处
      return child_pid;
    }

    // 判断是否存在子进程
    child_elem =
        list_traversal(&thread_all_list, find_child, parent_thread->pid);
    if (child_elem == NULL) {
      return -1;
    } else {
      // 子进程没运行完成-> 将自己挂起直到子进程执行exit时将自己唤醒
      thread_block(TASK_WAITING);
    }
  }
}

void sys_exit(int32_t status) {
  struct task_struct *child_thread = running_thread();
  child_thread->exit_status = status;
  if (child_thread->parent_pid == -1) {
    PANIC("sys_exit: child_thread->parent_pid is -1\n");
  }

  // 将child_thread所有子进程过继给init
  list_traversal(&thread_all_list, init_adopt_a_child, child_thread->pid);
  release_prog_resource(child_thread);

  // 判断父进程是否等待子进程退出
  struct task_struct *parent_thread = pid2thread(child_thread->parent_pid);
  if (parent_thread->status == TASK_WAITING) {
    thread_unblock(parent_thread); // 唤醒父进程
  }
  // 将自己挂起，等待父进程获取其status并回收其pcb
  thread_block(TASK_HANGING);
}