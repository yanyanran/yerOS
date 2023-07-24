#include "wait_exit.h"

#include "debug.h"
#include "file.h"
#include "fs.h"
#include "list.h"
#include "pipe.h"

/* 释放用户进程资源:
 * 1 页表中对应的物理页
 * 2 虚拟内存池占物理页框
 * 3 关闭打开的文件 */
static void realease_prog_resource(struct task_struct *release_thread) {
  uint32_t *pgdir_vaddr = release_thread->pgdir;

  uint16_t user_pde_nr = 768, pde_idx = 0;
  uint32_t pde = 0;
  uint32_t *v_pde_ptr = NULL;

  uint16_t user_pte_nr = 1024, pte_idx = 0;
  uint32_t pte = 0;
  uint32_t *v_pte_ptr = NULL;

  uint32_t *first_pte_vaddr_in_pde = NULL;

  uint32_t pg_phy_addr = 0;

  /* 回收页表中用户空间的页框 */
  while (pde_idx < user_pde_nr) {
    v_pde_ptr = pgdir_vaddr + pde_idx;
    pde = *v_pde_ptr;
    if (pde & 0x00000001) {
      first_pte_vaddr_in_pde = pte_ptr(pde_idx * 0x400000);
      pte_idx = 0;
      while (pte_idx < user_pte_nr) {
        v_pte_ptr = first_pte_vaddr_in_pde + pte_idx;
        pte = *v_pte_ptr;
        if (pte & 0x00000001) {
          // 在位图中清零
          pg_phy_addr = pte & 0xfffff000;
          free_a_phy_page(pg_phy_addr);
        }
        pte_idx++;
      }

      pg_phy_addr = pde & 0xfffff000;
      free_a_phy_page(pg_phy_addr);
    }
    pde_idx++;
  }
  /* 回收用户虚拟地址池所占的物理内存*/
  uint32_t bitmap_pg_cnt =
      (release_thread->userprog_vaddr.vaddr_bitmap.btmp_bytes_len) / PG_SIZE;
  uint8_t *user_vaddr_pool_bitmap =
      release_thread->userprog_vaddr.vaddr_bitmap.bits;
  mfree_page(PF_KERNEL, user_vaddr_pool_bitmap, bitmap_pg_cnt);

  /* 关闭进程打开的文件 */
  uint8_t local_fd = 3;
  while (local_fd < MAX_FILES_OPEN_PER_PROC) {
    if (release_thread->fd_table[local_fd] != -1) { // 关闭进程打开的文件
      if (is_pipe(local_fd)) {
        uint32_t global_fd = fd_local2global(local_fd);
        if (--file_table[global_fd].fd_pos == 0) {
          mfree_page(PF_KERNEL, file_table[global_fd].fd_inode, 1);
          file_table[global_fd].fd_inode = NULL;
        }
      } else {
        sys_close(local_fd);
      }
    }
    local_fd++;
  }
}

/* list_traversal 的回调函数,
 * 查找 pelem 的 parent_pid 是否是 ppid,成功返回 true,失败则返回 false */
static bool find_child(struct list_elem *pelem, int32_t ppid) {
  struct task_struct *pthread =
      elem2entry(struct task_struct, all_list_tag, pelem);
  if (pthread->parent_pid == ppid) {
    return true;
  }
  return false;
}

/* list_traversal 的回调函数,
 * 查找状态为 TASK_HANGING 的任务 */
static bool find_hanging_child(struct list_elem *pelem, int32_t ppid) {
  struct task_struct *pthread =
      elem2entry(struct task_struct, all_list_tag, pelem);
  if (pthread->parent_pid == ppid && pthread->status == TASK_HANGING) {
    return true;
  }
  return false;
}

/* list_traversal 的回调函数,
 * 将一个子进程过继给 init */
static bool init_adopt_a_child(struct list_elem *pelem, int32_t pid) {
  struct task_struct *pthread =
      elem2entry(struct task_struct, all_list_tag, pelem);
  if (pthread->parent_pid == pid) {
    pthread->parent_pid = 1;
    return true;
  }
  return false;
}

/* 等待子进程调用 exit,将子进程的退出状态保存到 status 指向的变量.
 * 成功则返回子进程的 pid,失败则返回−1 */
pid_t sys_wait(int32_t *status) {
  struct task_struct *parent_thread = running_thread();
  while (1) {
    /* 优先处理已经是挂起状态的任务 */
    struct list_elem *child_elem = list_traversal(
        &thread_all_list, find_hanging_child, parent_thread->pid);
    /*若有挂起的子进程*/
    if (child_elem != NULL) {
      struct task_struct *child_thread =
          elem2entry(struct task_struct, all_list_tag, child_elem);
      *status = child_thread->exit_status;

      /* thread_exit 之后,pcb 会被回收,因此提前获取 pid */
      uint16_t child_pid = child_thread->pid;

      /*从就绪队列和全部队列中删除进程表项*/
      thread_exit(child_thread, false);

      return child_pid;
    }
    /*判断是否有子进程*/
    child_elem =
        list_traversal(&thread_all_list, find_child, parent_thread->pid);
    if (child_elem == NULL) {
      return -1;
    } else {
      thread_block(TASK_WAITING);
    }
  }
}

/*子进程用来结束自己时调用*/
void sys_exit(int32_t status) {
  struct task_struct *child_thread = running_thread();
  child_thread->exit_status = status;
  if (child_thread->parent_pid == -1) {
    PANIC("sys_exit: child_thread->parent_pid is -1\n");
  }
  /* 将进程 child_thread 的所有子进程都过继给 init */
  list_traversal(&thread_all_list, init_adopt_a_child, child_thread->pid);

  /* 回收进程 child_thread 的资源 */
  realease_prog_resource(child_thread);
  /* 如果父进程正在等待子进程退出,将父进程唤醒 */
  struct task_struct *parent_thread = pid2thread(child_thread->parent_pid);
  if (parent_thread->status == TASK_WAITING) {
    thread_unblock(parent_thread);
  }

  // 将自己挂起,等待父进程获取其status,并回收其pcb
  thread_block(TASK_HANGING);
}