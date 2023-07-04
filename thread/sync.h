#ifndef THREAD_SYNC
#define THREAD_SYNC
#include "list.h"
#include "stdint.h"
#include "thread.h"

// 信号量
struct semaphore {
  uint8_t value;
  struct list waiters; // 记录在此信号量上阻塞的所有线程
};

// 锁结构
struct lock {
  struct task_struct *holder; // 锁持有者
  struct semaphore semaphore; // 二元信号量实现锁
  uint32_t holder_repeat_nr;  // 锁持有者重复申请锁的次数
};

void lock_init(struct lock *plock);
void lock_acquire(struct lock *plock);
void lock_release(struct lock *plock);
void sema_init(struct semaphore *psema, uint8_t value);
void sema_down(struct semaphore *psema);
void sema_up(struct semaphore *psema);

#endif /* THREAD_SYNC */
