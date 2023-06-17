#include "sync.h"
#include "debug.h"
#include "interrupt.h"
#include "list.h"
#include "stdint.h"
#include "thread.h"

void sema_init(struct semaphore *psema, uint8_t value) {
  psema->value = value;
  list_init(&psema->waiters);
}

void lock_init(struct lock *plock) {
  plock->holder = NULL;
  plock->holder_repeat_nr = 0;
  sema_init(&plock->semaphore, 1);
}

void sema_down(struct semaphore *psema) {
  enum intr_status old_status = intr_disable();
  while (psema->value == 0) { // 已经被别人持有
    ASSERT(!elem_find(&psema->waiters, &running_thread()->general_tag));
    if (elem_find(&psema->waiters, &running_thread()->general_tag)) {
      PANIC("sema_down: thread blocked has been in waiters_list\n");
    }
    // 当前线程把自己加入该锁的等待队列，然后阻塞自己
    list_append(&psema->waiters, &running_thread()->general_tag);
    thread_block(TASK_BLOCKED);
  }
  // value=1或被唤醒后-> 获得锁
  psema->value--;
  ASSERT(psema->value == 0);
  intr_set_status(old_status);
}

void sema_up(struct semaphore *psema) {
  enum intr_status old_status = intr_disable();
  ASSERT(psema->value == 0);
  if (!list_empty(&psema->waiters)) {
    struct task_struct *thread_blocked =
        elem2entry(struct task_struct, general_tag, list_pop(&psema->waiters));
    thread_unblock(thread_blocked);
  }
  psema->value++;
  ASSERT(psema->value == 1);
  intr_set_status(old_status);
}

// 获取锁plock
void lock_acquire(struct lock *plock) {
  if (plock->holder != running_thread()) { // 判断是否已持有该锁
    sema_down(&plock->semaphore);          // 信号量P操作(原子
    plock->holder = running_thread();
    ASSERT(plock->holder_repeat_nr == 0);
    plock->holder_repeat_nr = 1;
  } else {
    plock->holder_repeat_nr++;
  }
}

// 释放锁plock
void lock_release(struct lock *plock) {
  ASSERT(plock->holder == running_thread());
  if (plock->holder_repeat_nr > 1) {
    // 此时还不能释放锁
    plock->holder_repeat_nr--;
    return;
  }
  ASSERT(plock->holder_repeat_nr == 1);

  plock->holder = NULL; // 把锁的持有者置空放在V操作前
  plock->holder_repeat_nr = 0;
  sema_up(&plock->semaphore); // 信号量V操作(原子
}