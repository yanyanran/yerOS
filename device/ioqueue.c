#include "ioqueue.h"
#include "debug.h"
#include "global.h"
#include "interrupt.h"
#include "stdint.h"

void ioqueue_init(struct ioqueue *ioq) {
  lock_init(&ioq->lock);
  ioq->producer = ioq->consumer = NULL;
  ioq->head = ioq->tail = 0;
}

// 返回pos在缓冲区中的下一个位置值
static int32_t next_pos(int32_t pos) { return (pos + 1) % bufsize; }

bool ioq_full(struct ioqueue *ioq) {
  ASSERT(intr_get_status() == INTR_OFF);
  return next_pos(ioq->head) == ioq->tail;
}

bool ioq_empty(struct ioqueue *ioq) {
  ASSERT(intr_get_status() == INTR_OFF);
  return ioq->head == ioq->tail;
}

// 使当前生产者/消费者在此缓冲区上等待
static void ioq_wait(struct task_struct **waiter) {
  ASSERT(*waiter == NULL && waiter != NULL);
  *waiter = running_thread();
  thread_block(TASK_BLOCKED);
}

// 唤醒waiter
static void wakeup(struct task_struct **waiter) {
  ASSERT(*waiter != NULL);
  thread_unblock(*waiter);
  *waiter = NULL;
}

// 消费者从ioq队列中读一字节
char ioq_getchar(struct ioqueue *ioq) {
  ASSERT(intr_get_status() == INTR_OFF);
  while (ioq_empty(ioq)) {
    // 缓冲区为空-> 先睡眠
    lock_acquire(&ioq->lock);
    ioq_wait(&ioq->consumer);
    lock_release(&ioq->lock);
  }
  char byte = ioq->buf[ioq->tail]; // 从缓冲区中取出
  ioq->tail = next_pos(ioq->tail); // 把读游标移到下一位置
  if (ioq->producer != NULL) {
    wakeup(&ioq->producer); // 唤醒生产者
  }
  return byte;
}

// 生产者往ioq队列中写一字节
void ioq_putchar(struct ioqueue *ioq, char byte) {
  ASSERT(intr_get_status() == INTR_OFF);
  while (ioq_full(ioq)) {
    // 缓冲区满-> 先睡眠
    lock_acquire(&ioq->lock); // 避免惊群情况出现
    ioq_wait(&ioq->producer);
    lock_release(&ioq->lock);
  }
  ioq->buf[ioq->head] = byte;      // 把字节放入缓冲区中
  ioq->head = next_pos(ioq->head); // 把写游标移到下一位置
  if (ioq->consumer != NULL) {
    wakeup(&ioq->consumer); // 唤醒消费者
  }
}