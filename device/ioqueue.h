#ifndef DEVICE_IOQUEUE
#define DEVICE_IOQUEUE
#include "stdint.h"
#include "sync.h"
#include "thread.h"

#define bufsize 64

// 环形队列
struct ioqueue {
  struct lock lock;
  struct task_struct *producer; // 记录哪个生产者在此缓冲区上睡眠
  struct task_struct *consumer; // 记录哪个消费者在此缓冲区上睡眠
  char buf[bufsize];
  int32_t head; // 队首写
  int32_t tail; // 队尾读
};

void ioqueue_init(struct ioqueue *ioq);
bool ioq_full(struct ioqueue *ioq);
char ioq_getchar(struct ioqueue *ioq);
void ioq_putchar(struct ioqueue *ioq, char byte);
bool ioq_empty(struct ioqueue *ioq);

#endif /* DEVICE_IOQUEUE */
