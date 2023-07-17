#ifndef KERNEL_INTERRUPT
#define KERNEL_INTERRUPT
#include "stdint.h"
typedef void *intr_handler;
void idt_init(void);

/* 定义中断的两种状态:
 * INTR_OFF 值为 0，表示关中断
 * INTR_ON 值为 1，表示开中断 */
enum intr_status {
  INTR_OFF, // 中断关闭
  INTR_ON   // 中断打开
};

enum intr_status intr_enable(void);
enum intr_status intr_disable(void);
enum intr_status intr_set_status(enum intr_status status);
enum intr_status intr_get_status(void);
void register_handler(uint8_t vector_no, intr_handler func);
enum intr_status intr_get_status();
#endif /* KERNEL_INTERRUPT */
