#include "interrupt.h"
#include "io.h"
#include "print.h"
#include <stdint.h>
#define KBD_BUF_PORT 0x60 // 键盘buffer寄存器端口号

// 键盘中断处理程序
static void intr_keyboard_handler(void) {
  uint8_t scode =
      inb(KBD_BUF_PORT); // 必须读输出缓冲区寄存器，否则8042不再响应键盘中断
  put_int(scode);
  return;
}

// 键盘初始化
void keyboard_init() {
  put_str("keyboard_init start\n");
  register_handler(0x21, intr_keyboard_handler);
  put_str("keyboard_init done\n");
}