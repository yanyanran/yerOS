#include "print.h"
#include "sync.h"

static struct lock console_lock; // 终端锁

void console_init() { lock_init(&console_lock); }

// 获取终端
void console_acquire() { lock_acquire(&console_lock); }

// 释放终端
void console_release() { lock_release(&console_lock); }

// 终端中输出字符串
void console_put_str(char *str) {
  console_acquire();
  put_str(str);
  console_release();
}

// 终端中输出字符
void console_put_char(uint8_t char_asci) {
  console_acquire();
  put_char(char_asci);
  console_release();
}

// 终端中输出十六进制整数
void console_put_int(uint32_t num) {
  console_acquire();
  put_int(num);
  console_release();
}

// 终端中输出十进制整数
void console_put_int10(uint32_t num) {
  console_acquire();
  put_int10(num);
  console_release();
}

// 输出字符串(自定义颜色)
void console_write_color(char *cstr, real_color_t back, real_color_t fore) {
  console_acquire();
  while (*cstr) {
    put_char_color(*cstr++, back, fore);
  }
  console_release();
}

void sys_putchar(uint8_t char_asci) { console_put_char(char_asci); }