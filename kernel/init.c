#include "console.h"
#include "interrupt.h"
#include "keyboard.h"
#include "memory.h"
#include "print.h"
#include "thread.h"
#include "timer.h"

// 负责初始化所有模块
void init_all() {
  put_str("init_all\n");
  idt_init();      // 初始化中断
  timer_init();    // 初始化PIT
  mem_init();      // 初始化内存池
  thread_init();   // 初始化线程环境
  console_init();  // 初始化终端
  keyboard_init(); // 初始化键盘
}