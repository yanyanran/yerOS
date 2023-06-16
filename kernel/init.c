#include "interrupt.h"
#include "memory.h"
#include "print.h"
#include "thread.h"
#include "timer.h"

// 负责初始化所有模块
void init_all() {
  put_str("init_all\n");
  idt_init();    // 初始化中断
  timer_init();  // 初始化PIT
  mem_init();    // 初始化内存池
  thread_init(); // 初始化线程环境
}