#include "timer.h"
#include "debug.h"
#include "global.h"
#include "interrupt.h"
#include "io.h"
#include "print.h"
#include "thread.h"
#include "stdint.h"

#define IRQ0_FREQUENCY 100
#define INPUT_FREQUENCY 1193180
#define COUNTER0_VALUE INPUT_FREQUENCY / IRQ0_FREQUENCY
#define CONTRER0_PORT 0x40
#define COUNTER0_NO 0
#define COUNTER_MODE 2
#define READ_WRITE_LATCH 3
#define PIT_CONTROL_PORT 0x43
#define mil_seconds_per_intr (1000 / IRQ0_FREQUENCY)

uint32_t ticks; // 内核发生的总中断次数（系统运行时长）

static void frequency_set(uint8_t counter_port, uint8_t counter_no, uint8_t rwl,
                          uint8_t counter_mode, uint16_t counter_value) {
  // 往控制字寄存器端口0x43中写入控制字
  outb(PIT_CONTROL_PORT,
       (uint8_t)(counter_no << 6 | rwl << 4 | counter_mode << 1));
  // 先写入counter_value低8位，再写高8位
  outb(counter_port, (uint8_t)counter_value);
  outb(counter_port, (uint8_t)counter_value >> 8);
}

// 时钟中断处理函数
static void intr_timer_handler(void) {
  struct task_struct *cur_thread = running_thread();
  ASSERT(cur_thread->stack_magic == 0x20021112);
  cur_thread->elapsed_ticks++; // 记录此线程占用cpu时间
  ticks++;

  if (cur_thread->ticks == 0) { // 时间片用完，调度新进程上cpu
    schedule();
  } else {
    cur_thread->ticks--;
  }
}

// 初始化PIT8253
void timer_init() {
  put_str("timer_init start\n");
  // 设置8253定时周期-> 发中断周期
  frequency_set(CONTRER0_PORT, COUNTER0_NO, READ_WRITE_LATCH, COUNTER_MODE,
                COUNTER0_VALUE);
  register_handler(0x20, intr_timer_handler); // 注册时钟中断处理函数
  put_str("timer_init done\n");
}

// 以tick为单位的sleep，任何时间形式的sleep会转换此ticks形式
static void ticks_to_sleep(uint32_t sleep_ticks) {
  uint32_t start_tick = ticks;
  while (ticks - start_tick < sleep_ticks) {
    thread_yield();
  }
}

// 以ms为单位的sleep
void mtime_sleep(uint32_t m_seconds) {
  uint32_t sleep_ticks = DIV_ROUND_UP(m_seconds, mil_seconds_per_intr);
  ASSERT(sleep_ticks > 0);
  ticks_to_sleep(sleep_ticks);
}