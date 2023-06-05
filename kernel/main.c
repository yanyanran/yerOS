#include "init.h"
#include "print.h"

int main(void) {
  put_str("I am kernel\n");
  init_all();
  // asm volatile("sti"); // 演示中断处理，临时打开中断
  while (1)
    ;
}