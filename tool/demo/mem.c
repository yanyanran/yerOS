#include "stdio.h"
int main() {
  int in_a = 1, in_b = 2;
  asm("movw %w0, %1;" ::"a"(in_a), "m"(in_b));
  printf("in_b now is %d\n", in_b);

  int in_c = 0x12345678, in_d = 0;
  asm("movw %w1, %0;" : "=m"(in_d) : "a"(in_c)); // 0x5678
  printf("word in_d is 0x%x\n", in_d);
  in_d = 0;

  asm("movb %b1, %0;" : "=m"(in_d) : "a"(in_c)); // 0x78
  printf("low byte in_d is 0x%x\n", in_d);
  in_d = 0;

  asm("movb %h1, %0;" : "=m"(in_d) : "a"(in_c)); // 0x56
  printf("high byte in_d is 0x%x\n", in_d);
}