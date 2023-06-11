#include "debug.h"
#include "init.h"
#include "memory.h"
#include "print.h"

int main(void) {
  put_str("I am kernel\n");
  init_all();
  mem_init();
  while (1) {
  };
  return 0;
}