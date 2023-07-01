#include "console.h"
#include "init.h"
#include "interrupt.h"
#include "ioqueue.h"
#include "keyboard.h"
#include "print.h"
#include "process.h"
#include "stdio.h"
#include "syscall.h"
#include "syscall_init.h"
#include "thread.h"

void k_thread_a(void *arg);
void k_thread_b(void *arg);
void u_prog_a(void);
void u_prog_b(void);
int prog_a_pid = 0;
int prog_b_pid = 0;

int main(void) {
  put_str("I am kernel\n");
  init_all();

  // process_execute(u_prog_a, "user_prog_a");
  // process_execute(u_prog_b, "user_prog_b");

  intr_enable(); // 开中断
  // console_put_str("main_pid:0x");
  // console_put_int(sys_getpid());
  // console_put_char('\n');

  thread_start("k_thread_a", 31, k_thread_a, "I am thread_a");
  thread_start("k_thread_b", 31, k_thread_b, "I am thread_b ");

  while (1) {
    // console_put_str("Main ");
  };
  return 0;
}

// 线程中运行的函数
void k_thread_a(void *arg) {
  // char *para = arg;
  void *addr1;
  void *addr2;
  void *addr3;
  void *addr4;
  void *addr5;
  void *addr6;
  void *addr7;
  console_put_str(" thread_a start\n");
  int max = 1000;
  while (max-- > 0) {
    int size = 128;
    addr1 = sys_malloc(size);
    size *= 2;
    addr2 = sys_malloc(size);
    size *= 2;
    addr3 = sys_malloc(size);
    sys_free(addr1);
    addr4 = sys_malloc(size);
    size *= 2;
    size *= 2;
    size *= 2;
    size *= 2;
    size *= 2;
    size *= 2;
    size *= 2;
    addr5 = sys_malloc(size);
    addr6 = sys_malloc(size);
    sys_free(addr5);
    size *= 2;
    addr7 = sys_malloc(size);
    sys_free(addr6);
    sys_free(addr7);
    sys_free(addr2);
    sys_free(addr3);
    sys_free(addr4);
  }
  console_put_str(" thread_a end\n");
  while (1)
    ;
}

void k_thread_b(void *arg) {
  //char *para = arg;
  void *addr1;
  void *addr2;
  void *addr3;
  void *addr4;
  void *addr5;
  void *addr6;
  void *addr7;
  void *addr8;
  void *addr9;
  int max = 1000;
  console_put_str(" thread_b start\n");
  while (max-- > 0) {
    int size = 9;
    addr1 = sys_malloc(size);
    size *= 2;
    addr2 = sys_malloc(size);
    size *= 2;
    sys_free(addr2);
    addr3 = sys_malloc(size);
    sys_free(addr1);
    addr4 = sys_malloc(size);
    addr5 = sys_malloc(size);
    addr6 = sys_malloc(size);
    sys_free(addr5);
    size *= 2;
    addr7 = sys_malloc(size);
    sys_free(addr6);
    sys_free(addr7);
    sys_free(addr3);
    sys_free(addr4);
    size *= 2;
    size *= 2;
    size *= 2;
    addr1 = sys_malloc(size);
    addr2 = sys_malloc(size);
    addr3 = sys_malloc(size);
    addr4 = sys_malloc(size);
    addr5 = sys_malloc(size);
    addr6 = sys_malloc(size);
    addr7 = sys_malloc(size);
    addr8 = sys_malloc(size);
    addr9 = sys_malloc(size);
    sys_free(addr1);
    sys_free(addr2);
    sys_free(addr3);
    sys_free(addr4);
    sys_free(addr5);
    sys_free(addr6);
    sys_free(addr7);
    sys_free(addr8);
    sys_free(addr9);
  }
  console_put_str(" thread_b end\n");
  while (1)
    ;
}

void u_prog_a(void) {
  printf(" prog_a_pid:0x%x\n", getpid());
  while (1)
    ;
}

void u_prog_b(void) {
  printf(" prog_b_pid:0x%x\n", getpid());
  while (1)
    ;
}