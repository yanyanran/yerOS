#include "console.h"
#include "dir.h"
#include "fs.h"
#include "init.h"
#include "interrupt.h"
#include "ioqueue.h"
#include "keyboard.h"
#include "print.h"
#include "process.h"
#include "stdio.h"
#include "string.h"
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
  // intr_enable(); // 开中断
  // console_put_str("main_pid:0x");
  // console_put_int(sys_getpid());
  // console_put_char('\n');

  // 用户进程独享内存空间，虚拟地址相同不冲突
  // process_execute(u_prog_a, "user_prog_a");
  // process_execute(u_prog_b, "user_prog_b");

  // 内核线程共享内存空间，虚拟地址唯一
  // thread_start("k_thread_a", 31, k_thread_a, "I am thread_a");
  // thread_start("k_thread_b", 31, k_thread_b, "I am thread_b ");

  struct stat obj_stat;
  sys_stat("/", &obj_stat);
  printf("/`s info\n i_no:%d\n size:%d\n filetype:%s\n", obj_stat.st_ino,
         obj_stat.st_size, obj_stat.st_filetype == 2 ? "directory" : "regular");
  sys_stat("/dir1", &obj_stat);
  printf("/dir1`s info\n i_no:%d\n size:%d\n filetype:%s\n", obj_stat.st_ino,
         obj_stat.st_size, obj_stat.st_filetype == 2 ? "directory" : "regular");

  while (1) {
    // console_put_str("Main ");
  };
  return 0;
}

// 线程中运行的函数
void k_thread_a(void *arg) {
  void *addr1 = sys_malloc(256);
  void *addr2 = sys_malloc(255);
  void *addr3 = sys_malloc(254);
  // console_put_str(" thread_a malloc addr:0x");
  // console_put_int((int)addr1);
  // console_put_char(',');
  // console_put_int((int)addr2);
  // console_put_char(',');
  // console_put_int((int)addr3);
  // console_put_char('\n');

  int cpu_delay = 100000;
  while (cpu_delay-- > 0)
    ;
  sys_free(addr1);
  sys_free(addr2);
  sys_free(addr3);
  while (1)
    ;
}

void k_thread_b(void *arg) {
  void *addr1 = sys_malloc(256);
  void *addr2 = sys_malloc(255);
  void *addr3 = sys_malloc(254);
  // console_put_str(" thread_b malloc addr:0x");
  // console_put_int((int)addr1);
  // console_put_char(',');
  // console_put_int((int)addr2);
  // console_put_char(',');
  // console_put_int((int)addr3);
  // console_put_char('\n');

  int cpu_delay = 100000;
  while (cpu_delay-- > 0)
    ;
  sys_free(addr1);
  sys_free(addr2);
  sys_free(addr3);
  while (1)
    ;
}

void u_prog_a(void) {
  void *addr1 = malloc(256);
  void *addr2 = malloc(255);
  void *addr3 = malloc(254);
  // printf(" prog_a malloc addr:0x%x,0x%x,0x%x\n", (int)addr1, (int)addr2,
  // (int)addr3);
  int cpu_delay = 100000;
  while (cpu_delay-- > 0)
    ;
  free(addr1);
  free(addr2);
  free(addr3);
  while (1)
    ;
}

void u_prog_b(void) {
  void *addr1 = malloc(256);
  void *addr2 = malloc(255);
  void *addr3 = malloc(254);
  // printf(" prog_b malloc addr:0x%x,0x%x,0x%x\n", (int)addr1,
  // (int)addr2,(int)addr3);
  int cpu_delay = 100000;
  while (cpu_delay-- > 0)
    ;
  free(addr1);
  free(addr2);
  free(addr3);
  while (1)
    ;
}