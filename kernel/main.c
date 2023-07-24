#include "console.h"
#include "debug.h"
#include "dir.h"
#include "fs.h"
#include "init.h"
#include "interrupt.h"
#include "ioqueue.h"
#include "keyboard.h"
#include "print.h"
#include "process.h"
#include "shell.h"
#include "stdint.h"
#include "stdio.h"
#include "stdio_kernel.h"
#include "string.h"
#include "syscall.h"
#include "syscall_init.h"
#include "thread.h"

// void k_thread_a(void *arg);
// void k_thread_b(void *arg);
// void u_prog_a(void);
// void u_prog_b(void);
// int prog_a_pid = 0;
// int prog_b_pid = 0;

int main(void) {
  put_str("I am kernel\n");
  init_all();
  intr_enable();

  /************* 写入应用程序 *************/
  // uint32_t file_size = 26000;
  // uint32_t sec_cnt = DIV_ROUND_UP(file_size, 512);
  // struct disk *sda = &channels[0].devices[0];
  // void *prog_buf = sys_malloc(file_size);
  // ide_read(sda, 300, prog_buf, sec_cnt);
  // int32_t fd = sys_open("/cat", O_CREAT | O_RDWR);
  // if (fd != -1) {
  //   if (sys_write(fd, prog_buf, file_size) == -1) {
  //     printk("file write error!\n");
  //     while (1) {
  //     }
  //   }
  // }

  int32_t fd1 = sys_open("/dir1/file1", O_CREAT | O_RDWR);
  sys_write(fd1, "hello gty dog!\n", 16);

  cls_screen();
  console_put_str("[yers@localhost /]$ ");
  thread_exit(running_thread(), true);
  return 0;
}

void init(void) {
  uint32_t ret_pid = fork();
  if (ret_pid) {
    int status;
    int child_pid;
    /* init在此处不停地回收僵尸进程 */
    while (1) {
      child_pid = wait(&status);
      printf("I`m init, My pid is 1, I recieve a child, It`s pid is %d, status "
             "is %d\n",
             child_pid, status);
    }
  } else {
    my_shell();
  }
  PANIC("init: should not be here");
}

// // 线程中运行的函数
// void k_thread_a(void *arg) {
//   void *addr1 = sys_malloc(256);
//   void *addr2 = sys_malloc(255);
//   void *addr3 = sys_malloc(254);
//   // console_put_str(" thread_a malloc addr:0x");
//   // console_put_int((int)addr1);
//   // console_put_char(',');
//   // console_put_int((int)addr2);
//   // console_put_char(',');
//   // console_put_int((int)addr3);
//   // console_put_char('\n');

//   int cpu_delay = 100000;
//   while (cpu_delay-- > 0)
//     ;
//   sys_free(addr1);
//   sys_free(addr2);
//   sys_free(addr3);
//   while (1)
//     ;
// }

// void k_thread_b(void *arg) {
//   void *addr1 = sys_malloc(256);
//   void *addr2 = sys_malloc(255);
//   void *addr3 = sys_malloc(254);
//   // console_put_str(" thread_b malloc addr:0x");
//   // console_put_int((int)addr1);
//   // console_put_char(',');
//   // console_put_int((int)addr2);
//   // console_put_char(',');
//   // console_put_int((int)addr3);
//   // console_put_char('\n');

//   int cpu_delay = 100000;
//   while (cpu_delay-- > 0)
//     ;
//   sys_free(addr1);
//   sys_free(addr2);
//   sys_free(addr3);
//   while (1)
//     ;
// }

// void u_prog_a(void) {
//   void *addr1 = malloc(256);
//   void *addr2 = malloc(255);
//   void *addr3 = malloc(254);
//   // printf(" prog_a malloc addr:0x%x,0x%x,0x%x\n", (int)addr1, (int)addr2,
//   // (int)addr3);
//   int cpu_delay = 100000;
//   while (cpu_delay-- > 0)
//     ;
//   free(addr1);
//   free(addr2);
//   free(addr3);
//   while (1)
//     ;
// }

// void u_prog_b(void) {
//   void *addr1 = malloc(256);
//   void *addr2 = malloc(255);
//   void *addr3 = malloc(254);
//   // printf(" prog_b malloc addr:0x%x,0x%x,0x%x\n", (int)addr1,
//   // (int)addr2,(int)addr3);
//   int cpu_delay = 100000;
//   while (cpu_delay-- > 0)
//     ;
//   free(addr1);
//   free(addr2);
//   free(addr3);
//   while (1)
//     ;
// }