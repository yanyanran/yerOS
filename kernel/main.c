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

  // int32_t fd1 = sys_open("/dir1/file1", O_CREAT | O_RDWR);
  // sys_write(fd1, "hello gty dog!\n", 16);

  cls_screen();
  console_write_color("                                    ____  _____\n",
                      rc_black, rc_light_blue);
  console_write_color("       __  _____  _____            / __ \\/ ___/\n",
                      rc_black, rc_light_yellow);
  console_write_color("      / / / / _ \\/ ___/  ______   / / / /\\__ \\ \n",
                      rc_black, rc_light_blue);

  console_write_color("     / /_/ /  __/ /     ", rc_black, rc_light_blue);
  console_write_color("/", rc_black, rc_light_yellow);
  console_write_color("_____", rc_black, rc_light_blue);
  console_write_color("/", rc_black, rc_light_yellow);
  console_write_color("  / /_/ /___/ / \n", rc_black, rc_light_blue);

  console_write_color("     \\__, /", rc_black, rc_light_blue);
  console_write_color("\\___/_/               \\____//____/  \n", rc_black,
                      rc_light_yellow);
  console_write_color("    /____/                                     ",
                      rc_black, rc_light_yellow);
  console_write_color("  Welcome to use.\n\n", rc_black, rc_light_cyan);

  console_put_str("[yers@localhost /]$ ");
  thread_exit(running_thread(), true);
  printf("yeyeyeyeye\n");
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