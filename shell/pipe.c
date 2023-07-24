#include "pipe.h"
#include "file.h"
#include "fs.h"
#include "global.h"
#include "ioqueue.h"
#include "memory.h"
#include "stdint.h"

bool is_pipe(uint32_t local_fd) { // local_fd：pcb中数组fd_table下标
  uint32_t global_fd = fd_local2global(local_fd);
  return file_table[global_fd].fd_flag == PIPE_FLAG;
}

// 创建管道，成功返回0否则返-1
int32_t sys_pipe(int32_t pipefd[2]) {
  int32_t global_fd = get_free_slot_in_global();

  file_table[global_fd].fd_inode =
      get_kernel_pages(1); // 申请一页内核内存做环型缓冲区
  ioqueue_init((struct ioqueue *)file_table[global_fd].fd_inode);
  if (file_table[global_fd].fd_inode == NULL) {
    return -1;
  }
  file_table[global_fd].fd_flag = PIPE_FLAG;
  file_table[global_fd].fd_pos = 2; // 管道打开数
  pipefd[0] = pcb_fd_install(global_fd);
  pipefd[1] = pcb_fd_install(global_fd);
  return 0;
}

uint32_t pipe_read(int32_t fd, void *buf, uint32_t count) {
  char *buffer = buf;
  uint32_t bytes_read = 0;
  uint32_t global_fd = fd_local2global(fd);

  // 获取管道的环形缓冲区
  struct ioqueue *ioq = (struct ioqueue *)file_table[global_fd].fd_inode;
  uint32_t ioq_len = ioq_length(ioq);
  uint32_t size =
      ioq_len > count ? count : ioq_len; // 选择较小的数据读取量避免阻塞
  while (bytes_read < size) {
    *buffer = ioq_getchar(ioq);
    bytes_read++;
    buffer++;
  }
  return bytes_read;
}

uint32_t pipe_write(int32_t fd, const void *buf, uint32_t count) {
  uint32_t bytes_write = 0;
  uint32_t global_fd = fd_local2global(fd);
  struct ioqueue *ioq = (struct ioqueue *)file_table[global_fd].fd_inode;

  uint32_t ioq_left = bufsize - ioq_length(ioq); // 选择较小的数据写入量避免阻塞
  uint32_t size = ioq_left > count ? count : ioq_left;

  const char *buffer = buf;
  while (bytes_write < size) {
    ioq_putchar(ioq, *buffer);
    bytes_write++;
    buffer++;
  }
  return bytes_write;
}