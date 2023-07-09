#ifndef FS_FILE
#define FS_FILE
#include "inode.h"
#include "stdint.h"

struct file {
  uint32_t fd_pos; // 记录当前文件操作的偏移地址（最小0，最大为文件大小-1
  uint32_t fd_flag;
  struct inode *fd_inode;
};

// 标准输入输出描述符
enum std_fd {
  stdin_no,  // 0标准输入
  stdout_np, // 1标准输出
  stderr_no  // 2标准错误
};

enum bitmap_type {
  INODE_BITMAP, // inode位图
  BLOCK_BITMAP  // 块位图
};

#define MAX_FILE_OPEN 32 // 系统可打开的最大文件数

#endif /* FS_FILE */
