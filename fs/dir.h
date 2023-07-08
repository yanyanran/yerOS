#ifndef FS_DIR
#define FS_DIR
#include "fs.h"
#include "stdint.h"

#define MAX_FILE_NAME_LEN 16 // 最大文件名长度

// 目录
struct dir {
  struct inode *inode;
  uint32_t dir_pos;     // 在目录内的偏移
  uint8_t dir_buf[512]; // 目录的数据缓存
};

// 目录项
struct dir_entry {
  char filename[MAX_FILE_NAME_LEN]; // 普通文件/目录名
  uint32_t i_no;                    // 普通文件/目录对应的inode号
  enum file_type f_type;            // 文件类型
};

#endif /* FS_DIR */
