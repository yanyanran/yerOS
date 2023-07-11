#ifndef FS_FILE
#define FS_FILE
#include "dir.h"
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
extern struct file file_table[MAX_FILE_OPEN]; // 文件表

int32_t get_free_slot_in_global(void);
int32_t pcb_fd_install(int32_t global_fd_idx);
int32_t block_bitmap_malloc(struct partition *part);
int32_t inode_bitmap_malloc(struct partition *part);
void bitmap_sync(struct partition *part, uint32_t bit_idx, uint8_t btmp);
int32_t file_create(struct dir *parent_dir, char *filename, uint8_t flag);
int32_t file_open(uint32_t inode_no, uint8_t flag);
int32_t file_close(struct file *file);

#endif /* FS_FILE */
