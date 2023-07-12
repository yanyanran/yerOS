#ifndef FS_FS
#define FS_FS
#include "stdint.h"

#define MAX_FILES_PER_PART 4096 // 每个分区所支持最大创建的文件数（inode位图数
#define BITS_PER_SECTOR 4096   // 每扇区的位数
#define SECTOR_SIZE 512        // 扇区字节大小
#define BLOCK_SIZE SECTOR_SIZE // 块字节大小
#define MAX_PATH_LEN 512       // 路径最大长度

extern struct partition *cur_part; // 默认情况下操作的是哪个分区

enum file_type {
  FT_UNKNOWN,  // 不支持
  FT_REGULAR,  // 普通文件
  FT_DIRECTORY // 目录
};

// 打开文件的选项
enum oflags {
  O_RDONLY,   // 只读
  O_WRONLY,   // 只写
  O_RDWR,     // 读写
  O_CREAT = 4 // 创建
};

// 文件读写位置偏移量
enum whence { SEEK_SET = 1, SEEK_CUR, SEEK_END };

// 记录查找文件过程中已找到的上级路径
struct path_search_record {
  char searched_path[MAX_PATH_LEN]; // 查找过程中的父目录
  struct dir *parent_dir;           // 文件或目录所在的直接父目录
  enum file_type file_type; // 找到的是普通文件还是目录，找不到即未知类型
};

void filesys_init();
int32_t sys_open(const char *pathname, uint8_t flags);
int32_t sys_close(int32_t fd);
uint32_t sys_write(int32_t fd, const void *buf, uint32_t count);
int32_t sys_read(int32_t fd, void *buf, uint32_t count);
int32_t sys_lseek(int32_t fd, int32_t offset, uint8_t whence);

#endif /* FS_FS */
