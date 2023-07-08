#ifndef FS_SUPER_BLOCK
#define FS_SUPER_BLOCK
#include "stdint.h"

// lba - 扇区起始地址
// 超级块
struct super_block {
  uint32_t magic;     // 文件系统类型(支持多文件系统
  uint32_t sec_cnt;   // 总扇区数
  uint32_t inode_cnt; // inode数
  uint32_t part_lba_base;

  uint32_t block_bitmap_lba;   // 块位图lba
  uint32_t block_bitmap_sects; // 占扇区数

  uint32_t inode_bitmap_lba; // inode位图lba
  uint32_t inode_bitmap_sects;

  uint32_t inode_table_lba; // inode表lba
  uint32_t inode_table_sects;

  uint32_t data_start_lba; // 数据区第一个扇区号
  uint32_t root_inode_no;  // 根目录所在inode号
  uint32_t dir_entry_size; // 目录项大小

  uint8_t pad[460]; // 填充凑够一扇区
} __attribute__((packed));

#endif /* FS_SUPER_BLOCK */
