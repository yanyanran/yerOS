#include "file.h"
#include "bitmap.h"
#include "fs.h"
#include "ide.h"
#include "stdint.h"
#include "stdio_kernel.h"
#include "super_block.h"
#include "thread.h"

struct file file_table[MAX_FILE_OPEN]; // 文件表

// 从文件表中获取一个空闲位
int32_t get_free_slot_in_global(void) {
  uint32_t fd_idx = 3; // 跨过stdin,stdout,stderr
  
  while (fd_idx < MAX_FILE_OPEN) {
    if (file_table[fd_idx].fd_inode == NULL) {
      break;
    }
    fd_idx++;
  }
  if (fd_idx == MAX_FILE_OPEN) {
    printk("exceed max open files\n");
    return -1;
  }
  return fd_idx;
}

// 将全局描述符下标安装到进程/线程自己的文件描述符数组fd_table中
int32_t pcb_fd_install(int32_t global_fd_idx) {
  struct task_struct *cur = running_thread();
  uint8_t local_fd_idx = 3; // 跨过stdin,stdout,stderr

  while (local_fd_idx < MAX_FILES_OPEN_PER_PROC) {
    if (cur->fd_table[local_fd_idx] == -1) { // -1表示free_slot，可用
      cur->fd_table[local_fd_idx] = global_fd_idx;
      break;
    }
    local_fd_idx++;
  }
  if (local_fd_idx == MAX_FILES_OPEN_PER_PROC) {
    printk("exceed max open files_per_proc\n");
    return -1;
  }
  return local_fd_idx;
}

// 分配一个inode
int32_t inode_bitmap_malloc(struct partition *part) {
  int32_t bit_idx = bitmap_scan(&part->inode_bitmap, 1);
  if (bit_idx == -1) {
    return -1;
  }
  bitmap_set(&part->inode_bitmap, bit_idx, 1);
  return bit_idx;
}

// 分配一个扇区
int32_t block_bitmap_malloc(struct partition *part) {
  int32_t bit_idx = bitmap_scan(&part->inode_bitmap, 1);
  if (bit_idx == -1) {
    return -1;
  }
  bitmap_set(&part->inode_bitmap, bit_idx, 1);
  return (part->sb->data_start_lba + bit_idx);
}

// 将内存中bitmap第bit_idx位所在的512字节同步到硬盘
void bitmap_sync(struct partition *part, uint32_t bit_idx, uint8_t btmp) {
  uint32_t off_sec = bit_idx / 4096;
  uint32_t off_size = off_sec * BLOCK_SIZE;
  uint32_t sec_lba;
  uint8_t *bitmap_off;

  // 需要被同步到硬盘的位图只有inode_bitmap和block_bitmap
  switch (btmp) {
  case INODE_BITMAP:
    sec_lba = part->sb->inode_bitmap_lba + off_sec;
    bitmap_off = part->inode_bitmap.bits + off_size;
    break;

  case BLOCK_BITMAP:
    sec_lba = part->sb->block_bitmap_lba + off_sec;
    bitmap_off = part->block_bitmap.bits + off_size;
    break;
  }
  ide_write(part->my_disk, sec_lba, bitmap_off, 1);
}