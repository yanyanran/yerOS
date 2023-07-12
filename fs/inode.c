#include "inode.h"
#include "debug.h"
#include "file.h"
#include "global.h"
#include "ide.h"
#include "interrupt.h"
#include "list.h"
#include "memory.h"
#include "stdint.h"
#include "string.h"
#include "super_block.h"
#include "thread.h"

struct inode_position {
  bool two_sec;      // inode是否跨扇区
  uint32_t sec_lba;  // inode所在扇区号
  uint32_t off_size; // inode在扇区内的字节偏移量
};

// 获取inode所在扇区和偏移量存入inode_pos中
static void inode_locate(struct partition *part, uint32_t inode_no,
                         struct inode_position *inode_pos) {
  // inode_table在磁盘上连续
  ASSERT(inode_no < 4096);
  uint32_t inode_table_lba = part->sb->inode_table_lba;

  uint32_t inode_size = sizeof(struct inode);
  uint32_t off_size = inode_no * inode_size; // 字节偏移量
  uint32_t off_sec = off_size / 512;         // 扇区偏移量
  uint32_t off_size_in_sec =
      off_size % 512; // 待查找的inode所在扇区中的起始地址
  uint32_t left_in_sec = 512 - off_size_in_sec;

  if (left_in_sec < inode_size) { // 跨2个扇区
    inode_pos->two_sec = true;
  } else {
    inode_pos->two_sec = false;
  }
  inode_pos->sec_lba = inode_table_lba + off_sec;
  inode_pos->off_size = off_size_in_sec;
}

// 将inode写入分区part
void inode_sync(struct partition *part, struct inode *inode, void *io_buf) {
  uint8_t inode_no = inode->i_no;
  struct inode_position inode_pos;
  // inode位置信息存入inode_pos
  inode_locate(part, inode_no, &inode_pos);
  ASSERT(inode_pos.sec_lba <= (part->start_lba + part->sec_cnt));

  /* 以下inode三个成员只在内存中有效，现在将inode同步到硬盘，清掉这三项即可 */
  struct inode pure_inode;
  memcpy(&pure_inode, inode, sizeof(struct inode));
  pure_inode.i_open_cnt = 0;
  pure_inode.inode_tag.prev = pure_inode.inode_tag.next = NULL;
  pure_inode.write_deny = false; // 保证在磁盘中读出为可写

  char *inode_buf = (char *)io_buf;
  if (inode_pos.two_sec) { // 跨2个扇区就要读出2扇区再写2扇区
    /* 读写磁盘以扇区为单位，若写入数据小于一扇区，将原磁盘内容先读出来再和新数据拼成一扇区后再写入*/
    ide_read(part->my_disk, inode_pos.sec_lba, inode_buf, 2);
    // 将待写入的inode拼入到这2个扇区中的相应位置
    memcpy((inode_buf + inode_pos.off_size), &pure_inode, sizeof(struct inode));
    // 将拼接好的数据再写入磁盘
    ide_write(part->my_disk, inode_pos.sec_lba, inode_buf, 2);
  } else {
    ide_read(part->my_disk, inode_pos.sec_lba, inode_buf, 1);
    memcpy((inode_buf + inode_pos.off_size), &pure_inode, sizeof(struct inode));
    ide_write(part->my_disk, inode_pos.sec_lba, inode_buf, 1);
  }
}

// 根据inode号返回相应的inode
struct inode *inode_open(struct partition *part, uint32_t inode_no) {
  struct list_elem *elem = part->open_inodes.head.next;
  struct inode *inode_found;

  // 先在已打开的inode链表中找
  while (elem != &part->open_inodes.tail) {
    inode_found = elem2entry(struct inode, inode_tag, elem);
    if (inode_found->i_no == inode_no) {
      inode_found->i_open_cnt++;
      return inode_found;
    }
    elem = elem->next;
  }

  // 链表缓存中没有-> 从磁盘读此inode并加到链表中
  struct inode_position inode_pos;
  inode_locate(part, inode_no, &inode_pos);

  /* 为使通过sys_malloc创建的新inode被所有任务共享，需将inode置于内核空间 */
  struct task_struct *cur = running_thread();
  uint32_t *cur_pgdir_bak = cur->pgdir;
  cur_pgdir_bak = NULL; // 接下来分配的内存位于内核区
  inode_found = (struct inode *)sys_malloc(sizeof(struct inode));
  cur->pgdir = cur_pgdir_bak; // 恢复

  char *inode_buf;
  if (inode_pos.two_sec) { // 跨扇区
    inode_buf = (char *)sys_malloc(1024);
    ide_read(part->my_disk, inode_pos.sec_lba, inode_buf, 2);
  } else {
    inode_buf = (char *)sys_malloc(512);
    ide_read(part->my_disk, inode_pos.sec_lba, inode_buf, 1);
  }
  memcpy(inode_found, inode_buf + inode_pos.off_size, sizeof(struct inode));

  // 因为一会很可能要用到此inode，故将其插入到队首便于提前检索到
  list_push(&part->open_inodes, &inode_found->inode_tag);
  inode_found->i_open_cnt = 1;

  sys_free(inode_buf);
  return inode_found;
}

// 关闭inode或减少inode的打开数
void inode_close(struct inode *inode) {
  enum intr_status old_status = intr_disable();
  // 若没有进程再打开此文件，将此inode去掉并释放空间
  if (--inode->i_open_cnt == 0) {
    list_remove(&inode->inode_tag);
    struct task_struct *cur = running_thread();
    uint32_t *cur_pagedir_bak = cur->pgdir;
    cur->pgdir = NULL; // 确保释放的也是内核内存
    sys_free(inode);
    cur->pgdir = cur_pagedir_bak;
  }
  intr_set_status(old_status);
}

// 清空磁盘分区part上的inode【调试添加】
void inode_delete(struct partition *part, uint32_t inode_no, void *io_buf) {
  ASSERT(inode_no < 4096);
  struct inode_position inode_pos;
  inode_locate(part, inode_no, &inode_pos); // inode位置信息会存入inode_pos
  ASSERT(inode_pos.sec_lba <= (part->start_lba + part->sec_cnt));

  char *inode_buf = (char *)io_buf;
  if (inode_pos.two_sec) { // inode跨扇区，读2个扇区
    ide_read(part->my_disk, inode_pos.sec_lba, inode_buf, 2);
    memset((inode_buf + inode_pos.off_size), 0, sizeof(struct inode));
    // 用清0的内存数据覆盖磁盘
    ide_write(part->my_disk, inode_pos.sec_lba, inode_buf, 2);
  } else { // 未跨扇区，只读1个扇区
    ide_read(part->my_disk, inode_pos.sec_lba, inode_buf, 1);
    memset((inode_buf + inode_pos.off_size), 0, sizeof(struct inode));
    ide_write(part->my_disk, inode_pos.sec_lba, inode_buf, 1);
  }
}

// 回收inode的数据块和inode本身
void inode_release(struct partition *part, uint32_t inode_no) {
  struct inode *inode_to_del = inode_open(part, inode_no);
  ASSERT(inode_to_del->i_no == inode_no);

  /* 1、回收inode占的所有块 */
  uint8_t block_idx = 0, block_cnt = 12;
  uint32_t block_bitmap_idx;
  uint32_t all_blocks[140] = {0}; // 12个直接块+128个间接块

  // 将前12个直接块存入all_blocks
  while (block_idx < 12) {
    all_blocks[block_idx] = inode_to_del->i_sectors[block_idx];
    block_idx++;
  }

  if (inode_to_del->i_sectors[12] != 0) { // 一级间接块表存在
    // 把间接块读到all_blocks
    ide_read(part->my_disk, inode_to_del->i_sectors[12], all_blocks + 12, 1);
    block_cnt = 140;
    block_bitmap_idx = inode_to_del->i_sectors[12] - part->sb->data_start_lba;
    ASSERT(block_bitmap_idx > 0);
    // 释放一级间接块表占的块
    bitmap_set(&part->block_bitmap, block_bitmap_idx, 0);
    bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
  }

  // inode所有块地址已收集到all_blocks中，下面逐个回收
  block_idx = 0;
  while (block_idx < block_cnt) {
    if (all_blocks[block_idx] != 0) {
      block_bitmap_idx = 0;
      block_bitmap_idx = all_blocks[block_idx] - part->sb->data_start_lba;
      ASSERT(block_bitmap_idx > 0);
      bitmap_set(&part->block_bitmap, block_bitmap_idx, 0);
      bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
    }
    block_idx++;
  }

  /* 2、回收该inode所占inode */
  bitmap_set(&part->inode_bitmap, inode_no, 0);
  bitmap_sync(cur_part, inode_no, INODE_BITMAP);

  /*************inode_delete是调试用的*************
   * 此函数会在inode_table中将此inode清0，
   * 但实际上不需要，inode分配由inode_bitmap控制，
   * 磁盘上的数据无需清0，可直接覆盖 */
  void *io_buf = sys_malloc(1024);
  inode_delete(part, inode_no, io_buf);
  sys_free(io_buf);
  /***********************************************/
  inode_close(inode_to_del);
}

void inode_init(uint32_t inode_no, struct inode *new_inode) {
  new_inode->i_no = inode_no;
  new_inode->i_size = 0;
  new_inode->i_open_cnt = 0;
  new_inode->write_deny = false;

  // 初始化块索引数组i_sector
  uint8_t sec_idx = 0;
  while (sec_idx < 13) {
    new_inode->i_sectors[sec_idx] = 0;
    sec_idx++;
  }
}