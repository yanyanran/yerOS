#include "inode.h"
#include "debug.h"
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