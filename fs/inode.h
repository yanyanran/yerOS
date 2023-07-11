#ifndef FS_INODE
#define FS_INODE

#include "global.h"
#include "ide.h"
#include "list.h"
#include "stdint.h"

struct inode {
  uint32_t i_no;
  uint32_t i_size; // 文件-> 文件大小；目录-> 该目录下所有目录项大小之和

  uint32_t i_open_cnt; // 文件被打开的次数
  bool write_deny; // 写文件不能并行，进程写文件前检查此标识

  uint32_t
      i_sectors[13]; // 数据块指针
                     // 直接块i_sectors[0-11]，存储一级间接块指针i_sectors[12]
  struct list_elem inode_tag; // 已打开的inode列表（避免多次读硬盘
};

void inode_init(uint32_t inode_no, struct inode *new_inode);
struct inode *inode_open(struct partition *part, uint32_t inode_no);
void inode_close(struct inode *inode);
void inode_sync(struct partition *part, struct inode *inode, void *io_buf);

#endif /* FS_INODE */
