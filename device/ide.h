#ifndef DEVICE_IDE
#define DEVICE_IDE
#include "bitmap.h"
#include "list.h"
#include "stdint.h"
#include "sync.h"

// 分区表
struct partition {
  uint32_t start_lba;        // 起始扇区
  uint32_t sec_cnt;          // 扇区数
  struct disk *my_disk;      // 分区所属硬盘
  struct list_elem part_tag; // 用于队列中的标记
  char name[8];
  struct super_block *sb;

  struct bitmap block_bitmap;
  struct bitmap inode_bitmap;
  struct list open_inodes; // 本分区打开的inode队列
};

// 硬盘
struct disk {
  char name[8];
  struct ide_channel *my_channel;  // 本硬盘所属通道
  uint8_t dev_no;                  // 主盘0还是从盘1
  struct partition prim_parts[4];  // 主分区
  struct partition logic_parts[8]; // 逻辑分区
};

// ata/ide通道
struct ide_channel {
  char name[8];
  uint16_t port_base; // 本通道端口基址
  uint8_t irq_no;     // 本通道所用的中断号
  struct lock lock;
  bool expecting_intr;        // 表示正等待硬盘中断
  struct semaphore disk_done; // 用于阻塞、唤醒驱动程序
  struct disk devices[2]; // 一个通道上连接两个硬盘，一主一从
};

extern uint8_t channel_cnt;            // 通道数
extern struct ide_channel channels[2]; // 有两个ide通道
extern struct list partition_list;     // 分区列表

void ide_init();
void ide_write(struct disk *hd, uint32_t lba, void *buf, uint32_t sec_cnt);
void ide_read(struct disk *hd, uint32_t lba, void *buf, uint32_t sec_cnt);

#endif /* DEVICE_IDE */
