#include "ide.h"
#include "debug.h"
#include "global.h"
#include "interrupt.h"
#include "io.h"
#include "print.h"
#include "stdint.h"
#include "stdio.h"
#include "stdio_kernel.h"
#include "sync.h"
#include "timer.h"

// 硬盘各寄存器端口号
#define reg_data(channel) (channel->port_base + 0)
#define reg_error(channel) (channel->port_base + 1)
#define reg_sect_cnt(channel) (channel->port_base + 2)
#define reg_lba_l(channel) (channel->port_base + 3)
#define reg_lba_m(channel) (channel->port_base + 4)
#define reg_lba_h(channel) (channel->port_base + 5)
#define reg_dev(channel) (channel->port_base + 6)
#define reg_status(channel) (channel->port_base + 7)
#define reg_cmd(channel) (reg_status(channel))
#define reg_alt_status(channel) (channel->port_base + 0x206)
#define reg_ctl(channel) reg_alt_status(channel)

// status寄存器关键位
#define BIT_ALT_STAT_BSY 0x80  // 硬盘忙
#define BIT_ALT_STAT_DRDY 0x40 // 驱动器准备好
#define BIT_ALT_STAT_DRQ 0x8   // 数据传输准备好了

// device寄存器关键位
#define BIT_DEV_MBS 0xa0 // 第5、7位固定为1
#define BIT_DEV_LBA 0x40
#define BIT_DEV_DEV 0x10

// 硬盘操作指令
#define CMD_IDENTIFY 0xec     // identify获取硬盘身份信息
#define CMD_READ_SECTOR 0x20  // 读扇区
#define CMD_WRITE_SECTOR 0x30 // 写扇区

// 可读写的最大扇区数，调试用
#define max_lba ((80 * 1024 * 1024 / 512) - 1) // 只支持80MB硬盘

uint8_t channel_cnt;            // 通道数
struct ide_channel channels[2]; // 有两个ide通道

// 选择读写的硬盘
static void select_disk(struct disk *hd) {
  uint8_t reg_device = BIT_DEV_MBS | BIT_DEV_LBA;
  if (hd->dev_no == 1) { // 若是从盘-> 置dev位为1
    reg_device |= BIT_DEV_DEV;
  }
  outb(reg_dev(hd->my_channel), reg_device);
}

// 向硬盘控制器写入 起始扇区地址lba 及 读写扇区数sec_cnt
static void select_sector(struct disk *hd, uint32_t lba, uint8_t sec_cnt) {
  ASSERT(lba <= max_lba);
  struct ide_channel *channel = hd->my_channel;

  // 写入要读写扇区数
  outb(reg_sect_cnt(channel), sec_cnt); // 如果sec_cnt=0则表示写入256个扇区

  // 写入lba地址，即扇区号
  outb(reg_lba_l(channel), lba);
  outb(reg_lba_m(channel), lba >> 8);  // lba地址的8～15位
  outb(reg_lba_h(channel), lba >> 16); // lba地址的16～23位

  // lba地址第24～27位存储在device寄存器的0～3位，所以在此处把device寄存器再重新写入一次
  outb(reg_dev(channel), BIT_DEV_MBS | BIT_DEV_LBA |
                             (hd->dev_no == 1 ? BIT_DEV_DEV : 0) | lba >> 24);
}

// 向channel发命令cmd
static void cmd_out(struct ide_channel *channel, uint8_t cmd) {
  channel->expecting_intr =
      true; // 向硬盘发命令便将此标置为true，硬盘中断处理程序根据它来判断
  outb(reg_cmd(channel), cmd);
}

// 硬盘读入sec_cnt个扇区的数据到buf
static void read_from_sector(struct disk *hd, void *buf, uint8_t sec_cnt) {
  uint32_t size_in_byte;
  // 扇区数转字节
  if (sec_cnt == 0) {
    size_in_byte = 256 * 512; // sec_cnt=0表示256个扇区
  } else {
    size_in_byte = sec_cnt * 512;
  }
  insw(reg_data(hd->my_channel), buf, size_in_byte / 2);
}

// 将buf中sec_cnt扇区的数据写入硬盘
static void write2sector(struct disk *hd, void *buf, uint8_t sec_cnt) {
  uint32_t size_in_byte;
  if (sec_cnt == 0) {
    size_in_byte = 256 * 512;
  } else {
    size_in_byte = sec_cnt * 512;
  }
  outsw(reg_data(hd->my_channel), buf, size_in_byte / 2);
}

// 等待硬盘30s（驱动程序让出CPU使用权使其他任务得到调度
static bool busy_wait(struct disk *hd) {
  struct ide_channel *channel = hd->my_channel;
  uint16_t time_limit = 30 * 1000;

  while (time_limit -= 10 >= 0) {
    // 判断status寄存器BSY位是否为1
    if (!(inb(reg_status(channel)) & BIT_ALT_STAT_BSY)) {
      // DRQ=1 硬盘已准备好数据
      return (inb(reg_status(channel)) & BIT_ALT_STAT_DRQ);
    } else {
      mtime_sleep(10); // 硬盘繁忙，睡10ms（忙等
    }
  }
  return false;
}

// 从硬盘读sec_cnt个扇区到buf
void ide_read(struct disk *hd, uint32_t lba, void *buf, uint32_t sec_cnt) {
  ASSERT(lba <= max_lba);
  ASSERT(sec_cnt > 0);
  lock_acquire(&hd->my_channel->lock);

  // 1、选择操作的硬盘
  select_disk(hd);
  uint32_t secs_op;       // 每次操作的扇区数（<=256）
  uint32_t secs_done = 0; // 已完成的扇区数
  while (secs_done < sec_cnt) {
    if ((secs_done + 256) <= sec_cnt) {
      secs_op = 256;
    } else {
      secs_op = sec_cnt - secs_done;
    }
    // 2、写入待读入的扇区数和起始扇区号
    select_sector(hd, lba + secs_done, secs_op);
    // 3、向硬盘发读扇区命令
    cmd_out(hd->my_channel, CMD_READ_SECTOR);

    /* 硬盘开始工作（开始在内部读数据或写数据）后阻塞自己，等硬盘完成读操作后通过中断处理程序唤醒自己*/
    sema_down(&hd->my_channel->disk_done);

    // 【醒后执行】4、检测硬盘状态是否可读
    if (!busy_wait(hd)) { // 失败
      char error[64];
      sprintf(error, "%s read sector %d failed!!!!!!\n", hd->name, lba);
      PANIC(error);
    }

    // 5、将扇区数据读入到缓冲区(buf+secs_done*512)处
    read_from_sector(hd, (void *)((uint32_t)buf + secs_done * 512), secs_op);
    secs_done += secs_op;
  }
  lock_release(&hd->my_channel->lock);
}

// 将buf中sec_cnt扇区数据写入硬盘
void ide_write(struct disk *hd, uint32_t lba, void *buf, uint32_t sec_cnt) {
  ASSERT(lba <= max_lba);
  ASSERT(sec_cnt > 0);
  lock_acquire(&hd->my_channel->lock);

  select_disk(hd);
  uint32_t secs_op;
  uint32_t secs_done = 0;
  while (secs_done < sec_cnt) {
    if ((secs_done + 256) <= sec_cnt) {
      secs_op = 256;
    } else {
      secs_op = sec_cnt - secs_done;
    }
    select_sector(hd, lba + secs_done, secs_op);
    cmd_out(hd->my_channel, CMD_WRITE_SECTOR);

    if (!busy_wait(hd)) {
      char error[64];
      sprintf(error, "%s write sector %d failed!!!!!!\n", hd->name, lba);
      PANIC(error);
    }

    // 将数据写入硬盘
    write2sector(hd, (void *)((uint32_t)buf + secs_done * 512), secs_op);
    /* 在硬盘响应期间阻塞自己 */
    sema_down(&hd->my_channel->disk_done);
    secs_done += secs_op;
  }
  // 【醒后执行】开始释放锁
  lock_release(&hd->my_channel->lock);
}

// 硬盘中断处理程序
void intr_hd_handler(uint8_t irq_no) {
  ASSERT(irq_no == 0x2e || irq_no == 0x2f); // irq_no中断号
  uint8_t ch_no = irq_no - 0x2e;
  struct ide_channel *channel = &channels[ch_no];
  ASSERT(channel->irq_no == irq_no);

  // 锁的存在保证了expecting_intr和中断的一一对应
  if (channel->expecting_intr) {
    channel->expecting_intr = false;
    sema_up(&channel->disk_done);
    inb(reg_status(
        channel)); // 读取状态寄存器后硬盘中断被处理，硬盘可继续执行新读写
  }
}

void ide_init() {
  printk("ide_init start\n");
  uint8_t hd_cnt = *((uint8_t *)(0x475)); // 获取硬盘数
  ASSERT(hd_cnt > 0);
  channel_cnt = DIV_ROUND_UP(hd_cnt, 2); // 根据硬盘数反推ide通道数
  struct ide_channel *channel;
  uint8_t channel_no = 0;

  while (channel_no < channel_cnt) {
    channel = &channels[channel_no];
    sprintf(channel->name, "ide%d", channel_no);

    /* 为每个ide通道初始化端口基址及中断向量 */
    switch (channel_no) {
    case 0:
      channel->port_base = 0x1f0;
      // 从片8259A上倒二的中断引脚（响应ide0通道上的硬盘中断
      channel->irq_no = 0x20 + 14;
      break;
    case 1:
      channel->port_base = 0x170;
      // 从片8259A上的最后一个中断引脚（响应ide1通道上的硬盘中断
      channel->irq_no = 0x20 + 15;
      break;
    }
    channel->expecting_intr = false; // 未向硬盘写入指令时不期待硬盘的中断
    lock_init(&channel->lock);
    /* 初始化为0，目的是向硬盘控制器请求数据后，硬盘驱动sema_down阻塞线程，
    直到硬盘完成后通过发中断，由中断处理程序将此信号量sema_up，唤醒线程 */
    sema_init(&channel->disk_done, 0);
    register_handler(channel->irq_no, intr_hd_handler);
    channel_no++; // 下个channel
  }
  printk("ide_init done\n");
}