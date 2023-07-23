#include "file.h"
#include "bitmap.h"
#include "debug.h"
#include "dir.h"
#include "fs.h"
#include "global.h"
#include "ide.h"
#include "inode.h"
#include "interrupt.h"
#include "memory.h"
#include "stdint.h"
#include "stdio_kernel.h"
#include "string.h"
#include "super_block.h"
#include "thread.h"

struct file file_table[MAX_FILE_OPEN]; // 文件表（文件处于打开状态

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
  return local_fd_idx; // 文件描述符（也就是下标）
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
  int32_t bit_idx = bitmap_scan(&part->block_bitmap, 1);
  if (bit_idx == -1) {
    return -1;
  }
  bitmap_set(&part->block_bitmap, bit_idx, 1);
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

// 创建文件，成功返回文件描述符
int32_t file_create(struct dir *parent_dir, char *filename, uint8_t flag) {
  void *io_buf = sys_malloc(1024);
  if (io_buf == NULL) {
    printk("in file_creat: sys_malloc for io_buf failed\n");
    return -1;
  }
  uint8_t rollback_step = 0; // 用于操作失败时回滚各资源状态

  int32_t inode_no = inode_bitmap_malloc(cur_part); // 分配inode
  if (inode_no == -1) {
    printk("in file_creat: allocate inode failed\n");
    return -1;
  }
  /* 为使通过sys_malloc创建的新inode被所有任务共享，需将inode置于内核空间 */
  struct task_struct *cur = running_thread();
  uint32_t *cur_pgdir_bak = cur->pgdir;
  cur->pgdir = NULL; // 接下来分配的内存位于内核区
  struct inode *new_file_inode =
      (struct inode *)sys_malloc(sizeof(struct inode));
  if (new_file_inode == NULL) {
    printk("file_create: sys_malloc for inode failded\n");
    rollback_step = 1;
    goto rollback;
  }
  cur->pgdir = cur_pgdir_bak; // 恢复
  inode_init(inode_no, new_file_inode);

  int fd_idx = get_free_slot_in_global(); // file_table数组下标
  if (fd_idx == -1) {
    printk("exceed max open files\n");
    rollback_step = 2;
    goto rollback;
  }

  file_table[fd_idx].fd_inode = new_file_inode;
  file_table[fd_idx].fd_pos = 0;
  file_table[fd_idx].fd_flag = flag;
  file_table[fd_idx].fd_inode->write_deny = false;

  struct dir_entry new_dir_entry;
  memset(&new_dir_entry, 0, sizeof(struct dir_entry));
  create_dir_entry(filename, inode_no, FT_REGULAR, &new_dir_entry);

  /* 同步内存数据到磁盘 */
  // 1、在目录parent_dir下安装目录项new_dir_entry，写入磁盘后返回true
  if (!sync_dir_entry(parent_dir, &new_dir_entry, io_buf)) {
    printk("sync dir_entry to disk failed\n");
    rollback_step = 3;
    goto rollback;
  }
  memset(io_buf, 0, 1024);
  // 2、将父目录inode的内容同步到磁盘
  inode_sync(cur_part, parent_dir->inode, io_buf);
  memset(io_buf, 0, 1024);
  // 3、将新创建文件inode内容同步到磁盘
  inode_sync(cur_part, new_file_inode, io_buf);
  // 4、将inode_bitmap同步到磁盘
  bitmap_sync(cur_part, inode_no, INODE_BITMAP);
  // 5、将创建的文件inode添加到open_inodes链表
  list_push(&cur_part->open_inodes, &new_file_inode->inode_tag);
  new_file_inode->i_open_cnt = 1;

  sys_free(io_buf);
  return pcb_fd_install(fd_idx); // 返回文件描述符

// 回滚资源操作
rollback:
  switch (rollback_step) {
  case 3:
    // 失败时，将file_table中相应位清空
    memset(&file_table[fd_idx], 0, sizeof(struct file));
  case 2:
    sys_free(new_file_inode);
  case 1:
    // 如果新文件inode创建失败，之前位图中分配的inode_no也要恢复
    bitmap_set(&cur_part->inode_bitmap, inode_no, 0);
    break;
  }
  sys_free(io_buf);
  return -1;
}

// 打开编号为inode_no的inode对应文件，成功返回文件描述符
int32_t file_open(uint32_t inode_no, uint8_t flag) {
  int fd_idx = get_free_slot_in_global();
  if (fd_idx == -1) {
    printk("exceed max open files\n");
    return -1;
  }

  file_table[fd_idx].fd_inode = inode_open(cur_part, inode_no);
  file_table[fd_idx].fd_pos = 0; // 每次打开文件要让文件内指针指向开头
  file_table[fd_idx].fd_flag = flag;
  bool *write_deny = &file_table[fd_idx].fd_inode->write_deny; // 并行检查

  if (flag & O_WRONLY || flag & O_RDWR) {
    enum intr_status old_status = intr_disable(); // 进入临界区前先关中断
    if (!(*write_deny)) {
      *write_deny = true; // 当前没有其他进程写该文件，将其占用
      intr_set_status(old_status); // 恢复中断
    } else {
      intr_set_status(old_status);
      printk("file can't be write now, try again later\n");
      return -1;
    }
  }
  // 读或创建文件，不用理write_deny，保持默认
  return pcb_fd_install(fd_idx);
}

// 关闭文件
int32_t file_close(struct file *file) {
  if (file == NULL) {
    return -1;
  }
  file->fd_inode->write_deny = false;
  inode_close(file->fd_inode);
  file->fd_inode = NULL; // 使文件结构可用
  return 0;
}

// 把buf中count个字节写入file，成功返回写入字节数，失败返-1
int32_t file_write(struct file *file, const void *buf, uint32_t count) {
  // 文件支持的最大字节
  if ((file->fd_inode->i_size + count) > (BLOCK_SIZE * 140)) {
    printk("exceed max file_size 71680 bytes, write file failed\n");
    return -1;
  }

  uint8_t *io_buf = sys_malloc(512);
  if (io_buf == NULL) {
    printk("file_write: sys_malloc for io_buf failed\n");
    return -1;
  }

  // 记录文件所有块地址
  uint32_t *all_blocks = (uint32_t *)sys_malloc(BLOCK_SIZE + 48);
  if (all_blocks == NULL) {
    printk("file_write: sys_malloc for all_blocks failed\n");
    return -1;
  }

  const uint8_t *src = buf;   // 指向buf中待写入数据
  uint32_t bytes_written = 0; // 已写入数据大小
  uint32_t size_left = count; // 未写入数据大小
  uint32_t block_idx;
  int32_t block_lba = -1;
  uint32_t block_bitmap_idx = 0;
  uint32_t sec_idx;
  uint32_t sec_lba;
  uint32_t sec_off_bytes;        // 扇区内字节偏移量
  uint32_t sec_left_bytes;       // 扇区剩余字节量
  uint32_t chunk_size;           // 每次写入硬盘的数据块大小
  uint32_t indirect_block_table; // 一级间接表地址

  // 文件是否是第一次写
  if (file->fd_inode->i_sectors[0] == 0) {
    block_lba = block_bitmap_malloc(cur_part); // 先为其分配一个块
    if (block_lba == -1) {
      printk("file_write: block_bitmap_alloc failed\n");
      return -1;
    }
    file->fd_inode->i_sectors[0] = block_lba;

    // 每分配一个块就将位图同步磁盘
    block_bitmap_idx = block_lba - cur_part->sb->data_start_lba;
    ASSERT(block_bitmap_idx != 0);
    bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
  }

  uint32_t file_has_used_blocks = // 写count个字节前该文件已占用的块数
      file->fd_inode->i_size / BLOCK_SIZE + 1;
  uint32_t file_will_use_blocks = // 存count字节后该文件将占用的块数
      (file->fd_inode->i_size + count) / BLOCK_SIZE + 1;
  ASSERT(file_will_use_blocks <= 140);
  uint32_t add_blocks = // 用来判断是否需要分配新扇区
      file_will_use_blocks - file_has_used_blocks;

  // 将写文件所用到的块地址收集到all_blocks
  if (add_blocks == 0) { // 无需分配新扇区
    if (file_will_use_blocks <= 12) {
      block_idx = file_has_used_blocks - 1; // 指向最后一个已有数据的扇区
      all_blocks[block_idx] = file->fd_inode->i_sectors[block_idx];
    } else { // 写前已占了间接块-> 将间接块地址（i_sectors[12]）读进来
      ASSERT(file->fd_inode->i_sectors[12] != 0);
      indirect_block_table = file->fd_inode->i_sectors[12];
      ide_read(cur_part->my_disk, indirect_block_table, all_blocks + 12, 1);
    }
  } else { // 需要分配新扇区
    /* 1、12个直接块够用 */
    if (file_will_use_blocks <= 12) {
      // 先将有剩余空间的第一个可用块地址写入all_blocks
      block_idx = file_has_used_blocks - 1;
      ASSERT(file->fd_inode->i_sectors[block_idx] != 0);
      all_blocks[block_idx] = file->fd_inode->i_sectors[block_idx];
      block_idx = file_has_used_blocks; // 指向第一个要分配的新块

      while (block_idx < file_will_use_blocks) {
        // 除第一个块 后面占的整块再另外开辟
        block_lba = block_bitmap_malloc(cur_part);
        if (block_lba == -1) {
          printk("file_write: block_bitmap_malloc for situation 1 failed\n");
          return -1;
        }
        ASSERT(file->fd_inode->i_sectors[block_idx] == 0); // 确保未分配扇区地址
        file->fd_inode->i_sectors[block_idx] = all_blocks[block_idx] =
            block_lba;
        // 每分配一个块就将位图同步到磁盘
        block_bitmap_idx = block_lba - cur_part->sb->data_start_lba;
        bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
        block_idx++; // 下个新扇区
      }
    } else if (file_has_used_blocks <= 12 && file_will_use_blocks > 12) {
      /* 2、旧数据在12个直接块内，新数据将使用间接块*/
      block_idx = file_has_used_blocks - 1;
      all_blocks[block_idx] = file->fd_inode->i_sectors[block_idx];
      block_lba = block_bitmap_malloc(cur_part); // 创建一级间接块表
      if (block_lba == -1) {
        printk("file_write: block_bitmap_malloc for situation 2 failed\n");
        return -1;
      }
      block_bitmap_idx = block_lba - cur_part->sb->data_start_lba;
      bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);

      ASSERT(file->fd_inode->i_sectors[12] == 0); // 确保一级间接块表未分配
      // 分配一级间接块索引表
      indirect_block_table = file->fd_inode->i_sectors[12] = block_lba;
      block_idx = file_has_used_blocks;

      while (block_idx < file_will_use_blocks) {
        block_lba = block_bitmap_malloc(cur_part);
        if (block_lba == -1) {
          printk("file_write: block_bitmap_malloc for situation 2 failed\n");
          return -1;
        }
        if (block_idx < 12) {
          ASSERT(file->fd_inode->i_sectors[block_idx] == 0);
          file->fd_inode->i_sectors[block_idx] = all_blocks[block_idx] =
              block_lba;
        } else {
          all_blocks[block_idx] = block_lba;
        }
        block_bitmap_idx = block_lba - cur_part->sb->data_start_lba;
        bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
        block_idx++; // 下个新扇区
      }
      // 同步一级间接块表到磁盘
      ide_write(cur_part->my_disk, indirect_block_table, all_blocks + 12, 1);
    } else if (file_has_used_blocks > 12) {
      /* 3、占间接块 */
      ASSERT(file->fd_inode->i_sectors[12] != 0);
      indirect_block_table = file->fd_inode->i_sectors[12];
      ide_read(cur_part->my_disk, indirect_block_table, all_blocks + 12, 1);
      block_idx = file_has_used_blocks; // 第一个未使用的间接块

      while (block_idx < file_will_use_blocks) {
        block_lba = block_bitmap_malloc(cur_part);
        if (block_lba == -1) {
          printk("file_write: block_bitmap_malloc for situation 3 failed\n");
          return -1;
        }
        all_blocks[block_idx++] = block_lba;
        block_bitmap_idx = block_lba - cur_part->sb->data_start_lba;
        bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
      }
      // 同步一级间接块表到磁盘
      ide_write(cur_part->my_disk, indirect_block_table, all_blocks + 12, 1);
    }
  }

  /* 用到的块地址已收集到all_blocks中，下面开始写数据 */
  bool first_write_block = true;
  file->fd_pos = file->fd_inode->i_size - 1;
  while (bytes_written < count) {
    memset(io_buf, 0, BLOCK_SIZE);
    sec_idx = file->fd_inode->i_size / BLOCK_SIZE;
    sec_lba = all_blocks[sec_idx];
    sec_off_bytes = file->fd_inode->i_size % BLOCK_SIZE;
    sec_left_bytes = BLOCK_SIZE - sec_off_bytes;
    /* 判断此次写入磁盘的数据大小 */
    chunk_size = size_left < sec_left_bytes ? size_left : sec_left_bytes;
    if (first_write_block) {
      ide_read(cur_part->my_disk, sec_lba, io_buf, 1);
      first_write_block = false;
    }
    memcpy(io_buf + sec_off_bytes, src, chunk_size);
    ide_write(cur_part->my_disk, sec_lba, io_buf, 1);
    printk("file write at lba 0x%x\n", sec_lba); // 调试，完成后去掉
    src += chunk_size;                    // 指针推移到下个新数据
    file->fd_inode->i_size += chunk_size; // 更新文件大小
    file->fd_pos += chunk_size;
    bytes_written += chunk_size;
    size_left -= chunk_size;
  }
  inode_sync(cur_part, file->fd_inode, io_buf);
  sys_free(all_blocks);
  sys_free(io_buf);
  return bytes_written;
}

// 从文件中读取count个字节写入buf，成功返回读出字节数
int32_t file_read(struct file *file, void *buf, uint32_t count) {
  uint8_t *buf_dst = (uint8_t *)buf;
  uint32_t size = count, size_left = size;

  // 要读取字节数超过了文件可读剩余量
  if ((file->fd_pos + count) > file->fd_inode->i_size) {
    size = file->fd_inode->i_size - file->fd_pos; // 用剩余量作为待读取字节数
    size_left = size;
    if (size == 0) { // 到文件尾，返回-1
      return -1;
    }
  }

  uint8_t *io_buf = sys_malloc(BLOCK_SIZE);
  if (io_buf == NULL) {
    printk("file_read: sys_malloc for io_buf failed\n");
  }
  uint32_t *all_blocks = (uint32_t *)sys_malloc(BLOCK_SIZE + 48);
  if (all_blocks == NULL) {
    printk("file_read: sys_malloc for all_blocks failed\n");
    return -1;
  }

  uint32_t block_read_start_idx = // 数据所在块的起始地址
      file->fd_pos / BLOCK_SIZE;
  uint32_t block_read_end_idx = // 数据所在块的终止地址
      (file->fd_pos + size) / BLOCK_SIZE;
  uint32_t read_blocks = // 增量为0表示数据在同一个块
      block_read_start_idx - block_read_end_idx;
  ASSERT(block_read_start_idx < 139 && block_read_end_idx < 139);

  int32_t indirect_block_table; // 一级间接表地址
  uint32_t block_idx;           // 待读的块地址

  /* 开始构建all_blocks块地址数组 */
  if (read_blocks == 0) { // 同个块
    ASSERT(block_read_end_idx == block_read_start_idx);
    if (block_read_end_idx < 12) { // 待读数据在12个直接块内
      block_idx = block_read_end_idx;
      all_blocks[block_idx] = file->fd_inode->i_sectors[block_idx];
    } else { // 用到一级间接块表，需将表中间接块读进来
      indirect_block_table = file->fd_inode->i_sectors[12];
      ide_read(cur_part->my_disk, indirect_block_table, all_blocks + 12, 1);
    }
  } else {                         // 读多个块
    if (block_read_end_idx < 12) { /* 1、起始块和终止块属于直接块 */
      block_idx = block_read_start_idx;
      while (block_idx <= block_read_end_idx) {
        all_blocks[block_idx] = file->fd_inode->i_sectors[block_idx];
        block_idx++;
      }
    } else /* 2、待读入数据跨越直接块和间接块 */
      if (block_read_start_idx < 12 && block_read_end_idx >= 12) {
        block_idx = block_read_start_idx;
        while (block_idx < 12) { // 先将直接块地址写入all_blocks
          all_blocks[block_idx] = file->fd_inode->i_sectors[block_idx];
          block_idx++;
        }
        ASSERT(file->fd_inode->i_sectors[12] != 0);
        indirect_block_table = file->fd_inode->i_sectors[12];
        // 将一级间接块表读进来写入all_blocks第13个块位置之后
        ide_read(cur_part->my_disk, indirect_block_table, all_blocks + 12, 1);
      } else {
        /* 3、数据在间接块中 */
        ASSERT(file->fd_inode->i_sectors[12] != 0);
        indirect_block_table = file->fd_inode->i_sectors[12];
        ide_read(cur_part->my_disk, indirect_block_table, all_blocks + 12, 1);
      }
  }

  /* 用到的块地址已收集到all_blocks中，开始读数据 */
  uint32_t sec_idx, sec_lba, sec_off_bytes, sec_left_bytes, chunk_size;
  uint32_t bytes_read = 0;

  while (bytes_read < size) { // 读完为止
    sec_idx = file->fd_pos / BLOCK_SIZE;
    sec_lba = all_blocks[sec_idx];
    sec_off_bytes = file->fd_pos % BLOCK_SIZE;
    sec_left_bytes = BLOCK_SIZE - sec_off_bytes;
    chunk_size = size_left < sec_left_bytes
                     ? size_left
                     : sec_left_bytes; // 待读入的数据大小
    memset(io_buf, 0, BLOCK_SIZE);
    ide_read(cur_part->my_disk, sec_lba, io_buf, 1);
    memcpy(buf_dst, io_buf + sec_off_bytes, chunk_size);

    buf_dst += chunk_size;
    file->fd_pos += chunk_size;
    bytes_read += chunk_size;
    size_left -= chunk_size;
  }
  sys_free(all_blocks);
  sys_free(io_buf);
  return bytes_read;
}