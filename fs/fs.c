#include "fs.h"
#include "console.h"
#include "debug.h"
#include "dir.h"
#include "file.h"
#include "global.h"
#include "ide.h"
#include "inode.h"
#include "list.h"
#include "memory.h"
#include "print.h"
#include "stdint.h"
#include "stdio_kernel.h"
#include "string.h"
#include "super_block.h"
#include "thread.h"

struct partition *cur_part; // 默认情况下操作的是哪个分区

// 在分区链表中找到名为part_name的分区，并将其指针赋值给cur_part
static bool mount_partition(struct list_elem *pelem, int arg) {
  char *part_name = (char *)arg;
  struct partition *part = elem2entry(struct partition, part_tag, pelem);

  if (!strcmp(part->name, part_name)) {
    cur_part = part;
    struct disk *hd = cur_part->my_disk;
    struct super_block *sb_buf = (struct super_block *)sys_malloc(SECTOR_SIZE);

    // 在内存中创建cur_part分区的超级块
    cur_part->sb = (struct super_block *)sys_malloc(sizeof(struct super_block));
    if (cur_part->sb == NULL) {
      PANIC("alloc memory failed!");
    }
    memset(sb_buf, 0, SECTOR_SIZE);
    ide_read(hd, cur_part->start_lba + 1, sb_buf, 1); // 读超级块到sb_buf
    memcpy(cur_part->sb, sb_buf,
           sizeof(struct super_block)); // 复制到分区超级块sb中

    // 把磁盘上的块位图读入内存
    cur_part->block_bitmap.bits =
        (uint8_t *)sys_malloc(sb_buf->block_bitmap_sects * SECTOR_SIZE);
    if (cur_part->block_bitmap.bits == NULL) {
      PANIC("alloc memeory failed!");
    }
    cur_part->block_bitmap.btmp_bytes_len =
        sb_buf->block_bitmap_sects * SECTOR_SIZE;
    ide_read(hd, sb_buf->block_bitmap_lba, cur_part->block_bitmap.bits,
             sb_buf->block_bitmap_sects);

    // 将磁盘上的inode位图读入到内存
    cur_part->inode_bitmap.bits =
        (uint8_t *)sys_malloc(sb_buf->inode_bitmap_sects * SECTOR_SIZE);
    if (cur_part->inode_bitmap.bits == NULL) {
      PANIC("alloc memory failed!");
    }
    cur_part->inode_bitmap.btmp_bytes_len =
        sb_buf->inode_bitmap_sects * SECTOR_SIZE;
    ide_read(hd, sb_buf->inode_bitmap_lba, cur_part->inode_bitmap.bits,
             sb_buf->inode_bitmap_sects);

    list_init(&cur_part->open_inodes);
    printk("mount %s done!\n", part->name);
    return true; // 停止遍历
  }
  return false; // 继续遍历
}

// 初始化分区元信息（一个块大小是一扇区
static void partition_format(struct disk *hd, struct partition *part) {
  uint32_t boot_sector_sects = 1;
  uint32_t super_block_sects = 1;
  uint32_t inode_bitmap_sects = // inode位图占扇区数1（最多支持4096个文件
      DIV_ROUND_UP(MAX_FILES_PER_PART, BITS_PER_SECTOR);
  uint32_t inode_table_sects = // inode数组占扇区数
      DIV_ROUND_UP(((sizeof(struct inode) * MAX_FILES_PER_PART)), SECTOR_SIZE);
  uint32_t used_sects = boot_sector_sects + super_block_sects +
                        inode_bitmap_sects + inode_table_sects;
  uint32_t free_sects = part->sec_cnt - used_sects;

  // 处理块位图占的扇区数【动态规划】
  uint32_t block_bitmap_sects = DIV_ROUND_UP(free_sects, BITS_PER_SECTOR);
  uint32_t block_bitmap_bit_len =
      free_sects - block_bitmap_sects; // 位图中位的个数（真正的空闲块数）
  block_bitmap_sects = DIV_ROUND_UP(block_bitmap_bit_len, BITS_PER_SECTOR);

  // 超级块初始化
  struct super_block sb;
  sb.magic = 0x20021112;
  sb.sec_cnt = part->sec_cnt;
  sb.inode_cnt = MAX_FILES_PER_PART;
  sb.part_lba_base = part->start_lba;

  sb.block_bitmap_lba = sb.part_lba_base + 2; // 第0块是引导块，第1块是超级块
  sb.block_bitmap_sects = block_bitmap_sects;

  sb.inode_bitmap_lba = sb.block_bitmap_lba + sb.block_bitmap_sects;
  sb.inode_bitmap_sects = inode_bitmap_sects;

  sb.inode_table_lba = sb.inode_bitmap_lba + sb.inode_bitmap_sects;
  sb.inode_table_sects = inode_table_sects;

  sb.data_start_lba = sb.inode_table_lba + sb.inode_table_sects;
  sb.root_inode_no = 0; // inode数组中第0个留给根目录
  sb.dir_entry_size = sizeof(struct dir_entry);

  printk("%s info:\n", part->name);
  printk("      magic : 0x%x\n      part_lba_base : 0x%x\n      all_sectors : "
         "0x%x\n      inode_cnt : 0x%x\n    block_bitmap_lba : 0x%x\n     "
         "block_bitmap_sectors : 0x%x\n     inode_bitmap_lba : 0x%x\n     "
         "inode_bitmap_sectors : 0x%x\n     inode_table_lba : 0x%x\n    "
         "inode_table_sectors : 0x%x\n    data_start_lba : 0x%x\n ",
         sb.magic, sb.part_lba_base, sb.sec_cnt, sb.inode_cnt,
         sb.block_bitmap_lba, sb.block_bitmap_sects, sb.inode_bitmap_lba,
         sb.inode_bitmap_sects, sb.inode_table_lba, sb.inode_table_sects,
         sb.data_start_lba);

  hd = part->my_disk;
  /* 1、将超级块写入本分区的1扇区 */
  ide_write(hd, part->start_lba + 1, &sb, 1);
  printk("      super_block_lba : 0x%x\n", part->start_lba + 1);

  // 用数据量最大的元信息尺寸做存储缓冲区
  uint32_t buf_size =
      (sb.block_bitmap_sects >= sb.inode_bitmap_sects ? sb.block_bitmap_sects
                                                      : sb.inode_bitmap_sects);
  buf_size =
      (buf_size >= sb.inode_table_sects ? buf_size : sb.inode_table_sects) *
      SECTOR_SIZE;
  uint8_t *buf =
      (uint8_t *)sys_malloc(buf_size); // 申请的内存由内存管理系统清0后返回

  /* 2、块位图初始化并写入磁盘 */
  buf[0] = 0x01; // （占位）第0个块预留给根目录
  uint32_t block_bitmap_last_byte = block_bitmap_bit_len / 8;
  uint8_t block_bitmap_last_bit = block_bitmap_bit_len % 8;
  uint32_t last_size = // 位图所在最后一个扇区中不足一扇区的其余部分
      SECTOR_SIZE - (block_bitmap_last_byte % SECTOR_SIZE);

  // 先将超出实际块数部分置为1已占用,再将覆盖的最后一字节内的有效位重新置0
  memset(&buf[block_bitmap_last_byte], 0xff, last_size);
  uint8_t bit_idx = 0;
  while (bit_idx <= block_bitmap_last_bit) {
    buf[block_bitmap_last_byte] &= ~(1 << bit_idx++);
  }
  ide_write(hd, sb.block_bitmap_lba, buf, sb.block_bitmap_sects);

  /* 3、inode位图初始化并写入磁盘 */
  memset(buf, 0, buf_size);
  buf[0] |= 0x1; // 第0个inode给根目录
  ide_write(hd, sb.inode_bitmap_lba, buf, sb.inode_bitmap_sects);

  /* 4、inode数组初始化并写入磁盘 */
  memset(buf, 0, buf_size);
  struct inode *i = (struct inode *)buf;
  i->i_size = sb.dir_entry_size * 2; // .和..
  i->i_no = 0;
  i->i_sectors[0] = sb.data_start_lba;
  ide_write(hd, sb.inode_table_lba, buf, sb.inode_table_sects);

  /* 5、把根目录（两个目录项.和..）写入磁盘 */
  memset(buf, 0, buf_size);
  struct dir_entry *p_de = (struct dir_entry *)buf;

  // 初始化当前目录.
  memcpy(p_de->filename, ".", 1);
  p_de->i_no = 0;
  p_de->f_type = FT_DIRECTORY;
  p_de++;

  // 初始化当前目录父目录..
  memcpy(p_de->filename, "..", 2);
  p_de->i_no = 0;
  p_de->f_type = FT_DIRECTORY;
  ide_write(hd, sb.data_start_lba, buf, 1);

  printk("root_dir_lba : 0x%x\n", sb.data_start_lba);
  printk("%s format done\n", part->name);

  sys_free(buf); // 释放缓冲区
}

// 将最上层路径名解析出来（类似pop
static char *path_parse(char *pathname, char *name_store) {
  if (pathname[0] == '/') { // 跳过'/'
    while (*(++pathname) == '/') {
    }
  }

  // 一般路径解析
  while (*pathname != '/' && *pathname != 0) {
    *name_store++ = *pathname++;
  }
  if (pathname[0] == 0) { // 路径字符串为空
    return NULL;
  }
  return pathname;
}

// 返回路径深度
int32_t path_depth_cnt(char *pathname) {
  ASSERT(pathname != NULL);
  char *p = pathname;
  char name[MAX_FILE_NAME_LEN];
  uint32_t depth = 0;

  // 解析路径，从中拆分出各级名称
  p = path_parse(p, name);
  while (name[0]) {
    depth++;
    memset(name, 0, MAX_FILE_NAME_LEN);
    if (p) { // p非空就继续分析路径
      p = path_parse(p, name);
    }
  }
  return depth;
}

// 搜索文件,找到返回inode号,保证父目录打开
static int search_file(const char *pathname,
                       struct path_search_record *searched_record) {
  // 待查找的是根目录
  if (!strcmp(pathname, "/") || !strcmp(pathname, "/.") ||
      !strcmp(pathname, "/..")) {
    searched_record->parent_dir = &root_dir;
    searched_record->file_type = FT_DIRECTORY;
    searched_record->searched_path[0] = 0; // 搜索路径置空
    return 0;
  }

  uint32_t path_len = strlen(pathname);
  ASSERT(pathname[0] == '/' && path_len > 1 && path_len < MAX_PATH_LEN);
  char *sub_path = (char *)pathname;
  struct dir *parent_dir = &root_dir;
  struct dir_entry dir_e;
  char name[MAX_FILE_NAME_LEN] = {0}; // 记录路径解析出来的各级名称

  searched_record->parent_dir = parent_dir;
  searched_record->file_type = FT_UNKNOWN;
  uint32_t parent_inode_no = 0;
  /*
   * input->/a/b/c  output->  [name]a; [sub_path]/b/c
   */
  sub_path = path_parse(sub_path, name);

  while (name[0]) {
    ASSERT(strlen(searched_record->searched_path) < 512);

    // 记录已存在的父目录
    strcat(searched_record->searched_path, "/");
    strcat(searched_record->searched_path, name);

    // 在所给目录中查找文件
    if (search_dir_entry(cur_part, parent_dir, name, &dir_e)) {
      memset(name, 0, MAX_FILE_NAME_LEN);
      if (sub_path) { // sub_path不为空，未结束，继续拆分
        sub_path = path_parse(sub_path, name);
      }

      if (FT_DIRECTORY == dir_e.f_type) { // 目录
        parent_inode_no = parent_dir->inode->i_no;
        dir_close(parent_dir);
        parent_dir = dir_open(cur_part, dir_e.i_no); // 更新父目录
        searched_record->parent_dir = parent_dir;
        continue;
      } else if (FT_REGULAR == dir_e.f_type) { // 普通文件
        searched_record->file_type = FT_REGULAR;
        return dir_e.i_no;
      }
    } else { // 找不到目录项也要留着parent_dir不要关闭，创建新文件需要在parent_dir中创
      return -1;
    }
  }

  // 执行到此，必然是遍历了完整路径，且查找的文件/目录存在
  dir_close(searched_record->parent_dir);
  // 保存被查找目录的直接父目录
  searched_record->parent_dir = dir_open(cur_part, parent_inode_no);
  searched_record->file_type = FT_DIRECTORY;
  return dir_e.i_no;
}

// 创建文件
int32_t sys_create(const char *pathname) {
  // TODO：sys_create创建文件后文件需保持关闭状态
  return 0;
}

// 打开/创建文件，成功返回文件描述符fd
int32_t sys_open(const char *pathname, uint8_t flags) {
  if (pathname[strlen(pathname) - 1] == '/') { // 目录不行
    printk("can`t open a directory %s\n", pathname);
    return -1;
  }
  ASSERT(flags <= 7);
  int32_t fd = -1;

  struct path_search_record searched_record;
  memset(&searched_record, 0, sizeof(struct path_search_record));
  uint32_t pathname_depth = path_depth_cnt((char *)pathname); // 总目录深度

  // 检查文件是否存在
  int inode_no = search_file(pathname, &searched_record);
  bool found = inode_no != -1 ? true : false;

  if (searched_record.file_type == FT_DIRECTORY) {
    printk("can`t open a direcotry with open(), use opendir() to instead\n");
    dir_close(searched_record.parent_dir);
    return -1;
  }

  uint32_t path_searched_depth = path_depth_cnt(searched_record.searched_path);

  // 是否在某个中间目录就失败了
  if (pathname_depth != path_searched_depth) {
    printk("cannot access %s: Not a directory, subpath %s is’t exist\n",
           pathname, searched_record.searched_path);
    dir_close(searched_record.parent_dir);
    return -1;
  }

  // 在最后一个路径上没找到且不创建文件
  if (!found && !(flags & O_CREAT)) {
    printk("in path %s, file %s is`t exist\n", searched_record.searched_path,
           (strrchr(searched_record.searched_path, '/') + 1));
    dir_close(searched_record.parent_dir);
    return -1;
  } else if (found &&
             flags &
                 O_CREAT) { // TODO
                            // FIX：若要创建的文件已存在，Linux选择open该文件
    printk("%s has already exist!\n", pathname);
    dir_close(searched_record.parent_dir);
    return -1;
  }

  /*
   * create用法：sys_open(“xxx”,O_CREAT|O_XXX)
   */
  switch (flags & O_CREAT) {
  case O_CREAT:
    printk("creating file\n");
    fd = file_create(searched_record.parent_dir, (strrchr(pathname, '/') + 1),
                     flags);
    dir_close(searched_record.parent_dir);
  default: // 其余情况均为打开已存在文件O_RDONLY,O_WRONLY,O_RDWR
    fd = file_open(inode_no, flags);
  }
  return fd; // 此fd是任务pcb->fd_table数组中的元素下标
}

// 将文件描述符转化为文件表的下标
static uint32_t fd_local2global(uint32_t local_fd) {
  struct task_struct *cur = running_thread();
  int32_t global_fd = cur->fd_table[local_fd];
  ASSERT(global_fd >= 0 && global_fd < MAX_FILE_OPEN);
  return (uint32_t)global_fd;
}

// 关闭文件描述符fd指向的文件，成功返0否则返-1
int32_t sys_close(int32_t fd) {
  int32_t ret = -1;
  if (fd > 2) {
    uint32_t _fd = fd_local2global(fd);
    ret = file_close(&file_table[_fd]);
    running_thread()->fd_table[fd] = -1; // 使该文件描述符位可用
  }
  return ret;
}

// 将buf中连续count个字节写入文件描述符fd，成功返回写入字节数
uint32_t sys_write(int32_t fd, const void *buf, uint32_t count) {
  if (fd < 0) {
    printk("sys_write: fd error\n");
    return -1;
  }
  if (fd == stdout_no) { // 往屏幕上打印信息
    char tmp_buf[1024] = {0};
    memcpy(tmp_buf, buf, count);
    console_put_str(tmp_buf);
    return count;
  }
  // 往文件中写数据
  uint32_t _fd = fd_local2global(fd);
  struct file *wr_file = &file_table[_fd];
  if (wr_file->fd_flag & O_WRONLY || wr_file->fd_flag & O_RDWR) {
    uint32_t bytes_written = file_write(wr_file, buf, count);
    return bytes_written;
  } else {
    console_put_str("sys_write: not allowed to write file without flag O_RDWR "
                    "or O_WRONLY\n");
    return -1;
  }
}

// 从文件描述符fd指向文件中读count个字节到buf，成功返回读出字节数
int32_t sys_read(int32_t fd, void *buf, uint32_t count) {
  if (fd < 0) {
    printk("sys_read: fd error\n");
    return -1;
  }
  ASSERT(buf != NULL);
  uint32_t _fd = fd_local2global(fd);
  return file_read(&file_table[_fd], buf, count);
}

// 重置用于文件读写操作的偏移指针，成功返回新偏移量（whence + offset-> fd_pos
int32_t sys_lseek(int32_t fd, int32_t offset, uint8_t whence) {
  if (fd < 0) {
    printk("sys_lseek: fd error\n");
    return -1;
  }
  ASSERT(whence > 0 && whence < 4);
  int32_t new_pos = 0;
  uint32_t _fd = fd_local2global(fd);
  struct file *pf = &file_table[_fd];
  int32_t file_size = (int32_t)pf->fd_inode->i_size;

  switch (whence) {
  case SEEK_SET:
    new_pos = offset;
    break;
  case SEEK_CUR: // offse可正可负
    new_pos = (int32_t)pf->fd_pos + offset;
    break;
  case SEEK_END: // offset为负
    new_pos = file_size + offset;
  }
  if (new_pos < 0 || new_pos > (file_size - 1)) {
    return -1;
  }
  pf->fd_pos = new_pos;
  return pf->fd_pos;
}

// 删除文件（目录），成功返回0
int32_t sys_unlink(const char *pathname) {
  ASSERT(strlen(pathname) < MAX_PATH_LEN);
  struct path_search_record searched_record;
  memset(&searched_record, 0, sizeof(struct path_search_record));
  int inode_no =
      search_file(pathname, &searched_record); // 检查待删除文件是否存在
  ASSERT(inode_no != 0);
  if (inode_no == -1) {
    printk("file %s not found!\n", pathname);
    dir_close(searched_record.parent_dir);
    return -1;
  }

  uint32_t file_idx = 0;
  while (file_idx < MAX_FILE_OPEN) {
    if (file_table[file_idx].fd_inode != NULL &&
        (uint32_t)inode_no == file_table[file_idx].fd_inode->i_no) {
      break;
    }
    file_idx++;
  }

  // 判断是否在已打开文件表file_table中
  if (file_idx < MAX_FILE_OPEN) {
    // 父目录是在search_file时打开的，所以退出时需关闭
    dir_close(searched_record.parent_dir);
    printk("file %s is in use, not allow to delete!\n", pathname);
    return -1;
  }
  ASSERT(file_idx == MAX_FILE_OPEN);

  // 为delete_dir_entry申请缓冲区
  void *io_buf = sys_malloc(SECTOR_SIZE + SECTOR_SIZE);
  if (io_buf == NULL) {
    dir_close(searched_record.parent_dir);
    printk("sys_unlink: malloc for io_buf failed\n");
    return -1;
  }
  struct dir *parent_dir = searched_record.parent_dir;
  delete_dir_entry(cur_part, parent_dir, inode_no, io_buf);
  inode_release(cur_part, inode_no);
  sys_free(io_buf);
  dir_close(searched_record.parent_dir);
  return 0; // 成功删除文件
}

// 在磁盘上搜索文件系统，若没有则格式化分区创建文件系统
void filesys_init() {
  uint8_t channel_no = 0, dev_no, part_idx = 0;
  struct super_block *sb_buf = (struct super_block *)sys_malloc(SECTOR_SIZE);
  uint32_t fd_idx = 0;

  if (sb_buf == NULL) {
    PANIC("malloc memory failed!");
  }
  printk("searching filesystem.....\n");

  while (channel_no < channel_cnt) {
    dev_no = 0;
    while (dev_no < 2) {
      if (dev_no == 0) { // 跨过裸盘hd60M.img
        dev_no++;
        continue;
      }
      struct disk *hd = &channels[channel_no].devices[dev_no];
      struct partition *part = hd->prim_parts;
      while (part_idx < 12) { // 4个主分区+8个逻辑分区
        if (part_idx == 4) {  // 主分区处理完开始处理逻辑分区
          part = hd->logic_parts;
        }

        if (part->sec_cnt != 0) { // 分区存在
          memset(sb_buf, 0, SECTOR_SIZE);
          ide_read(hd, part->start_lba + 1, sb_buf, 1); // 读分区超级块
          if (sb_buf->magic == 0x20021112) {
            printk("%s has filesystem\n", part->name);
          } else {
            printk("formatting %s`s partition %s......\n", hd->name,
                   part->name);
            partition_format(hd, part);
          }
        }
        part_idx++;
        part++; // 下一分区
      }
      dev_no++; // 下一磁盘
    }
    channel_no++; // 下一通道
  }
  sys_free(sb_buf);
  char default_part[8] = "sdb1"; // 默认操作分区
  list_traversal(&partition_list, mount_partition,
                 (int)default_part); // 挂载分区

  open_root_dir(cur_part);         // 打开当前分区根目录
  while (fd_idx < MAX_FILE_OPEN) { // 初始化文件表
    file_table[fd_idx++].fd_inode = NULL;
  }
}