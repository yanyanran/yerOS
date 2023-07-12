#include "dir.h"
#include "debug.h"
#include "file.h"
#include "fs.h"
#include "global.h"
#include "ide.h"
#include "inode.h"
#include "memory.h"
#include "stdint.h"
#include "stdio_kernel.h"
#include "string.h"
#include "super_block.h"

struct dir root_dir; // 根目录

// 打开根目录
void open_root_dir(struct partition *part) {
  root_dir.inode = inode_open(part, part->sb->root_inode_no);
  root_dir.dir_pos = 0;
}

// 打开inode_no目录并返回目录指针
struct dir *dir_open(struct partition *part, uint32_t inode_no) {
  struct dir *pdir = (struct dir *)sys_malloc(sizeof(struct dir));
  pdir->inode = inode_open(part, inode_no);
  pdir->dir_pos = 0;
  return pdir;
}

// 在part分区内的pdir目录内寻找name文件/目录，找到后目录项存入dir_e（目录指针pdir、目录项指针dir_e
bool search_dir_entry(struct partition *part, struct dir *pdir,
                      const char *name, struct dir_entry *dir_e) {
  uint32_t block_cnt = 140; // 12个直接块+128个间接块
  uint32_t *all_blocks = (uint32_t *)sys_malloc(560);
  if (all_blocks == NULL) {
    printk("search_dir_entry: sys_malloc for all_blocks failed");
    return false;
  }

  uint32_t block_idx = 0;
  while (block_idx < 12) {
    all_blocks[block_idx] = pdir->inode->i_sectors[block_idx];
    block_idx++;
  }
  block_idx = 0;

  if (pdir->inode->i_sectors[12] != 0) { // 有一级间接块表
    ide_read(part->my_disk, pdir->inode->i_sectors[12], all_blocks + 12, 1);
  }
  // 至此all_blocks存了该文件/目录的所有扇区地址

  // 往目录中写目录项选择写一整个扇区
  uint8_t *buf = (uint8_t *)sys_malloc(SECTOR_SIZE);
  struct dir_entry *p_de = (struct dir_entry *)buf; // p_de为指向目录项的指针
  uint32_t dir_entry_size = part->sb->dir_entry_size;
  uint32_t dir_entry_cnt = SECTOR_SIZE / dir_entry_size; // 1扇区容纳的目录项数

  // 【先遍历扇区】
  while (block_idx < block_cnt) {
    if (all_blocks[block_idx] == 0) { // 该块中无数据
      block_idx++;
      continue;
    }
    ide_read(part->my_disk, all_blocks[block_idx], buf, 1);

    uint32_t dir_entry_idx = 0;
    // 【再遍历各个扇区中的所有目录项】
    while (dir_entry_idx < dir_entry_cnt) {
      // 若找到了，就直接复制整个目录项
      if (!strcmp(p_de->filename, name)) {
        memcpy(dir_e, p_de, dir_entry_size);
        sys_free(buf);
        sys_free(all_blocks);
        return true;
      }
      dir_entry_idx++;
      p_de++;
    }
    block_idx++;
    p_de = (struct dir_entry *)
        buf; // 此时p_de已指向扇区内最后一个完整目录项，需恢复p_de指向为buf
    memset(buf, 0, SECTOR_SIZE); // buf清0
  }
  sys_free(buf);
  sys_free(all_blocks);
  return false;
}

// 关闭目录（根目录不能关闭，root_dir在低端1MB之内而不在堆中，free会出问题
void dir_close(struct dir *dir) {
  if (dir == &root_dir) {
    return;
  }
  inode_close(dir->inode);
  sys_free(dir);
}

// 在内存中初始化目录项p_de
void create_dir_entry(char *filename, uint32_t inode_no, uint8_t file_type,
                      struct dir_entry *p_de) {
  ASSERT(strlen(filename) <= MAX_FILE_NAME_LEN);
  memcpy(p_de->filename, filename, strlen(filename));
  p_de->i_no = inode_no;
  p_de->f_type = file_type;
}

// 将目录项写入父目录中
bool sync_dir_entry(struct dir *parent_dir, struct dir_entry *p_de,
                    void *io_buf) {
  struct inode *dir_inode = parent_dir->inode;
  uint32_t dir_size = dir_inode->i_size;
  uint32_t dir_entry_size = cur_part->sb->dir_entry_size;
  ASSERT(dir_size % dir_entry_size == 0);              // 整数倍
  uint32_t dir_entry_per_sec = (512 / dir_entry_size); // 每扇区最大的目录项数
  int32_t block_lba = -1;

  // 将该目录的所有扇区地址（12个直接块+128个间接块）存入all_blocks
  uint8_t block_idx = 0;
  uint32_t all_blocks[140] = {0}; // 保存目录所有的块

  while (block_idx < 12) {
    all_blocks[block_idx] = dir_inode->i_sectors[block_idx];
    block_idx++;
  }

  struct dir_entry *dir_e = (struct dir_entry *)io_buf; // 在io_buf中遍历目录项
  int32_t block_bitmap_idx = -1;

  // 开始遍历所有块寻找目录项空位（无空闲则申请新扇区来存
  block_idx = 0;
  while (block_idx < 140) {
    block_bitmap_idx = -1;
    if (all_blocks[block_idx] == 0) {
      block_lba = block_bitmap_malloc(cur_part);
      if (block_lba == -1) {
        printk("malloc block bitmap for sync_dir_entry failed\n");
        return false;
      }

      // 【每分配一个块就同步一次block_bitmap】
      block_bitmap_idx = block_lba - cur_part->sb->data_start_lba;
      ASSERT(block_bitmap_idx != -1);
      bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
      block_bitmap_idx = -1;

      if (block_idx < 12) { // 直接块
        dir_inode->i_sectors[block_idx] = all_blocks[block_idx] = block_lba;
      } else if (block_idx == 12) { // 未分配一级间接块表
        // 将上面分配的块作为一级间接块表地址
        dir_inode->i_sectors[12] = block_lba;
        block_lba = -1;
        // 再分配一个第0个间接块
        block_lba = block_bitmap_malloc(cur_part);
        if (block_lba == -1) {
          block_bitmap_idx =
              dir_inode->i_sectors[12] - cur_part->sb->data_start_lba;
          bitmap_set(&cur_part->block_bitmap, block_bitmap_idx, 0);
          // 同步到磁盘
          bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
          dir_inode->i_sectors[12] = 0;
          printk("malloc block bitmap for sync_dir_entry failed\n");
          return false;
        }

        // 【每分配一个块就同步一次block_bitmap】
        block_bitmap_idx = block_lba - cur_part->sb->data_start_lba;
        ASSERT(block_bitmap_idx != -1);
        bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
        all_blocks[12] = block_lba;

        /* 把新分配的第0个间接块地址写入一级间接块表 */
        ide_write(cur_part->my_disk, dir_inode->i_sectors[12], all_blocks + 12,
                  1);
      } else { // 建立间接块
        all_blocks[block_idx] = block_lba;
        // 把新分配的第(block_idx-12)个间接块地址写入一级间接块表
        ide_write(cur_part->my_disk, dir_inode->i_sectors[12], all_blocks + 12,
                  1);
      }

      // 再将新目录项p_de写入新分配的间接块
      memset(io_buf, 0, 512);
      memcpy(io_buf, p_de, dir_entry_size);
      ide_write(cur_part->my_disk, all_blocks[block_idx], io_buf, 1);
      dir_inode->i_size += dir_entry_size;
      return true;
    }

    // 若第block_idx块已存在，将其读进内存，然后在该块中查找空目录项
    ide_read(cur_part->my_disk, all_blocks[block_idx], io_buf, 1);
    uint8_t dir_entry_idx = 0;
    while (dir_entry_idx < dir_entry_per_sec) { // 在扇区内查找空目录项
      if ((dir_e + dir_entry_idx)->f_type == FT_UNKNOWN) {
        memcpy(dir_e + dir_entry_idx, p_de, dir_entry_size);
        ide_write(cur_part->my_disk, all_blocks[block_idx], io_buf, 1);
        dir_inode->i_size += dir_entry_size;
        return true;
      }
      dir_entry_idx++;
    }
    block_idx++;
    if (block_idx > 12) {
      ide_read(cur_part->my_disk, all_blocks[12], all_blocks + 12, 1);
    }
  }
  printk("directory is full!\n");
  return false;
}

// 把分区part目录pdir中编号为inode_no的目录项删除
bool delete_dir_entry(struct partition *part, struct dir *pdir,
                      uint32_t inode_no, void *io_buf) {
  struct inode *dir_inode = pdir->inode;
  uint32_t block_idx = 0, all_blocks[140] = {0};

  while (block_idx < 12) {
    all_blocks[block_idx] = dir_inode->i_sectors[block_idx];
    block_idx++;
  }
  if (dir_inode->i_sectors[12]) {
    ide_read(part->my_disk, dir_inode->i_sectors[12], all_blocks + 12, 1);
  }

  uint32_t dir_entry_size = part->sb->dir_entry_size;
  uint32_t dir_entry_per_sec =
      (SECTOR_SIZE / dir_entry_size); // 每扇区最大的目录项数目
  struct dir_entry *dir_e = (struct dir_entry *)io_buf;
  struct dir_entry *dir_entry_found = NULL;
  uint8_t dir_entry_idx, dir_entry_cnt; // 此扇区内目录项总数
  bool is_dir_first_block = false; // 当前待删除的块是否是目录第一个块“.”

  // 遍历所有块寻找目录项
  block_idx = 0;
  while (block_idx < 140) {
    is_dir_first_block = false;
    if (all_blocks[block_idx] == 0) {
      block_idx++;
      continue;
    }
    dir_entry_idx = dir_entry_cnt = 0;
    memset(io_buf, 0, SECTOR_SIZE);
    // 读扇区获取目录项
    ide_read(part->my_disk, all_blocks[block_idx], io_buf, 1);

    /* 遍历所有的目录项，统计该扇区的目录项数量及是否有待删除的目录项 */
    while (dir_entry_idx < dir_entry_per_sec) {
      if ((dir_e + dir_entry_idx)->f_type != FT_UNKNOWN) { // 该目录项有意义
        if (!strcmp((dir_e + dir_entry_idx)->filename, ".")) {
          is_dir_first_block = true;
        } else if (strcmp((dir_e + dir_entry_idx)->filename, ".") &&
                   strcmp((dir_e + dir_entry_idx)->filename, "..")) {
          dir_entry_cnt++; // 用来判断删除目录项后是否回收该扇区
          if ((dir_e + dir_entry_idx)->i_no == inode_no) { // 找到此inode
            ASSERT(dir_entry_found == NULL);
            // 将其记录在dir_entry_found
            dir_entry_found = dir_e + dir_entry_idx;
            /* 找到后也继续遍历，统计总目录项数 */
          }
        }
      }
      dir_entry_idx++;
    }
    /* 此扇区未找到该目录项，继续在下个扇区找 */
    if (dir_entry_found == NULL) {
      block_idx++;
      continue;
    }
    /* 找到目录项 */
    ASSERT(dir_entry_cnt >= 1);
    // 除目录第1个扇区外，该扇区只有目录项自己-> 将整个扇区回收
    if (dir_entry_cnt == 1 && !is_dir_first_block) {
      // 1、从块位图中回收该块
      uint32_t block_bitmap_idx =
          all_blocks[block_idx] - part->sb->data_start_lba;
      bitmap_set(&part->block_bitmap, block_bitmap_idx, 0);
      bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
      // 2、将块地址从数组i_sectors或索引表中去掉
      if (block_idx < 12) {
        dir_inode->i_sectors[block_idx] = 0;
      } else { /* 先判断一级间接索引表的间接块数，如果仅有这个间接块，连同间接索引表块一同回收*/
        uint32_t indirect_blocks = 0;
        uint32_t indirect_block_idx = 12;
        while (indirect_block_idx < 140) {
          if (all_blocks[indirect_block_idx] != 0) {
            indirect_blocks++;
          }
        }
        ASSERT(indirect_blocks >= 1);
        if (indirect_blocks > 1) { // 间接索引表中还有其他间接块
          all_blocks[block_idx] = 0;
          ide_write(part->my_disk, dir_inode->i_sectors[12], all_blocks + 12,
                    1);
        } else {
          /* 回收间接索引表所在的块 */
          block_bitmap_idx =
              dir_inode->i_sectors[12] - part->sb->data_start_lba;
          bitmap_set(&part->block_bitmap, block_bitmap_idx, 0);
          bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
          dir_inode->i_sectors[12] = 0; // 将间接索引表地址清0
        }
      }
    } else { // 仅将该目录项清空
      memset(dir_entry_found, 0, dir_entry_size);
      ide_write(part->my_disk, all_blocks[block_idx], io_buf, 1);
    }

    // 更新inode信息并同步到磁盘
    ASSERT(dir_inode->i_size >= dir_entry_size);
    dir_inode->i_size -= dir_entry_size;
    memset(io_buf, 0, SECTOR_SIZE * 2);
    inode_sync(part, dir_inode, io_buf);
    return true;
  }
  // 所有块中未找到则返回false（这种情况该是serarch_file出错了
  return false;
}

// 读取目录，成功返回1个目录项
struct dir_entry *dir_read(struct dir *dir) {
  struct dir_entry *dir_e = (struct dir_entry *)dir->dir_buf;
  struct inode *dir_inode = dir->inode;
  uint32_t all_blocks[140] = {0}, block_cnt = 12;
  uint32_t block_idx = 0, dir_entry_idx = 0;

  while (block_idx < 12) {
    all_blocks[block_idx] = dir_inode->i_sectors[block_idx];
    block_idx++;
  }

  block_idx = 0;
  uint32_t cur_dir_entry_pos = 0; // 当前目录项偏移,判断目录项是否之前已经返回过
  uint32_t dir_entry_size = cur_part->sb->dir_entry_size;
  uint32_t dir_entrys_per_sec =
      SECTOR_SIZE / dir_entry_size; // 一扇区内可容纳目录项个数

  // 在目录大小内遍历
  while (block_idx < block_cnt) {
    if (dir->dir_pos >= dir_inode->i_size) {
      return NULL;
    }
    if (all_blocks[block_idx] == 0) { // 此块地址为0即空块，继续读出下一块
      block_idx++;
      continue;
    }
    memset(dir_e, 0, SECTOR_SIZE);
    ide_read(cur_part->my_disk, all_blocks[block_idx], dir_e, 1);
    dir_entry_idx = 0;
    // 遍历块内所有目录项
    while (dir_entry_idx < dir_entrys_per_sec) {
      if ((dir_e + dir_entry_idx)->f_type) { // 文件类型有效
        if (cur_dir_entry_pos < dir->dir_pos) { // 判断是不是最新的目录项
          // 是之前返回过的目录项
          cur_dir_entry_pos += dir_entry_size;
          dir_entry_idx++;
          continue;
        }
        ASSERT(cur_dir_entry_pos == dir->dir_pos); // 找到了要返回的目录项
        if (dir_inode->i_sectors[12] != 0) {       // 有一级间接块表
          ide_read(cur_part->my_disk, dir_inode->i_sectors[12], all_blocks + 12,
                   1);
          block_cnt = 140;
        }
        dir->dir_pos += dir_entry_size; // 更新位置为下个返回的目录项地址
        return dir_e + dir_entry_idx;
      }
      dir_entry_idx++;
    }
    block_idx++;
  }
  return NULL;
}