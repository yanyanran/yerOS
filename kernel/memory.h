#ifndef KERNEL_MEMORY
#define KERNEL_MEMORY
#include "bitmap.h"
#include "list.h"
#include "stdint.h"

// 虚拟地址池，用于虚拟地址管理
struct virtual_addr {
  struct bitmap vaddr_bitmap; // 虚拟地址用到的位图结构
  uint32_t vaddr_start;       // 虚拟地址起始地址
};

// 内存池标记，用于判断用哪个内存池（内核/用户）
enum pool_flags { PF_KERNEL = 1, PF_USER = 2 };

#define PG_P_1 1 // 页内存存在
#define PG_P_0 0 // 页内存不存在

#define PG_RW_R 0 // 读/执行
#define PG_RW_W 2 // 读/写/执行

#define PG_US_S 0 // 系统级
#define PG_US_U 4 // 用户级

extern struct pool kernel_pool, user_pool;
void *get_kernel_pages(uint32_t pg_cnt);
void *get_user_pages(uint32_t pg_cnt);
void *get_a_page(enum pool_flags pf, uint32_t vaddr);
void mem_init();
uint32_t addr_v2p(uint32_t vaddr);

// 内存块
struct mem_block {
  struct list_elem free_elem;
};

// 内存块描述符
struct mem_block_desc {
  uint32_t block_size;      // 内存块大小
  uint32_t block_per_arena; // 本arena中可容纳此mem_block数
  struct list free_list;    // 目前可用的mem_block链表
};

#define DESC_CNT 7 // mem_block_desc个数

void block_desc_init(struct mem_block_desc *desc_array);
void *sys_malloc(uint32_t size);
void sys_free(void *ptr);

#endif /* KERNEL_MEMORY */
