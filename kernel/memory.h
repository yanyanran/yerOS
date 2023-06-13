#ifndef KERNEL_MEMORY
#define KERNEL_MEMORY
#include "bitmap.h"
#include "stdint.h"

// 虚拟地址池，用于虚拟地址管理
struct virtual_addr {
  struct bitmap vaddr_bitmap; //虚拟地址用到的位图结构
  uint32_t vaddr_start;       //虚拟地址起始地址
};

extern struct pool kernel_pool, user_pool;
void *get_kernel_pages(uint32_t pg_cnt);
void mem_init();

// 内存池标记，用于判断用哪个内存池（内核/用户）
enum pool_flags { PF_KERNEL = 1, PF_USER = 2 };

#define PG_P_1 1 // 页内存存在
#define PG_P_0 0 // 页内存不存在

#define PG_RW_R 0 // 读/执行
#define PG_RW_W 2 // 读/写/执行

#define PG_US_S 0 // 系统级
#define PG_US_U 4 // 用户级

#endif /* KERNEL_MEMORY */
