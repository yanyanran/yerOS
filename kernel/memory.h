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
void mem_init(void);

#endif /* KERNEL_MEMORY */
