#include "memory.h"
#include "bitmap.h"
#include "print.h"
#include "stdint.h"

#define PG_SIZE 4096 // 页大小0-> 4KB

/*-----------------------内存位图基址---------------------------*/
#define MEM_BITMAP_BASE 0xc009a000
#define K_HEAP_START 0xc0100000 // 内核堆空间起始地址
// 0xc0100000->
// 跟在低端1MB内存后面使虚拟地址在逻辑上连续（虚拟地址0xc000000-0xc00ffff低端1MB）

// 物理内存池结构
struct pool {
  struct bitmap pool_bitmap; // 位图-> 管理物理内存
  uint32_t phy_addr_start;   // 物理内存起始地址
  uint32_t pool_size;        // 字节容量
};

struct pool kernel_pool, user_pool;
struct virtual_addr kernel_vaddr; // 用来给内核分配虚拟地址

// 初始化内存池
static void mem_pool_init(uint32_t all_mem) {
  put_str("   mem_pool_init start\n");
  uint32_t page_table_size = PG_SIZE * 256; // 页表+页目录表
  uint32_t used_mem = page_table_size + 0x100000; // 已用：页表占大小+低端1MB
  uint32_t free_mem = all_mem - used_mem;
  uint16_t all_free_pages = free_mem / PG_SIZE; // free_mem转为的物理内存页数
  uint16_t kernel_free_pages = all_free_pages / 2;
  uint16_t user_free_pages = all_free_pages - kernel_free_pages;

  uint32_t kbm_len = kernel_free_pages / 8;
  uint32_t ubm_len = user_free_pages / 8;

  // 内核内存池起始地址
  uint32_t kp_start = used_mem;
  // 用户内存池起始地址
  uint32_t up_start = kp_start + kernel_free_pages * PG_SIZE;

  kernel_pool.phy_addr_start = kp_start;
  user_pool.phy_addr_start = up_start;

  kernel_pool.pool_size = kernel_free_pages * PG_SIZE;
  user_pool.pool_size = user_free_pages * PG_SIZE;

  kernel_pool.pool_bitmap.btmp_bytes_len = kbm_len;
  user_pool.pool_bitmap.btmp_bytes_len = ubm_len;

  kernel_pool.pool_bitmap.bits = (void *)MEM_BITMAP_BASE;
  user_pool.pool_bitmap.bits = (void *)(MEM_BITMAP_BASE + kbm_len);

  /* -----------------------输出内存池信息 -----------------------*/
  put_str("     kernel_pool_bitmap start: ");
  put_int((int)kernel_pool.pool_bitmap.bits);
  put_str(" kernel_pool_phy_addr start: ");
  put_int(kernel_pool.phy_addr_start);
  put_str("\n");
  put_str("     user_pool_bitmap start: ");
  put_int((int)user_pool.pool_bitmap.bits);
  put_str(" user_pool_phy_addr start: ");
  put_int(user_pool.phy_addr_start);
  put_str("\n");
  bitmap_init(&kernel_pool.pool_bitmap); // 将位图置0-> 表示位对应的页未分配
  bitmap_init(&user_pool.pool_bitmap);

  // 初始化内核虚拟地址池
  kernel_vaddr.vaddr_bitmap.btmp_bytes_len = kbm_len;
  kernel_vaddr.vaddr_bitmap.bits =
      (void *)(MEM_BITMAP_BASE + kbm_len + ubm_len);
  kernel_vaddr.vaddr_start = K_HEAP_START;
  bitmap_init(&kernel_vaddr.vaddr_bitmap);
  put_str("   mem_pool_init done\n");
}

// 内存管理部分初始化入口
void mem_init() {
  put_str("mem_init start\n");
  uint32_t mem_bytes_total = (*(uint32_t *)(0xb00));
  mem_pool_init(mem_bytes_total); // 初始化内存池
  put_str("mem_init done\n");
}