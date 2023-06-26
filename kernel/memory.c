#include "memory.h"
#include "bitmap.h"
#include "debug.h"
#include "global.h"
#include "print.h"
#include "stdint.h"
#include "string.h"
#include "sync.h"
#include "thread.h"

#define PG_SIZE 4096 // 页大小0-> 4KB

/*-----------------------内存位图基址---------------------------*/
// 因为0xc009f000是内核主线程栈顶，0xc009e000是内核主线程pcb
// 一个页框大小位图可表示128MB内存，位图位置安排在地址0xc009a000，这样本系统最大支持4个页框的位图，即512MB
#define MEM_BITMAP_BASE 0xc009a000
#define K_HEAP_START                                                           \
  0xc0100000 // 内核堆空间起始地址:跟在低端1MB内存后面使虚拟地址在逻辑上连续（虚拟地址0xc000000-0xc00ffff低端1MB）
#define PDE_IDX(addr) ((addr & 0xffc00000) >> 22) // 高10位
#define PTE_IDX(addr) ((addr & 0x003ff000) >> 12) // 中间10位

// 物理内存池结构
struct pool {
  struct bitmap pool_bitmap; // 位图-> 管理物理内存
  uint32_t phy_addr_start;   // 物理内存起始地址
  uint32_t pool_size;        // 字节容量
  struct lock lock;          // 申请内存时互斥
};
struct pool kernel_pool, user_pool;
struct virtual_addr kernel_vaddr; // 用来给内核分配虚拟地址

// 在虚拟内存池（pf指定类型）中申请pg_cnt个虚拟页
static void *vaddr_get(enum pool_flags pf, uint32_t pg_cnt) {
  int vaddr_start = 0, bit_idx_start = -1;
  uint32_t cnt = 0;

  if (pf == PF_KERNEL) {
    bit_idx_start = bitmap_scan(&kernel_vaddr.vaddr_bitmap, pg_cnt);
    if (bit_idx_start == -1) {
      return NULL; // 失败
    }
    while (cnt < pg_cnt) {
      bitmap_set(&kernel_vaddr.vaddr_bitmap, bit_idx_start + cnt++, 1);
    }
    // 将bit_idx_start转为虚拟地址
    vaddr_start = kernel_vaddr.vaddr_start + bit_idx_start * PG_SIZE;
  } else {
    struct task_struct *cur = running_thread();
    bit_idx_start = bitmap_scan(&cur->userprog_vaddr.vaddr_bitmap, pg_cnt);
    if (bit_idx_start == -1) {
      return NULL;
    }

    while (cnt < pg_cnt) {
      bitmap_set(&cur->userprog_vaddr.vaddr_bitmap, bit_idx_start + cnt++, 1);
    }
    vaddr_start = cur->userprog_vaddr.vaddr_start + bit_idx_start * PG_SIZE;

    // (0xc0000000-PG_SIZE)-> 用户3级栈
    ASSERT((uint32_t)vaddr_start < (0xc0000000 - PG_SIZE));
  }
  return (void *)vaddr_start;
}

// 得到虚拟地址对应的pte指针
uint32_t *pte_ptr(uint32_t vaddr) {
  /* 先访问到页表自己
   * 再用页目录项 pde（页目录内页表的索引）作为 pte 的索引访问到页表
   * 再用 pte 的索引作为页内偏移
   */
  uint32_t *pte = (uint32_t *)(0xffc00000 + ((vaddr & 0xffc00000) >> 10) +
                               PTE_IDX(vaddr) * 4);
  return pte;
}

// 得到虚拟地址对应的pde指针
uint32_t *pde_ptr(uint32_t vaddr) {
  // 0xfffff用来访问到页表本身所在的地址
  uint32_t *pde = (uint32_t *)((0xfffff000) + PDE_IDX(vaddr) * 4);
  return pde;
}

// 在m_pool指向的物理内存池中分配1个物理页
static void *palloc(struct pool *m_pool) {
  /* 扫描或设置位图要保证原子操作 */
  int bit_idx = bitmap_scan(&m_pool->pool_bitmap, 1); // 找一个物理页面
  if (bit_idx == -1) {
    return NULL; // 失败
  }
  bitmap_set(&m_pool->pool_bitmap, bit_idx, 1);
  uint32_t page_phyaddr = // 分配的物理页地址
      ((bit_idx * PG_SIZE) + m_pool->phy_addr_start);
  return (void *)page_phyaddr;
}

// 页表中添加虚拟地址与物理地址的映射
static void page_table_add(void *_vaddr, void *_page_phyaddr) {
  uint32_t vaddr = (uint32_t)_vaddr, page_phyaddr = (uint32_t)_page_phyaddr;
  uint32_t *pde = pde_ptr(vaddr);
  uint32_t *pte = pte_ptr(vaddr);

  // 在页目录表内判断目录项的P位，为1表示该表已存在
  if (*pde & 0x00000001) {
    ASSERT(!(*pte & 0x00000001));
    if (!(*pte & 0x00000001)) {
      *pte = (page_phyaddr | PG_US_U | PG_RW_W | PG_P_1); // US=1,RW=1,P=1
    } else {
      //目前不会执行到这，因为上面的ASSERT会先执行
      PANIC("pte repeat");
      *pte = (page_phyaddr | PG_US_U | PG_RW_W | PG_P_1); // US=1,RW=1,P=1
    }
  } else { // 页目录项不存在-> 先创建pde再创建pte
    uint32_t pde_pyhaddr = (uint32_t)palloc(&kernel_pool);
    *pde = (pde_pyhaddr | PG_US_U | PG_RW_W | PG_P_1);

    // 分配的物理内存清0，避免陈旧数据变成了pte从而让页表混乱
    // 取高20位，低12位置0
    memset((void *)((int)pte & 0xfffff000), 0, PG_SIZE);
    ASSERT(!(*pte & 0x00000001));
    *pte = (page_phyaddr | PG_US_U | PG_RW_W | PG_P_1); // US=1,RW=1,P=1
  }
}

/***** malloc_page：分配pg_cnt个页，成功返回起始虚拟地址 *******
1、在虚拟内存池中申请虚拟地址（vaddr_get）
2、在物理内存池中申请物理页（palloc）
3、将以上得到的虚拟地址和物理地址在页表中完成映射（page_table_add）
**********************************************************/
void *malloc_page(enum pool_flags pf, uint32_t pg_cnt) {
  ASSERT(pg_cnt > 0 && pg_cnt < 3840);
  void *vaddr_start = vaddr_get(pf, pg_cnt);
  if (vaddr_start == NULL) {
    return NULL; // 失败
  }

  uint32_t vaddr = (uint32_t)vaddr_start, cnt = pg_cnt;
  struct pool *mem_pool = pf & PF_KERNEL ? &kernel_pool : &user_pool;

  // 虚拟地址连续但物理地址可以不连续，所以逐个做映射
  while (cnt-- > 0) {
    void *page_phyaddr = palloc(mem_pool);
    if (page_phyaddr == NULL) {
      // TODO：失败时要将曾经已申请的虚拟地址和物理页全部回滚，完成内存回收时再补充
      return NULL;
    }
    page_table_add((void *)vaddr, page_phyaddr); // 在页表中作映射
    vaddr += PG_SIZE;                            // 下个虚拟页
  }
  return vaddr_start;
}

// 从内核物理内存池中申请1页内存，成功则返回其虚拟地址
void *get_kernel_pages(uint32_t pg_cnt) {
  void *vaddr = malloc_page(PF_KERNEL, pg_cnt);
  if (vaddr != NULL) { // 若分配的地址不为空，将页框清0后返回
    memset(vaddr, 0, pg_cnt * PG_SIZE);
  }
  return vaddr;
}

// 在用户空间中申请4k内存，并返回其虚拟地址
void *get_user_pages(uint32_t pg_cnt) {
  lock_acquire(&user_pool.lock);
  void *vaddr = malloc_page(PF_USER, pg_cnt);
  if (vaddr != NULL) {
    memset(vaddr, 0, pg_cnt * PG_SIZE);
  }
  lock_release(&user_pool.lock);
  return vaddr;
}

// 申请一页内存，并将vaddr映射到该页（即可指定虚拟地址
void *get_a_page(enum pool_flags pf, uint32_t vaddr) {
  struct pool *mem_pool = pf & PF_KERNEL ? &kernel_pool : &user_pool;
  lock_acquire(&mem_pool->lock);
  struct task_struct *cur = running_thread();
  int32_t bit_idx = -1;

  // 位图置1操作
  if (cur->pgdir != NULL && pf == PF_USER) {
    bit_idx = (vaddr - cur->userprog_vaddr.vaddr_start) / PG_SIZE;
    ASSERT(bit_idx > 0);
    bitmap_set(&cur->userprog_vaddr.vaddr_bitmap, bit_idx, 1);
  } else if (cur->pgdir == NULL && pf == PF_KERNEL) {
    bit_idx = (vaddr - kernel_vaddr.vaddr_start) / PG_SIZE;
    ASSERT(bit_idx > 0);
    bitmap_set(&kernel_vaddr.vaddr_bitmap, bit_idx, 1);
  } else {
    PANIC("get_a_pages: not allow kernel alloc userspace or user alloc "
          "kernelspace by get_a_page");
  }

  void *page_phyaddr = palloc(mem_pool);
  if (page_phyaddr == NULL) {
    return NULL;
  }
  page_table_add((void *)vaddr, page_phyaddr);
  lock_release(&mem_pool->lock);
  return (void *)vaddr;
}

// 得到vaddr映射的物理地址
uint32_t addr_v2p(uint32_t vaddr) {
  uint32_t *pte = pte_ptr(vaddr);
  return ((*pte & 0xfffff000) +
          (vaddr & 0x00000fff)); // 去掉页表物理地址低12位属性 + vaddr低12位
}

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
  lock_init(&kernel_pool.lock);
  lock_init(&user_pool.lock);

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