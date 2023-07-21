#include "memory.h"
#include "bitmap.h"
#include "debug.h"
#include "global.h"
#include "interrupt.h"
#include "list.h"
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

// 12字节的元数据
struct arena {
  struct mem_block_desc *desc;
  uint32_t cnt;
  bool large; /// ture-> cnt为页框数，否则表示空闲mem_block数
};

struct mem_block_desc k_block_descs[DESC_CNT]; // 内核内存块描述符数组
struct pool kernel_pool, user_pool;
struct virtual_addr kernel_vaddr; // 用来给内核分配虚拟地址

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

// 得到vaddr映射的物理地址
uint32_t addr_v2p(uint32_t vaddr) {
  uint32_t *pte = pte_ptr(vaddr);
  return ((*pte & 0xfffff000) +
          (vaddr & 0x00000fff)); // 去掉页表物理地址低12位属性 + vaddr低12位
}

// 返回arena中第idx个内存块的地址
static struct mem_block *arena2block(struct arena *a, uint32_t idx) {
  return (struct mem_block *)((uint32_t)a + sizeof(struct arena) +
                              idx * a->desc->block_size);
}

// 返回内存块b所在的arena地址
static struct arena *block2arena(struct mem_block *b) {
  return (struct arena *)((uint32_t)b & 0xfffff000);
}

// --------------------------------------------------------------------------------------------

// 在虚拟内存池（pf指定类型）中申请pg_cnt个虚拟页p *(struct arena*)0xc0101000
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

// 安装一页大小vaddr而无需操作虚拟地址位图（fork
void *get_a_page_without_opvaddrbitmap(enum pool_flags pf, uint32_t vaddr) {
  struct pool *mem_pool = pf & PF_KERNEL ? &kernel_pool : &user_pool;
  lock_acquire(&mem_pool->lock);
  void *page_phyaddr = palloc(mem_pool);
  if (page_phyaddr == NULL) {
    lock_release(&mem_pool->lock);
    return NULL;
  }
  page_table_add((void *)vaddr, page_phyaddr);
  lock_release(&mem_pool->lock);
  return (void *)vaddr;
}

// 从堆中申请size字节内存
void *sys_malloc(uint32_t size) {
  enum pool_flags PF;
  struct pool *mem_pool;
  uint32_t pool_size;
  struct mem_block_desc *descs;
  struct task_struct *cur_thread = running_thread();

  if (cur_thread->pgdir == NULL) { // 内核线程
    PF = PF_KERNEL;
    mem_pool = &kernel_pool;
    pool_size = kernel_pool.pool_size;
    descs = k_block_descs;
  } else { // 用户进程
    PF = PF_USER;
    mem_pool = &user_pool;
    pool_size = user_pool.pool_size;
    descs = cur_thread->u_block_desc;
  }

  if (!(size > 0 && size < pool_size)) {
    return NULL;
  }
  struct arena *a;
  struct mem_block *b;
  lock_acquire(&mem_pool->lock);

  if (size > 1024) { // 直接分配页框
    uint32_t page_cnt = DIV_ROUND_UP(size + sizeof(struct arena), PG_SIZE);
    a = malloc_page(PF, page_cnt);

    if (a != NULL) {
      memset(a, 0, page_cnt * PG_SIZE); // 分配的内存清0

      // 分配大块页框-> desc置NULL，cnt置为页框数，large置true
      a->desc = NULL;
      a->cnt = page_cnt;
      a->large = true;
      lock_release(&mem_pool->lock);
      return (void *)++a; // 跨过arena大小把剩下内存返回
    } else {
      lock_release(&mem_pool->lock);
      return NULL;
    }
  } else { // 去各规格mem_block_desc中适配
    uint32_t desc_idx;
    for (desc_idx = 0; desc_idx < DESC_CNT; desc_idx++) {
      if (size <= descs[desc_idx].block_size) {
        break;
      }
    }

    if (list_empty(&descs[desc_idx].free_list)) { // 没有可用mem_block->
                                                  // 创建新arena提供mem_block
      a = malloc_page(PF, 1); // 分配1页框作为arena
      if (a == NULL) {
        lock_release(&mem_pool->lock);
        return NULL;
      }
      memset(a, 0, PG_SIZE);

      // 分配小块内存->
      // desc置为相应内存块描述符，cnt置为此arena可用的内存块数,large置false
      a->desc = &descs[desc_idx];
      a->large = false;
      a->cnt = descs[desc_idx].block_per_arena;
      uint32_t block_idx;

      enum intr_status old_status = intr_disable();

      // 将arena拆分成内存块，并添加到内存块描述符的free_list中
      for (block_idx = 0; block_idx < descs[desc_idx].block_per_arena;
           block_idx++) {
        b = arena2block(a, block_idx);
        ASSERT(!elem_find(&a->desc->free_list, &b->free_elem));
        list_append(&a->desc->free_list, &b->free_elem);
      }
      intr_set_status(old_status);
    }

    // 开始分配内存块
    b = elem2entry(struct mem_block, free_elem,
                   list_pop(&(descs[desc_idx].free_list)));
    memset(b, 0, descs[desc_idx].block_size);

    a = block2arena(b); // 获取内存块b所在arena
    a->cnt--;           // 此arena中的空闲内存块数--
    lock_release(&mem_pool->lock);
    return (void *)b;
  }
}

// --------------------------------------------------------------------------------------------

// 在内存池中释放一页物理页
void pfree(uint32_t pg_phy_addr) {
  struct pool *mem_pool;
  uint32_t bit_idx = 0; // 地址在物理内存池中的偏移量
  if (pg_phy_addr >= user_pool.phy_addr_start) { // 用户物理内存池
    mem_pool = &user_pool;
    bit_idx = (pg_phy_addr - user_pool.phy_addr_start) / PG_SIZE;
  } else { // 内核物理内存池
    mem_pool = &kernel_pool;
    bit_idx = (pg_phy_addr - kernel_pool.phy_addr_start) / PG_SIZE;
  }
  bitmap_set(&mem_pool->pool_bitmap, bit_idx, 0); // 将位图中该位清0
}

// 去掉页表中虚拟地址的映射，只去掉vaddr对应的pte
static void page_table_pte_remove(uint32_t vaddr) {
  uint32_t *pte = pte_ptr(vaddr);
  *pte &= ~PG_P_1;                                   // pte的P位取反置0
  asm volatile("invlpg %0" ::"m"(vaddr) : "memory"); // 更新tlb
}

// 在虚拟地址池中释放以_vaddr起始的连续pg_nct个虚拟页地址
static void vaddr_remove(enum pool_flags pf, void *_vaddr, uint32_t pg_cnt) {
  uint32_t bit_idx_start = 0;
  uint32_t vaddr = (uint32_t)_vaddr;
  uint32_t cnt = 0;

  if (pf == PF_KERNEL) {
    bit_idx_start = (vaddr - kernel_vaddr.vaddr_start) / PG_SIZE;
    while (cnt < pg_cnt) {
      bitmap_set(&kernel_vaddr.vaddr_bitmap, bit_idx_start + cnt++, 0);
    }
  } else {
    struct task_struct *cur_thread = running_thread();
    bit_idx_start = (vaddr - cur_thread->userprog_vaddr.vaddr_start) / PG_SIZE;
    while (cnt < pg_cnt) {
      bitmap_set(&cur_thread->userprog_vaddr.vaddr_bitmap,
                 bit_idx_start + cnt++, 0);
    }
  }
}

/***** mfree_page：释放以虚拟地址vaddr为始的cnt个物理页框 *******
1、在物理地址池中释放物理页地址（pfree）
2、在页表中去掉虚拟地址映射-> 虚拟地址对应pte的P置0（page_table_pte_remove）
3、在虚拟地址池中释放虚拟地址（vaddr_remove）
**********************************************************/
void mfree_page(enum pool_flags pf, void *_vaddr, uint32_t pg_cnt) {
  uint32_t pg_phy_addr;
  uint32_t vaddr = (uint32_t)_vaddr;
  uint32_t page_cnt = 0;
  ASSERT(pg_cnt >= 1 && vaddr % PG_SIZE == 0);
  pg_phy_addr = addr_v2p(vaddr);

  // 确保释放的物理内存在低端1MB+1KB大小的页目录+1KB大小的页表地址范围外
  ASSERT((pg_phy_addr % PG_SIZE) == 0 && pg_phy_addr >= 0x102000);

  if (pg_phy_addr >= user_pool.phy_addr_start) {
    vaddr -= PG_SIZE;
    while (page_cnt < pg_cnt) {
      vaddr += PG_SIZE;
      pg_phy_addr = addr_v2p(vaddr);

      // 确保物理地址属于用户物理内存池
      ASSERT((pg_phy_addr % PG_SIZE) == 0 &&
             pg_phy_addr >= user_pool.phy_addr_start);
      pfree(pg_phy_addr);
      page_table_pte_remove(vaddr);
      page_cnt++;
    }
    vaddr_remove(pf, _vaddr, pg_cnt);
  } else {
    vaddr -= PG_SIZE;
    while (page_cnt < pg_cnt) {
      vaddr += PG_SIZE;
      pg_phy_addr = addr_v2p(vaddr);

      // 确保待释放的物理内存只属于内核物理内存池
      ASSERT((pg_phy_addr % PG_SIZE) == 0 &&
             pg_phy_addr >= kernel_pool.phy_addr_start &&
             pg_phy_addr < user_pool.phy_addr_start);
      pfree(pg_phy_addr);
      page_table_pte_remove(vaddr);
      page_cnt++;
    }
    vaddr_remove(pf, _vaddr, pg_cnt);
  }
}

// 释放ptr指向的内存
void sys_free(void *ptr) {
  ASSERT(ptr != NULL);
  if (ptr != NULL) {
    enum pool_flags PF;
    struct pool *mem_pool;

    if (running_thread()->pgdir == NULL) {
      ASSERT((uint32_t)ptr >= K_HEAP_START);
      PF = PF_KERNEL;
      mem_pool = &kernel_pool;
    } else {
      PF = PF_USER;
      mem_pool = &user_pool;
    }

    lock_acquire(&mem_pool->lock);
    struct mem_block *b = ptr;
    struct arena *a = block2arena(b); // 把mem_block转换成arena，获取元信息
    ASSERT(a->large == 0 || a->large == 1);

    if (a->desc == NULL && a->large == true) { // >1024的内存
      mfree_page(PF, a, a->cnt);
    } else { // <=1024的内存
      // 将内存块回收到free_list
      list_append(&a->desc->free_list, &b->free_elem);
      // 判断此arena中的内存块是否都空闲，空闲释放arena
      if (++(a->cnt) == a->desc->block_per_arena) {
        uint32_t block_idx;
        for (block_idx = 0; block_idx < a->desc->block_per_arena; block_idx++) {
          struct mem_block *b = arena2block(a, block_idx);
          ASSERT(elem_find(&a->desc->free_list, &b->free_elem));
          list_remove(&b->free_elem);
        }
        mfree_page(PF, a, 1);
      }
    }
    lock_release(&mem_pool->lock);
  }
}

// 根据物理页地址在对应的内存池位图清0,不改动页表
void free_a_phy_page(uint32_t pg_phy_addr) {
  struct pool *mem_pool;
  uint32_t bit_idx = 0;

  if (pg_phy_addr >= user_pool.phy_addr_start) {
    mem_pool = &user_pool;
    bit_idx = (pg_phy_addr - user_pool.phy_addr_start) / PG_SIZE;
  } else {
    mem_pool = &kernel_pool;
    bit_idx = (pg_phy_addr - kernel_pool.phy_addr_start) / PG_SIZE;
  }
  bitmap_set(&mem_pool->pool_bitmap, bit_idx, 0);
}

// --------------------------------------------------------------------------------------------

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

// 初始化内存块描述符数组中的7个描述符，为malloc做准备
void block_desc_init(struct mem_block_desc *desc_array) {
  uint16_t desc_idx;
  uint16_t block_size = 16;

  for (desc_idx = 0; desc_idx < DESC_CNT; desc_idx++) {
    desc_array[desc_idx].block_size = block_size;

    // 初始化arena中的内存块数量
    desc_array[desc_idx].block_per_arena =
        (PG_SIZE - sizeof(struct arena)) / block_size;
    list_init(&desc_array[desc_idx].free_list);
    block_size *= 2; // 更新为下一个规格内存块
    // 下标越低，内存块容量越小
  }
}

// 内存管理部分初始化入口
void mem_init() {
  put_str("mem_init start\n");
  uint32_t mem_bytes_total = (*(uint32_t *)(0xb00));
  mem_pool_init(mem_bytes_total); // 初始化内存池
  block_desc_init(k_block_descs); // 初始化mem_block_deesc数组descs
  put_str("mem_init done\n");
}