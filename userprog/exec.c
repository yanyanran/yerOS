#include "fs.h"
#include "global.h"
#include "interrupt.h"
#include "list.h"
#include "memory.h"
#include "stdint.h"
#include "stdio.h"
#include "string.h"
#include "thread.h"

extern void intr_exit(void);
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

// 32位elf头
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum; // 段数量
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

// 程序头表(段头表
struct Elf32_Phdr {
  Elf32_Word p_type; // 见下面的senum segment_type
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

// 可识别的段类型
enum segment_type {
  PT_NULL,    // 忽略
  PT_LOAD,    // 可加载程序段
  PT_DYNAMIC, // 动态加载信息
  PT_INTERP,  // 动态加载器名称
  PT_NOTE,    // 一些辅助信息
  PT_SHLIB,   // 保留
  PT_PHDR     // 程序头表
};

// [段加载到内存]
// 将文件描述符fd指向的文件中偏移offset，大小filesz的段加载到虚拟地址vaddr内存
static bool segment_load(int32_t fd, uint32_t offset, uint32_t filesz,
                         uint32_t vaddr) {
  uint32_t vaddr_first_page = vaddr & 0xfffff000; // vaddr地址所在页框起始地址
  uint32_t size_in_first_page =
      PG_SIZE - (vaddr & 0x00000fff); // 文件在第一个页框中占的字节大小
  uint32_t occupy_pages = 0;          // 该段占用页框数

  if (filesz > size_in_first_page) { // 一个页框容不下该段
    uint32_t left_size = filesz - size_in_first_page;
    occupy_pages = DIV_ROUND_UP(left_size, PG_SIZE) + 1;
  } else {
    occupy_pages = 1;
  }

  // 为进程分配内存
  uint32_t page_idx = 0;
  uint32_t vaddr_page = vaddr_first_page;
  while (page_idx < occupy_pages) {
    uint32_t *pde = pde_ptr(vaddr_page);
    uint32_t *pte = pte_ptr(vaddr_page);

    /* pde不存在或pte不存在就分配内存
     * （pde的判断要在pte之前，否则pde若不存在会导致判断pte时缺页异常 */
    if (!(*pde & 0x00000001) || !(*pte & 0x00000001)) {
      if (get_a_page(PF_USER, vaddr_page) == NULL) {
        return false;
      }
    }
    // 原进程页表已分配-> 用现有物理页直接覆盖进程体
    vaddr_page += PG_SIZE;
    page_idx++;
  }
  sys_lseek(fd, offset, SEEK_SET); // 将文件指针定位到段在文件中的偏移地址
  sys_read(fd, (void *)vaddr, filesz); // 将该段读入到虚拟地址vaddr处
  return true;
}

void debug() {}
// 从文件系统上加载用户程序pathname (成功返回程序起始地址，否则返-1
static int32_t load(const char *pathname) {
  int32_t ret = -1;
  struct Elf32_Ehdr elf_header;
  struct Elf32_Phdr prog_header;
  memset(&elf_header, 0, sizeof(struct Elf32_Ehdr));
  int32_t fd = sys_open(pathname, O_RDONLY);
  if (fd == -1) {
    return -1;
  }
  if (sys_read(fd, &elf_header, sizeof(struct Elf32_Ehdr)) !=
      sizeof(struct Elf32_Ehdr)) {
    ret = -1;
    goto done;
  }

  // 校验elf头,判断格式是否为elf
  if (memcmp(elf_header.e_ident, "\177ELF\1\1\1", 7) ||
      elf_header.e_type != 2 || elf_header.e_machine != 3 ||
      elf_header.e_version != 1 || elf_header.e_phnum > 1024 ||
      elf_header.e_phentsize != sizeof(struct Elf32_Phdr)) {
    ret = -1;
    goto done;
  }

  Elf32_Off prog_header_offset = elf_header.e_phoff; // 程序头的起始地址
  Elf32_Half prog_header_size = elf_header.e_phentsize; // 程序头条目

  // 遍历所有程序头
  uint32_t prog_idx = 0;
  while (prog_idx < elf_header.e_phnum) {
    debug();
    memset(&prog_header, 0, prog_header_size);
    sys_lseek(fd, prog_header_offset, SEEK_SET); // 将文件指针定位到程序头
    /* 只获取程序头 */
    if (sys_read(fd, &prog_header, prog_header_size) != prog_header_size) {
      ret = -1;
      goto done;
    }

    if (PT_LOAD ==
        prog_header.p_type) { // 如果是可加载段就调segment_load加载到内存
      if (!segment_load(fd, prog_header.p_offset, prog_header.p_filesz,
                        prog_header.p_vaddr)) {
        ret = -1;
        goto done;
      }
    }
    // 更新下个程序头的偏移
    prog_header_offset += elf_header.e_phentsize;
    prog_idx++;
  }
  ret = elf_header.e_entry;

done:
  sys_close(fd);
  return ret;
}

// 用path指向的程序替换当前进程
int32_t sys_execv(const char *path, const char *argv[]) {
  uint32_t argc = 0;
  while (argv[argc]) {
    argc++; // 统计参数个数
  }

  struct task_struct *cur = running_thread();
  for (int i = 0; i < DESC_CNT; i++) {
    list_init(&(cur->u_block_desc[i].free_list));
  }

  int32_t entry_point = load(path); // 加载文件path
  if (entry_point == -1) {
    return -1;
  }

  memcpy(cur->name, path, TASK_NAME_LEN); // 修改进程名
  cur->name[TASK_NAME_LEN - 1] = 0;
  struct intr_stack *intr_0_stack = // 获得内核栈的地址(老进程的)
      (struct intr_stack *)((uint32_t)cur + PG_SIZE -
                            sizeof(struct intr_stack));
  // 修改栈中数据为新进程
  intr_0_stack->ebx = (int32_t)argv;
  intr_0_stack->ecx = argc;
  intr_0_stack->eip = (void *)entry_point; // 可执行文件的入口地址
  intr_0_stack->esp =
      (void *)0xc0000000; // 将内核栈中的用户栈指针esp恢复为新开始

  /* exec不同于fork，为使新进程更快被执行，直接假装从中断返回 */

  asm volatile("movl %0, %%esp; jmp intr_exit"
               :
               : "g"(intr_0_stack)
               : "memory");
  return 0;
}