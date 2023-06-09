/*
 创建中断描述符表IDT
 把中断处理程序安装到IDT中
*/
#include "interrupt.h"
#include "global.h"
#include "io.h"
#include "print.h"
#include "stdint.h"
#define IDT_DESC_CNT 0x81 // 目前总共支持的中断数:0-0x80
#define PIC_M_CTRL 0x20   // 主片控制端口
#define PIC_M_DATA 0x21   // 主片数据端口
#define PIC_S_CTRL 0xa0   // 从片...
#define PIC_S_DATA 0xa1
#define EFLAGS_IF 0x00000200 // eflags寄存器中if位为1（中断开）
#define GET_EFLAGS(EFLAG_VAR)                                                  \
  asm volatile(                                                                \
      "pushfl; popl %0"                                                        \
      : "=g"(                                                                  \
          EFLAG_VAR)) // 获取eflags寄存器的值，C变量EFLAG_VAR获得eflags中的值

extern uint32_t syscall_handler(void);

//中断门描述符
struct gate_desc {
  uint16_t func_offset_low_word;
  uint16_t selector;
  uint8_t dcount; // 双字计数字段，门描述符中的第4字节（此项固定不考虑）
  uint8_t attribute; // 属性
  uint16_t func_offset_high_word;
};

// 静态全局
static void make_idt_desc(struct gate_desc *p_gdesc, uint8_t attr,
                          intr_handler function);
static struct gate_desc idt[IDT_DESC_CNT]; // IDT本质-> 中断门描述符数组
char *intr_name[IDT_DESC_CNT];             // 中断异常名数组
extern intr_handler intr_entry_table[IDT_DESC_CNT]; // 中断入口数组(asm)
intr_handler idt_table[IDT_DESC_CNT]; // 最终中断处理程序数组(c)

// 初始化8259A
static void pic_init() {
  // 初始化主片
  outb(PIC_M_CTRL, 0x11); // ICW1: 边沿触发,级联8259, 需要ICW4
  outb(PIC_M_DATA, 0x20); // ICW2: 起始中断向量号0x20,也就是IR[0-7]为0x20～0x27
  outb(PIC_M_DATA, 0x04); // ICW3: IR2接从片
  outb(PIC_M_DATA, 0x01); // ICW4: 8086模式正常EOI

  // 初始化从片
  outb(PIC_S_CTRL, 0x11);
  outb(PIC_S_DATA, 0x28); // ICW2: 起始中断向量号0x28,也就是IR[8-15]为0x28～0x2F
  outb(PIC_S_DATA, 0x02); // ICW3: 设置从片连接到主片的IR2引脚
  outb(PIC_S_DATA, 0x01);

  outb(PIC_M_DATA, 0xf8); // 主片 打开IRQ0时钟中断、IRQ1键盘中断和级联从片的IRQ2
  outb(PIC_S_DATA, 0xbf); // 从片 打开IRQ14接收硬盘控制器中断

  put_str("   pic_init done\n");
}

// 创建中断门描述符
static void make_idt_desc(struct gate_desc *p_gdesc, uint8_t attr,
                          intr_handler function) {
  p_gdesc->func_offset_low_word = (uint32_t)function & 0x0000FFFF;
  p_gdesc->selector = SELECTOR_K_CODE;
  p_gdesc->dcount = 0;
  p_gdesc->attribute = attr;
  p_gdesc->func_offset_high_word = ((uint32_t)function & 0xFFFF0000) >> 16;
}

// 初始化填充IDT
static void idt_desc_init(void) {
  int i;
  int lastindex = IDT_DESC_CNT - 1;
  for (i = 0; i < IDT_DESC_CNT; i++) {
    make_idt_desc(&idt[i], IDT_DESC_ATTR_DPL0, intr_entry_table[i]);
  }
  /* 系统调用单独处理，对应中断门dpl为3，中断处理程序为syscall_handler */
  make_idt_desc(&idt[lastindex], IDT_DESC_ATTR_DPL3, syscall_handler);
  put_str("   idt_desc_init done\n");
}

// 通用中断处理函数（异常处理）
static void general_intr_handler(uint8_t vec_nr) {
  // 伪中断无需处理，0x2f是从片8259A上最后一个IRQ引脚，作保留项
  if (vec_nr == 0x27 || vec_nr == 0x2f) {
    return;
  }
  set_cursor(0); // 光标置0
  int cursor_pos = 0;
  while (cursor_pos < 320) { // 4行空格
    put_char(' ');
    cursor_pos++;
  }

  set_cursor(0);
  put_str("!!!       excetion messge begin          !!!\n");
  set_cursor(88); // 第2行第8个地方开始打印
  put_str(intr_name[vec_nr]);
  if (vec_nr == 14) { // pagefault缺页异常，将缺失地址打印出来并悬停
    int page_fault_vaddr = 0;
    asm("movl %%cr2, %0" : "=r"(page_fault_vaddr)); // cr2存放造成pagefault地址

    put_str("\npage fault addr is ");
    put_int(page_fault_vaddr);
  }

  put_str("\n!!!       excetion messge end          !!!\n");
  while (1)
    ; // 到这不再会被中断
}

// 完成一般中断处理函数的注册、异常名的注册
static void exception_init(void) {
  int i;
  // idt_table中的函数在进入中断后根据中断向量号调用
  for (i = 0; i < IDT_DESC_CNT; i++) {
    idt_table[i] = general_intr_handler; // 默认，以后注册具体处理函数
    intr_name[i] = "unknown";
  }

  // 20个异常（0x00-0x13）
  intr_name[0] = "#DE Divide Error";
  intr_name[1] = "#DB Debug Exception";
  intr_name[2] = "NMI Interrupt";
  intr_name[3] = "#BP Breakpoint Exception";
  intr_name[4] = "#OF Overflow Exception";
  intr_name[5] = "#BR BOUND Range Exceeded Exception";
  intr_name[6] = "#UD Invalid Opcode Exception";
  intr_name[7] = "#NM Device Not Available Exception";
  intr_name[8] = "#DF Double Fault Exception";
  intr_name[9] = "Coprocessor Segment Overrun";
  intr_name[10] = "#TS Invalid TSS Exception";
  intr_name[11] = "#NP Segment Not Present";
  intr_name[12] = "#SS Stack Fault Exception";
  intr_name[13] = "#GP General Protection Exception";
  intr_name[14] = "#PF Page-Fault Exception";
  // intr_name[15] 第15项是intel保留项，未使用
  intr_name[16] = "#MF x87 FPU Floating-Point Error";
  intr_name[17] = "#AC Alignment Check Exception";
  intr_name[18] = "#MC Machine-Check Exception";
  intr_name[19] = "#XF SIMD Floating-Point Exception";
}

// 开中断，并返回开中断前的状态
enum intr_status intr_enable() {
  enum intr_status old_status;
  if (INTR_ON == intr_get_status()) {
    old_status = INTR_ON;
    return old_status;
  } else {
    old_status = INTR_OFF;
    asm volatile("sti"); // 开中断，sti指令将IF位置1
    return old_status;
  }
}

// 关中断，并返回关中断前的状态
enum intr_status intr_disable() {
  enum intr_status old_status;
  if (INTR_ON == intr_get_status()) {
    old_status = INTR_ON;
    asm volatile("cli" ::: "memory"); // 关中断，cli指令将IF位置0
    return old_status;
  } else {
    old_status = INTR_OFF;
    return old_status;
  }
}

// 注册中断处理函数
void register_handler(uint8_t vector_no, intr_handler func) {
  idt_table[vector_no] = func;
}

// 将中断状态设置为status
enum intr_status intr_set_status(enum intr_status status) {
  return status & INTR_ON ? intr_enable() : intr_disable();
}

// 获取当前中断状态
enum intr_status intr_get_status() {
  uint32_t eflags = 0;
  GET_EFLAGS(eflags);
  return (EFLAGS_IF & eflags) ? INTR_ON : INTR_OFF; // 判断eflags中的IF位
}

// 完成有关中断的所有初始化工作
void idt_init() {
  put_str("idt_init start\n");
  idt_desc_init();  // 初始化IDT
  exception_init(); // 异常名初始化并注册通常的中断处理函数
  pic_init();       // 初始化8259A

  // 加载IDT
  uint64_t idt_operand =
      ((sizeof(idt) - 1) | (((uint64_t)(uint32_t)idt << 16)));
  asm volatile("lidt %0" ::"m"(idt_operand));
  put_str("idt_init done\n");
}