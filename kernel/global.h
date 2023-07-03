#ifndef KERNEL_GLOBAL
#define KERNEL_GLOBAL
#include "stdint.h"

#define NULL 0

typedef enum { false, true } bool;

#define UNUSED __attribute__((unused))

/*------------------GDT描述符属性------------------*/
#define DESC_G_4K 1
#define DESC_D_32 1
#define DESC_L 0
#define DESC_AVL 0
#define DESC_P 1
#define DESC_DPL_0 0
#define DESC_DPL_1 1
#define DESC_DPL_2 2
#define DESC_DPL_3 3
/****************************************************************
s=1表示存储段(代码段和数据段)，s=0表示系统段(tss和各种门描述符)
****************************************************************/
#define DESC_S_CODE 1
#define DESC_S_DATA DESC_S_CODE
#define DESC_S_SYS 0
#define DESC_TYPE_CODE 8 // x1,c0,r0,a0代码段可执行/非依从/不可读/已访问位a清0
#define DESC_TYPE_DATA 2 // x0,e0,w1,a0数据段不可执行/向上扩展/可写/已访问位a清0
#define DESC_TYPE_TSS 9 // B位为0，不忙

#define RPL0 0
#define RPL1 1
#define RPL2 2
#define RPL3 3

#define TI_GDT 0
#define TI_LDT 1

// 第0个段描述符不可用
#define SELECTOR_K_CODE ((1 << 3) + (TI_GDT << 2) + RPL0) // 1：内核代码段
#define SELECTOR_K_DATA ((2 << 3) + (TI_GDT << 2) + RPL0) // 2：内核数据段+栈
#define SELECTOR_K_STACK SELECTOR_K_DATA
#define SELECTOR_K_GS ((3 << 3) + (TI_GDT << 2) + RPL0)   // 3：显存
#define SELECTOR_TSS ((4 << 3) + (TI_GDT << 2) + RPL0)    // 4：TSS
#define SELECTOR_U_CODE ((5 << 3) + (TI_GDT << 2) + RPL3) // 5：用户代码段
#define SELECTOR_U_DATA ((6 << 3) + (TI_GDT << 2) + RPL3) // 6：用户数据段+栈
#define SELECTOR_U_STACK SELECTOR_U_DATA

#define GDT_ATTR_HIGH                                                          \
  ((DESC_G_4K << 7) + (DESC_D_32 << 6) + (DESC_L << 5) + (DESC_AVL << 4))
#define GDT_CODE_ATTR_LOW_DPL3                                                 \
  ((DESC_P << 7) + (DESC_DPL_3 << 5) + (DESC_S_CODE << 4) + DESC_TYPE_CODE)
#define GDT_DATA_ATTR_LOW_DPL3                                                 \
  ((DESC_P << 7) + (DESC_DPL_3 << 5) + (DESC_S_DATA << 4) + DESC_TYPE_DATA)

/*------------------TSS描述符属性------------------*/
#define TSS_DESC_D 0
#define TSS_ATTR_HIGH                                                          \
  ((DESC_G_4K << 7) + (TSS_DESC_D << 6) + (DESC_L << 5) + (DESC_AVL << 4) + 0x0)
#define TSS_ATTR_LOW                                                           \
  ((DESC_P << 7) + (DESC_DPL_0 << 5) + (DESC_S_SYS << 4) + DESC_TYPE_TSS)

// 定义GDT中描述符的结构
struct gdt_desc {
  uint16_t limit_low_word;
  uint16_t base_low_word;
  uint8_t base_mid_byte;
  uint8_t attr_low_byte;
  uint8_t limit_high_attr_high;
  uint8_t base_high_byte;
};

/*------------------IDT描述符属性------------------*/
#define IDT_DESC_P 1
#define IDT_DESC_DPL0 0
#define IDT_DESC_DPL3 3
#define IDT_DESC_32_TYPE 0xE // 32位的门
#define IDT_DESC_16_TYPE 0x6 // 16位的门（不会用到，定义是为了和32位区分）

#define IDT_DESC_ATTR_DPL0                                                     \
  ((IDT_DESC_P << 7) + (IDT_DESC_DPL0 << 5) + IDT_DESC_32_TYPE)
#define IDT_DESC_ATTR_DPL3                                                     \
  ((IDT_DESC_P << 7) + (IDT_DESC_DPL3 << 5) + IDT_DESC_32_TYPE)

/*------------------ eflags属性 ------------------*/
#define EFLAGS_MBS (1 << 1)  // 此项必须要设置
#define EFLAGS_IF_1 (1 << 9) // if=1，开中断
#define EFLAGS_IF_0 0        // if=0，关中断
#define EFLAGS_IOPL_3 (3 << 12) // IOPL3，用于测试用户程序在非系统调用下进行IO
#define EFLAGS_IOPL_0 (0 << 12) // IOPL0
// #define NULL ((void *)0)
#define DIV_ROUND_UP(X, STEP) ((X + STEP - 1) / (STEP)) // 除法的向上取整
#define bool int

#define PG_SIZE 4096

#endif /* KERNEL_GLOBAL */
