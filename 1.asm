
kernel.bin：     文件格式 elf32-i386


Disassembly of section .text:

c0001500 <main>:
// void u_prog_a(void);
// void u_prog_b(void);
// int prog_a_pid = 0;
// int prog_b_pid = 0;

int main(void) {
c0001500:	8d 4c 24 04          	lea    0x4(%esp),%ecx
c0001504:	83 e4 f0             	and    $0xfffffff0,%esp
c0001507:	ff 71 fc             	push   -0x4(%ecx)
c000150a:	55                   	push   %ebp
c000150b:	89 e5                	mov    %esp,%ebp
c000150d:	51                   	push   %ecx
c000150e:	83 ec 04             	sub    $0x4,%esp
  put_str("I am kernel\n");
c0001511:	83 ec 0c             	sub    $0xc,%esp
c0001514:	68 00 c0 00 c0       	push   $0xc000c000
c0001519:	e8 12 05 00 00       	call   c0001a30 <put_str>
c000151e:	83 c4 10             	add    $0x10,%esp
  init_all();
c0001521:	e8 4f 00 00 00       	call   c0001575 <init_all>
  cls_screen();
c0001526:	e8 c3 05 00 00       	call   c0001aee <cls_screen>
  console_put_str("[yers@localhost /]$ ");
c000152b:	83 ec 0c             	sub    $0xc,%esp
c000152e:	68 0d c0 00 c0       	push   $0xc000c00d
c0001533:	e8 39 32 00 00       	call   c0004771 <console_put_str>
c0001538:	83 c4 10             	add    $0x10,%esp
  while (1) {
c000153b:	eb fe                	jmp    c000153b <main+0x3b>

c000153d <init>:
  };
  return 0;
}

void init(void) {
c000153d:	55                   	push   %ebp
c000153e:	89 e5                	mov    %esp,%ebp
c0001540:	83 ec 18             	sub    $0x18,%esp
  uint32_t ret_pid = fork();
c0001543:	e8 c4 3d 00 00       	call   c000530c <fork>
c0001548:	98                   	cwtl   
c0001549:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (ret_pid) {
c000154c:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
c0001550:	74 02                	je     c0001554 <init+0x17>
    while (1) {
c0001552:	eb fe                	jmp    c0001552 <init+0x15>
    }
  } else {
    my_shell();
c0001554:	e8 8c 9c 00 00       	call   c000b1e5 <my_shell>
  }
  PANIC("init: should not be here");
c0001559:	68 22 c0 00 c0       	push   $0xc000c022
c000155e:	68 4c c0 00 c0       	push   $0xc000c04c
c0001563:	6a 2c                	push   $0x2c
c0001565:	68 3b c0 00 c0       	push   $0xc000c03b
c000156a:	e8 69 0d 00 00       	call   c00022d8 <panic_spin>
c000156f:	83 c4 10             	add    $0x10,%esp
}
c0001572:	90                   	nop
c0001573:	c9                   	leave  
c0001574:	c3                   	ret    

c0001575 <init_all>:
#include "thread.h"
#include "timer.h"
#include "tss.h"

// 负责初始化所有模块
void init_all() {
c0001575:	55                   	push   %ebp
c0001576:	89 e5                	mov    %esp,%ebp
c0001578:	83 ec 08             	sub    $0x8,%esp
  put_str("init_all\n");
c000157b:	83 ec 0c             	sub    $0xc,%esp
c000157e:	68 51 c0 00 c0       	push   $0xc000c051
c0001583:	e8 a8 04 00 00       	call   c0001a30 <put_str>
c0001588:	83 c4 10             	add    $0x10,%esp
  idt_init();      // 初始化中断
c000158b:	e8 2e 04 00 00       	call   c00019be <idt_init>
  timer_init();    // 初始化PIT
c0001590:	e8 7f 0c 00 00       	call   c0002214 <timer_init>
  mem_init();      // 初始化内存池
c0001595:	e8 24 25 00 00       	call   c0003abe <mem_init>
  thread_init();   // 初始化线程环境
c000159a:	e8 d9 2b 00 00       	call   c0004178 <thread_init>
  console_init();  // 初始化终端
c000159f:	e8 82 31 00 00       	call   c0004726 <console_init>
  keyboard_init(); // 初始化键盘
c00015a4:	e8 ef 34 00 00       	call   c0004a98 <keyboard_init>
  tss_init();      // 初始化任务状态表
c00015a9:	e8 90 38 00 00       	call   c0004e3e <tss_init>
  syscall_init();  // 初始化系统调用
c00015ae:	e8 d8 3d 00 00       	call   c000538b <syscall_init>
  ide_init();      // 初始化硬盘驱动
c00015b3:	e8 dd 4c 00 00       	call   c0006295 <ide_init>
  filesys_init();  // 初始化文件系统
c00015b8:	e8 0c 6d 00 00       	call   c00082c9 <filesys_init>
c00015bd:	90                   	nop
c00015be:	c9                   	leave  
c00015bf:	c3                   	ret    

c00015c0 <outb>:
#ifndef __LIB_IO_H
#define __LIB_IO_H
#include "stdint.h"

// 向端口写入1字节
static inline void outb(uint16_t port, uint8_t data) {
c00015c0:	55                   	push   %ebp
c00015c1:	89 e5                	mov    %esp,%ebp
c00015c3:	83 ec 08             	sub    $0x8,%esp
c00015c6:	8b 45 08             	mov    0x8(%ebp),%eax
c00015c9:	8b 55 0c             	mov    0xc(%ebp),%edx
c00015cc:	66 89 45 fc          	mov    %ax,-0x4(%ebp)
c00015d0:	89 d0                	mov    %edx,%eax
c00015d2:	88 45 f8             	mov    %al,-0x8(%ebp)
  asm volatile("outb %b0, %w1" ::"a"(data), "Nd"(port));
c00015d5:	0f b6 45 f8          	movzbl -0x8(%ebp),%eax
c00015d9:	0f b7 55 fc          	movzwl -0x4(%ebp),%edx
c00015dd:	ee                   	out    %al,(%dx)
}
c00015de:	90                   	nop
c00015df:	c9                   	leave  
c00015e0:	c3                   	ret    

c00015e1 <pic_init>:
char *intr_name[IDT_DESC_CNT];             // 中断异常名数组
extern intr_handler intr_entry_table[IDT_DESC_CNT]; // 中断入口数组(asm)
intr_handler idt_table[IDT_DESC_CNT]; // 最终中断处理程序数组(c)

// 初始化8259A
static void pic_init() {
c00015e1:	55                   	push   %ebp
c00015e2:	89 e5                	mov    %esp,%ebp
c00015e4:	83 ec 08             	sub    $0x8,%esp
  // 初始化主片
  outb(PIC_M_CTRL, 0x11); // ICW1: 边沿触发,级联8259, 需要ICW4
c00015e7:	6a 11                	push   $0x11
c00015e9:	6a 20                	push   $0x20
c00015eb:	e8 d0 ff ff ff       	call   c00015c0 <outb>
c00015f0:	83 c4 08             	add    $0x8,%esp
  outb(PIC_M_DATA, 0x20); // ICW2: 起始中断向量号0x20,也就是IR[0-7]为0x20～0x27
c00015f3:	6a 20                	push   $0x20
c00015f5:	6a 21                	push   $0x21
c00015f7:	e8 c4 ff ff ff       	call   c00015c0 <outb>
c00015fc:	83 c4 08             	add    $0x8,%esp
  outb(PIC_M_DATA, 0x04); // ICW3: IR2接从片
c00015ff:	6a 04                	push   $0x4
c0001601:	6a 21                	push   $0x21
c0001603:	e8 b8 ff ff ff       	call   c00015c0 <outb>
c0001608:	83 c4 08             	add    $0x8,%esp
  outb(PIC_M_DATA, 0x01); // ICW4: 8086模式正常EOI
c000160b:	6a 01                	push   $0x1
c000160d:	6a 21                	push   $0x21
c000160f:	e8 ac ff ff ff       	call   c00015c0 <outb>
c0001614:	83 c4 08             	add    $0x8,%esp

  // 初始化从片
  outb(PIC_S_CTRL, 0x11);
c0001617:	6a 11                	push   $0x11
c0001619:	68 a0 00 00 00       	push   $0xa0
c000161e:	e8 9d ff ff ff       	call   c00015c0 <outb>
c0001623:	83 c4 08             	add    $0x8,%esp
  outb(PIC_S_DATA, 0x28); // ICW2: 起始中断向量号0x28,也就是IR[8-15]为0x28～0x2F
c0001626:	6a 28                	push   $0x28
c0001628:	68 a1 00 00 00       	push   $0xa1
c000162d:	e8 8e ff ff ff       	call   c00015c0 <outb>
c0001632:	83 c4 08             	add    $0x8,%esp
  outb(PIC_S_DATA, 0x02); // ICW3: 设置从片连接到主片的IR2引脚
c0001635:	6a 02                	push   $0x2
c0001637:	68 a1 00 00 00       	push   $0xa1
c000163c:	e8 7f ff ff ff       	call   c00015c0 <outb>
c0001641:	83 c4 08             	add    $0x8,%esp
  outb(PIC_S_DATA, 0x01);
c0001644:	6a 01                	push   $0x1
c0001646:	68 a1 00 00 00       	push   $0xa1
c000164b:	e8 70 ff ff ff       	call   c00015c0 <outb>
c0001650:	83 c4 08             	add    $0x8,%esp

  outb(PIC_M_DATA, 0xf8); // 主片 打开IRQ0时钟中断、IRQ1键盘中断和级联从片的IRQ2
c0001653:	68 f8 00 00 00       	push   $0xf8
c0001658:	6a 21                	push   $0x21
c000165a:	e8 61 ff ff ff       	call   c00015c0 <outb>
c000165f:	83 c4 08             	add    $0x8,%esp
  outb(PIC_S_DATA, 0xbf); // 从片 打开IRQ14接收硬盘控制器中断
c0001662:	68 bf 00 00 00       	push   $0xbf
c0001667:	68 a1 00 00 00       	push   $0xa1
c000166c:	e8 4f ff ff ff       	call   c00015c0 <outb>
c0001671:	83 c4 08             	add    $0x8,%esp

  put_str("   pic_init done\n");
c0001674:	83 ec 0c             	sub    $0xc,%esp
c0001677:	68 5c c0 00 c0       	push   $0xc000c05c
c000167c:	e8 af 03 00 00       	call   c0001a30 <put_str>
c0001681:	83 c4 10             	add    $0x10,%esp
}
c0001684:	90                   	nop
c0001685:	c9                   	leave  
c0001686:	c3                   	ret    

c0001687 <make_idt_desc>:

// 创建中断门描述符
static void make_idt_desc(struct gate_desc *p_gdesc, uint8_t attr,
                          intr_handler function) {
c0001687:	55                   	push   %ebp
c0001688:	89 e5                	mov    %esp,%ebp
c000168a:	83 ec 04             	sub    $0x4,%esp
c000168d:	8b 45 0c             	mov    0xc(%ebp),%eax
c0001690:	88 45 fc             	mov    %al,-0x4(%ebp)
  p_gdesc->func_offset_low_word = (uint32_t)function & 0x0000FFFF;
c0001693:	8b 45 10             	mov    0x10(%ebp),%eax
c0001696:	89 c2                	mov    %eax,%edx
c0001698:	8b 45 08             	mov    0x8(%ebp),%eax
c000169b:	66 89 10             	mov    %dx,(%eax)
  p_gdesc->selector = SELECTOR_K_CODE;
c000169e:	8b 45 08             	mov    0x8(%ebp),%eax
c00016a1:	66 c7 40 02 08 00    	movw   $0x8,0x2(%eax)
  p_gdesc->dcount = 0;
c00016a7:	8b 45 08             	mov    0x8(%ebp),%eax
c00016aa:	c6 40 04 00          	movb   $0x0,0x4(%eax)
  p_gdesc->attribute = attr;
c00016ae:	8b 45 08             	mov    0x8(%ebp),%eax
c00016b1:	0f b6 55 fc          	movzbl -0x4(%ebp),%edx
c00016b5:	88 50 05             	mov    %dl,0x5(%eax)
  p_gdesc->func_offset_high_word = ((uint32_t)function & 0xFFFF0000) >> 16;
c00016b8:	8b 45 10             	mov    0x10(%ebp),%eax
c00016bb:	c1 e8 10             	shr    $0x10,%eax
c00016be:	89 c2                	mov    %eax,%edx
c00016c0:	8b 45 08             	mov    0x8(%ebp),%eax
c00016c3:	66 89 50 06          	mov    %dx,0x6(%eax)
}
c00016c7:	90                   	nop
c00016c8:	c9                   	leave  
c00016c9:	c3                   	ret    

c00016ca <idt_desc_init>:

// 初始化填充IDT
static void idt_desc_init(void) {
c00016ca:	55                   	push   %ebp
c00016cb:	89 e5                	mov    %esp,%ebp
c00016cd:	83 ec 18             	sub    $0x18,%esp
  int i;
  int lastindex = IDT_DESC_CNT - 1;
c00016d0:	c7 45 f0 80 00 00 00 	movl   $0x80,-0x10(%ebp)
  for (i = 0; i < IDT_DESC_CNT; i++) {
c00016d7:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
c00016de:	eb 29                	jmp    c0001709 <idt_desc_init+0x3f>
    make_idt_desc(&idt[i], IDT_DESC_ATTR_DPL0, intr_entry_table[i]);
c00016e0:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00016e3:	8b 04 85 08 10 01 c0 	mov    -0x3ffeeff8(,%eax,4),%eax
c00016ea:	8b 55 f4             	mov    -0xc(%ebp),%edx
c00016ed:	c1 e2 03             	shl    $0x3,%edx
c00016f0:	81 c2 a0 15 01 c0    	add    $0xc00115a0,%edx
c00016f6:	50                   	push   %eax
c00016f7:	68 8e 00 00 00       	push   $0x8e
c00016fc:	52                   	push   %edx
c00016fd:	e8 85 ff ff ff       	call   c0001687 <make_idt_desc>
c0001702:	83 c4 0c             	add    $0xc,%esp
  for (i = 0; i < IDT_DESC_CNT; i++) {
c0001705:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
c0001709:	81 7d f4 80 00 00 00 	cmpl   $0x80,-0xc(%ebp)
c0001710:	7e ce                	jle    c00016e0 <idt_desc_init+0x16>
  }
  /* 系统调用单独处理，对应中断门dpl为3，中断处理程序为syscall_handler */
  make_idt_desc(&idt[lastindex], IDT_DESC_ATTR_DPL3, syscall_handler);
c0001712:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0001715:	c1 e0 03             	shl    $0x3,%eax
c0001718:	05 a0 15 01 c0       	add    $0xc00115a0,%eax
c000171d:	68 ca 20 00 c0       	push   $0xc00020ca
c0001722:	68 ee 00 00 00       	push   $0xee
c0001727:	50                   	push   %eax
c0001728:	e8 5a ff ff ff       	call   c0001687 <make_idt_desc>
c000172d:	83 c4 0c             	add    $0xc,%esp
  put_str("   idt_desc_init done\n");
c0001730:	83 ec 0c             	sub    $0xc,%esp
c0001733:	68 6e c0 00 c0       	push   $0xc000c06e
c0001738:	e8 f3 02 00 00       	call   c0001a30 <put_str>
c000173d:	83 c4 10             	add    $0x10,%esp
}
c0001740:	90                   	nop
c0001741:	c9                   	leave  
c0001742:	c3                   	ret    

c0001743 <general_intr_handler>:

// 通用中断处理函数（异常处理）
static void general_intr_handler(uint8_t vec_nr) {
c0001743:	55                   	push   %ebp
c0001744:	89 e5                	mov    %esp,%ebp
c0001746:	83 ec 28             	sub    $0x28,%esp
c0001749:	8b 45 08             	mov    0x8(%ebp),%eax
c000174c:	88 45 e4             	mov    %al,-0x1c(%ebp)
  // 伪中断无需处理，0x2f是从片8259A上最后一个IRQ引脚，作保留项
  if (vec_nr == 0x27 || vec_nr == 0x2f) {
c000174f:	80 7d e4 27          	cmpb   $0x27,-0x1c(%ebp)
c0001753:	0f 84 bf 00 00 00    	je     c0001818 <general_intr_handler+0xd5>
c0001759:	80 7d e4 2f          	cmpb   $0x2f,-0x1c(%ebp)
c000175d:	0f 84 b5 00 00 00    	je     c0001818 <general_intr_handler+0xd5>
    return;
  }
  set_cursor(0); // 光标置0
c0001763:	83 ec 0c             	sub    $0xc,%esp
c0001766:	6a 00                	push   $0x0
c0001768:	e8 a2 03 00 00       	call   c0001b0f <set_cursor>
c000176d:	83 c4 10             	add    $0x10,%esp
  int cursor_pos = 0;
c0001770:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  while (cursor_pos < 320) { // 4行空格
c0001777:	eb 11                	jmp    c000178a <general_intr_handler+0x47>
    put_char(' ');
c0001779:	83 ec 0c             	sub    $0xc,%esp
c000177c:	6a 20                	push   $0x20
c000177e:	e8 cb 02 00 00       	call   c0001a4e <put_char>
c0001783:	83 c4 10             	add    $0x10,%esp
    cursor_pos++;
c0001786:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
  while (cursor_pos < 320) { // 4行空格
c000178a:	81 7d f4 3f 01 00 00 	cmpl   $0x13f,-0xc(%ebp)
c0001791:	7e e6                	jle    c0001779 <general_intr_handler+0x36>
  }

  set_cursor(0);
c0001793:	83 ec 0c             	sub    $0xc,%esp
c0001796:	6a 00                	push   $0x0
c0001798:	e8 72 03 00 00       	call   c0001b0f <set_cursor>
c000179d:	83 c4 10             	add    $0x10,%esp
  put_str("!!!       excetion messge begin          !!!\n");
c00017a0:	83 ec 0c             	sub    $0xc,%esp
c00017a3:	68 88 c0 00 c0       	push   $0xc000c088
c00017a8:	e8 83 02 00 00       	call   c0001a30 <put_str>
c00017ad:	83 c4 10             	add    $0x10,%esp
  set_cursor(88); // 第2行第8个地方开始打印
c00017b0:	83 ec 0c             	sub    $0xc,%esp
c00017b3:	6a 58                	push   $0x58
c00017b5:	e8 55 03 00 00       	call   c0001b0f <set_cursor>
c00017ba:	83 c4 10             	add    $0x10,%esp
  put_str(intr_name[vec_nr]);
c00017bd:	0f b6 45 e4          	movzbl -0x1c(%ebp),%eax
c00017c1:	8b 04 85 60 11 01 c0 	mov    -0x3ffeeea0(,%eax,4),%eax
c00017c8:	83 ec 0c             	sub    $0xc,%esp
c00017cb:	50                   	push   %eax
c00017cc:	e8 5f 02 00 00       	call   c0001a30 <put_str>
c00017d1:	83 c4 10             	add    $0x10,%esp
  if (vec_nr == 14) { // pagefault缺页异常，将缺失地址打印出来并悬停
c00017d4:	80 7d e4 0e          	cmpb   $0xe,-0x1c(%ebp)
c00017d8:	75 2c                	jne    c0001806 <general_intr_handler+0xc3>
    int page_fault_vaddr = 0;
c00017da:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
    asm("movl %%cr2, %0" : "=r"(page_fault_vaddr)); // cr2存放造成pagefault地址
c00017e1:	0f 20 d0             	mov    %cr2,%eax
c00017e4:	89 45 f0             	mov    %eax,-0x10(%ebp)

    put_str("\npage fault addr is ");
c00017e7:	83 ec 0c             	sub    $0xc,%esp
c00017ea:	68 b6 c0 00 c0       	push   $0xc000c0b6
c00017ef:	e8 3c 02 00 00       	call   c0001a30 <put_str>
c00017f4:	83 c4 10             	add    $0x10,%esp
    put_int(page_fault_vaddr);
c00017f7:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00017fa:	83 ec 0c             	sub    $0xc,%esp
c00017fd:	50                   	push   %eax
c00017fe:	e8 2a 03 00 00       	call   c0001b2d <put_int>
c0001803:	83 c4 10             	add    $0x10,%esp
  }

  put_str("\n!!!       excetion messge end          !!!\n");
c0001806:	83 ec 0c             	sub    $0xc,%esp
c0001809:	68 cc c0 00 c0       	push   $0xc000c0cc
c000180e:	e8 1d 02 00 00       	call   c0001a30 <put_str>
c0001813:	83 c4 10             	add    $0x10,%esp
  while (1)
c0001816:	eb fe                	jmp    c0001816 <general_intr_handler+0xd3>
    return;
c0001818:	90                   	nop
    ; // 到这不再会被中断
}
c0001819:	c9                   	leave  
c000181a:	c3                   	ret    

c000181b <exception_init>:

// 完成一般中断处理函数的注册、异常名的注册
static void exception_init(void) {
c000181b:	55                   	push   %ebp
c000181c:	89 e5                	mov    %esp,%ebp
c000181e:	83 ec 10             	sub    $0x10,%esp
  int i;
  // idt_table中的函数在进入中断后根据中断向量号调用
  for (i = 0; i < IDT_DESC_CNT; i++) {
c0001821:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%ebp)
c0001828:	eb 20                	jmp    c000184a <exception_init+0x2f>
    idt_table[i] = general_intr_handler; // 默认，以后注册具体处理函数
c000182a:	8b 45 fc             	mov    -0x4(%ebp),%eax
c000182d:	c7 04 85 80 13 01 c0 	movl   $0xc0001743,-0x3ffeec80(,%eax,4)
c0001834:	43 17 00 c0 
    intr_name[i] = "unknown";
c0001838:	8b 45 fc             	mov    -0x4(%ebp),%eax
c000183b:	c7 04 85 60 11 01 c0 	movl   $0xc000c0f9,-0x3ffeeea0(,%eax,4)
c0001842:	f9 c0 00 c0 
  for (i = 0; i < IDT_DESC_CNT; i++) {
c0001846:	83 45 fc 01          	addl   $0x1,-0x4(%ebp)
c000184a:	81 7d fc 80 00 00 00 	cmpl   $0x80,-0x4(%ebp)
c0001851:	7e d7                	jle    c000182a <exception_init+0xf>
  }

  // 20个异常（0x00-0x13）
  intr_name[0] = "#DE Divide Error";
c0001853:	c7 05 60 11 01 c0 01 	movl   $0xc000c101,0xc0011160
c000185a:	c1 00 c0 
  intr_name[1] = "#DB Debug Exception";
c000185d:	c7 05 64 11 01 c0 12 	movl   $0xc000c112,0xc0011164
c0001864:	c1 00 c0 
  intr_name[2] = "NMI Interrupt";
c0001867:	c7 05 68 11 01 c0 26 	movl   $0xc000c126,0xc0011168
c000186e:	c1 00 c0 
  intr_name[3] = "#BP Breakpoint Exception";
c0001871:	c7 05 6c 11 01 c0 34 	movl   $0xc000c134,0xc001116c
c0001878:	c1 00 c0 
  intr_name[4] = "#OF Overflow Exception";
c000187b:	c7 05 70 11 01 c0 4d 	movl   $0xc000c14d,0xc0011170
c0001882:	c1 00 c0 
  intr_name[5] = "#BR BOUND Range Exceeded Exception";
c0001885:	c7 05 74 11 01 c0 64 	movl   $0xc000c164,0xc0011174
c000188c:	c1 00 c0 
  intr_name[6] = "#UD Invalid Opcode Exception";
c000188f:	c7 05 78 11 01 c0 87 	movl   $0xc000c187,0xc0011178
c0001896:	c1 00 c0 
  intr_name[7] = "#NM Device Not Available Exception";
c0001899:	c7 05 7c 11 01 c0 a4 	movl   $0xc000c1a4,0xc001117c
c00018a0:	c1 00 c0 
  intr_name[8] = "#DF Double Fault Exception";
c00018a3:	c7 05 80 11 01 c0 c7 	movl   $0xc000c1c7,0xc0011180
c00018aa:	c1 00 c0 
  intr_name[9] = "Coprocessor Segment Overrun";
c00018ad:	c7 05 84 11 01 c0 e2 	movl   $0xc000c1e2,0xc0011184
c00018b4:	c1 00 c0 
  intr_name[10] = "#TS Invalid TSS Exception";
c00018b7:	c7 05 88 11 01 c0 fe 	movl   $0xc000c1fe,0xc0011188
c00018be:	c1 00 c0 
  intr_name[11] = "#NP Segment Not Present";
c00018c1:	c7 05 8c 11 01 c0 18 	movl   $0xc000c218,0xc001118c
c00018c8:	c2 00 c0 
  intr_name[12] = "#SS Stack Fault Exception";
c00018cb:	c7 05 90 11 01 c0 30 	movl   $0xc000c230,0xc0011190
c00018d2:	c2 00 c0 
  intr_name[13] = "#GP General Protection Exception";
c00018d5:	c7 05 94 11 01 c0 4c 	movl   $0xc000c24c,0xc0011194
c00018dc:	c2 00 c0 
  intr_name[14] = "#PF Page-Fault Exception";
c00018df:	c7 05 98 11 01 c0 6d 	movl   $0xc000c26d,0xc0011198
c00018e6:	c2 00 c0 
  // intr_name[15] 第15项是intel保留项，未使用
  intr_name[16] = "#MF x87 FPU Floating-Point Error";
c00018e9:	c7 05 a0 11 01 c0 88 	movl   $0xc000c288,0xc00111a0
c00018f0:	c2 00 c0 
  intr_name[17] = "#AC Alignment Check Exception";
c00018f3:	c7 05 a4 11 01 c0 a9 	movl   $0xc000c2a9,0xc00111a4
c00018fa:	c2 00 c0 
  intr_name[18] = "#MC Machine-Check Exception";
c00018fd:	c7 05 a8 11 01 c0 c7 	movl   $0xc000c2c7,0xc00111a8
c0001904:	c2 00 c0 
  intr_name[19] = "#XF SIMD Floating-Point Exception";
c0001907:	c7 05 ac 11 01 c0 e4 	movl   $0xc000c2e4,0xc00111ac
c000190e:	c2 00 c0 
}
c0001911:	90                   	nop
c0001912:	c9                   	leave  
c0001913:	c3                   	ret    

c0001914 <intr_enable>:

// 开中断，并返回开中断前的状态
enum intr_status intr_enable() {
c0001914:	55                   	push   %ebp
c0001915:	89 e5                	mov    %esp,%ebp
c0001917:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status;
  if (INTR_ON == intr_get_status()) {
c000191a:	e8 82 00 00 00       	call   c00019a1 <intr_get_status>
c000191f:	83 f8 01             	cmp    $0x1,%eax
c0001922:	75 0c                	jne    c0001930 <intr_enable+0x1c>
    old_status = INTR_ON;
c0001924:	c7 45 f4 01 00 00 00 	movl   $0x1,-0xc(%ebp)
    return old_status;
c000192b:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000192e:	eb 0b                	jmp    c000193b <intr_enable+0x27>
  } else {
    old_status = INTR_OFF;
c0001930:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
    asm volatile("sti"); // 开中断，sti指令将IF位置1
c0001937:	fb                   	sti    
    return old_status;
c0001938:	8b 45 f4             	mov    -0xc(%ebp),%eax
  }
}
c000193b:	c9                   	leave  
c000193c:	c3                   	ret    

c000193d <intr_disable>:

// 关中断，并返回关中断前的状态
enum intr_status intr_disable() {
c000193d:	55                   	push   %ebp
c000193e:	89 e5                	mov    %esp,%ebp
c0001940:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status;
  if (INTR_ON == intr_get_status()) {
c0001943:	e8 59 00 00 00       	call   c00019a1 <intr_get_status>
c0001948:	83 f8 01             	cmp    $0x1,%eax
c000194b:	75 0d                	jne    c000195a <intr_disable+0x1d>
    old_status = INTR_ON;
c000194d:	c7 45 f4 01 00 00 00 	movl   $0x1,-0xc(%ebp)
    asm volatile("cli" ::: "memory"); // 关中断，cli指令将IF位置0
c0001954:	fa                   	cli    
    return old_status;
c0001955:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0001958:	eb 0a                	jmp    c0001964 <intr_disable+0x27>
  } else {
    old_status = INTR_OFF;
c000195a:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
    return old_status;
c0001961:	8b 45 f4             	mov    -0xc(%ebp),%eax
  }
}
c0001964:	c9                   	leave  
c0001965:	c3                   	ret    

c0001966 <register_handler>:

// 注册中断处理函数
void register_handler(uint8_t vector_no, intr_handler func) {
c0001966:	55                   	push   %ebp
c0001967:	89 e5                	mov    %esp,%ebp
c0001969:	83 ec 04             	sub    $0x4,%esp
c000196c:	8b 45 08             	mov    0x8(%ebp),%eax
c000196f:	88 45 fc             	mov    %al,-0x4(%ebp)
  idt_table[vector_no] = func;
c0001972:	0f b6 45 fc          	movzbl -0x4(%ebp),%eax
c0001976:	8b 55 0c             	mov    0xc(%ebp),%edx
c0001979:	89 14 85 80 13 01 c0 	mov    %edx,-0x3ffeec80(,%eax,4)
}
c0001980:	90                   	nop
c0001981:	c9                   	leave  
c0001982:	c3                   	ret    

c0001983 <intr_set_status>:

// 将中断状态设置为status
enum intr_status intr_set_status(enum intr_status status) {
c0001983:	55                   	push   %ebp
c0001984:	89 e5                	mov    %esp,%ebp
c0001986:	83 ec 08             	sub    $0x8,%esp
  return status & INTR_ON ? intr_enable() : intr_disable();
c0001989:	8b 45 08             	mov    0x8(%ebp),%eax
c000198c:	83 e0 01             	and    $0x1,%eax
c000198f:	85 c0                	test   %eax,%eax
c0001991:	74 07                	je     c000199a <intr_set_status+0x17>
c0001993:	e8 7c ff ff ff       	call   c0001914 <intr_enable>
c0001998:	eb 05                	jmp    c000199f <intr_set_status+0x1c>
c000199a:	e8 9e ff ff ff       	call   c000193d <intr_disable>
}
c000199f:	c9                   	leave  
c00019a0:	c3                   	ret    

c00019a1 <intr_get_status>:

// 获取当前中断状态
enum intr_status intr_get_status() {
c00019a1:	55                   	push   %ebp
c00019a2:	89 e5                	mov    %esp,%ebp
c00019a4:	83 ec 10             	sub    $0x10,%esp
  uint32_t eflags = 0;
c00019a7:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%ebp)
  GET_EFLAGS(eflags);
c00019ae:	9c                   	pushf  
c00019af:	58                   	pop    %eax
c00019b0:	89 45 fc             	mov    %eax,-0x4(%ebp)
  return (EFLAGS_IF & eflags) ? INTR_ON : INTR_OFF; // 判断eflags中的IF位
c00019b3:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00019b6:	c1 e8 09             	shr    $0x9,%eax
c00019b9:	83 e0 01             	and    $0x1,%eax
}
c00019bc:	c9                   	leave  
c00019bd:	c3                   	ret    

c00019be <idt_init>:

// 完成有关中断的所有初始化工作
void idt_init() {
c00019be:	55                   	push   %ebp
c00019bf:	89 e5                	mov    %esp,%ebp
c00019c1:	57                   	push   %edi
c00019c2:	56                   	push   %esi
c00019c3:	83 ec 10             	sub    $0x10,%esp
  put_str("idt_init start\n");
c00019c6:	83 ec 0c             	sub    $0xc,%esp
c00019c9:	68 06 c3 00 c0       	push   $0xc000c306
c00019ce:	e8 5d 00 00 00       	call   c0001a30 <put_str>
c00019d3:	83 c4 10             	add    $0x10,%esp
  idt_desc_init();  // 初始化IDT
c00019d6:	e8 ef fc ff ff       	call   c00016ca <idt_desc_init>
  exception_init(); // 异常名初始化并注册通常的中断处理函数
c00019db:	e8 3b fe ff ff       	call   c000181b <exception_init>
  pic_init();       // 初始化8259A
c00019e0:	e8 fc fb ff ff       	call   c00015e1 <pic_init>

  // 加载IDT
  uint64_t idt_operand =
      ((sizeof(idt) - 1) | (((uint64_t)(uint32_t)idt << 16)));
c00019e5:	b8 a0 15 01 c0       	mov    $0xc00115a0,%eax
c00019ea:	ba 00 00 00 00       	mov    $0x0,%edx
c00019ef:	0f a4 c2 10          	shld   $0x10,%eax,%edx
c00019f3:	c1 e0 10             	shl    $0x10,%eax
c00019f6:	89 c1                	mov    %eax,%ecx
c00019f8:	81 c9 07 04 00 00    	or     $0x407,%ecx
c00019fe:	89 ce                	mov    %ecx,%esi
c0001a00:	89 d0                	mov    %edx,%eax
c0001a02:	80 cc 00             	or     $0x0,%ah
c0001a05:	89 c7                	mov    %eax,%edi
  uint64_t idt_operand =
c0001a07:	89 75 f0             	mov    %esi,-0x10(%ebp)
c0001a0a:	89 7d f4             	mov    %edi,-0xc(%ebp)
  asm volatile("lidt %0" ::"m"(idt_operand));
c0001a0d:	0f 01 5d f0          	lidtl  -0x10(%ebp)
  put_str("idt_init done\n");
c0001a11:	83 ec 0c             	sub    $0xc,%esp
c0001a14:	68 16 c3 00 c0       	push   $0xc000c316
c0001a19:	e8 12 00 00 00       	call   c0001a30 <put_str>
c0001a1e:	83 c4 10             	add    $0x10,%esp
c0001a21:	90                   	nop
c0001a22:	8d 65 f8             	lea    -0x8(%ebp),%esp
c0001a25:	5e                   	pop    %esi
c0001a26:	5f                   	pop    %edi
c0001a27:	5d                   	pop    %ebp
c0001a28:	c3                   	ret    
c0001a29:	66 90                	xchg   %ax,%ax
c0001a2b:	66 90                	xchg   %ax,%ax
c0001a2d:	66 90                	xchg   %ax,%ax
c0001a2f:	90                   	nop

c0001a30 <put_str>:
c0001a30:	53                   	push   %ebx
c0001a31:	51                   	push   %ecx
c0001a32:	31 c9                	xor    %ecx,%ecx
c0001a34:	8b 5c 24 0c          	mov    0xc(%esp),%ebx

c0001a38 <put_str.goon>:
c0001a38:	8a 0b                	mov    (%ebx),%cl
c0001a3a:	80 f9 00             	cmp    $0x0,%cl
c0001a3d:	74 0c                	je     c0001a4b <put_str.str_over>
c0001a3f:	51                   	push   %ecx
c0001a40:	e8 09 00 00 00       	call   c0001a4e <put_char>
c0001a45:	83 c4 04             	add    $0x4,%esp
c0001a48:	43                   	inc    %ebx
c0001a49:	eb ed                	jmp    c0001a38 <put_str.goon>

c0001a4b <put_str.str_over>:
c0001a4b:	59                   	pop    %ecx
c0001a4c:	5b                   	pop    %ebx
c0001a4d:	c3                   	ret    

c0001a4e <put_char>:
c0001a4e:	60                   	pusha  
c0001a4f:	66 b8 18 00          	mov    $0x18,%ax
c0001a53:	8e e8                	mov    %eax,%gs
c0001a55:	66 ba d4 03          	mov    $0x3d4,%dx
c0001a59:	b0 0e                	mov    $0xe,%al
c0001a5b:	ee                   	out    %al,(%dx)
c0001a5c:	66 ba d5 03          	mov    $0x3d5,%dx
c0001a60:	ec                   	in     (%dx),%al
c0001a61:	88 c4                	mov    %al,%ah
c0001a63:	66 ba d4 03          	mov    $0x3d4,%dx
c0001a67:	b0 0f                	mov    $0xf,%al
c0001a69:	ee                   	out    %al,(%dx)
c0001a6a:	66 ba d5 03          	mov    $0x3d5,%dx
c0001a6e:	ec                   	in     (%dx),%al
c0001a6f:	66 89 c3             	mov    %ax,%bx
c0001a72:	8b 4c 24 24          	mov    0x24(%esp),%ecx
c0001a76:	80 f9 0d             	cmp    $0xd,%cl
c0001a79:	74 3c                	je     c0001ab7 <put_char.is_carriage_return>
c0001a7b:	80 f9 0a             	cmp    $0xa,%cl
c0001a7e:	74 37                	je     c0001ab7 <put_char.is_carriage_return>
c0001a80:	80 f9 08             	cmp    $0x8,%cl
c0001a83:	74 02                	je     c0001a87 <put_char.back_space>
c0001a85:	eb 16                	jmp    c0001a9d <put_char.put_other>

c0001a87 <put_char.back_space>:
c0001a87:	66 4b                	dec    %bx
c0001a89:	66 d1 e3             	shl    %bx
c0001a8c:	65 67 c6 07 20       	movb   $0x20,%gs:(%bx)
c0001a91:	66 43                	inc    %bx
c0001a93:	65 67 c6 07 07       	movb   $0x7,%gs:(%bx)
c0001a98:	66 d1 eb             	shr    %bx
c0001a9b:	eb 72                	jmp    c0001b0f <set_cursor>

c0001a9d <put_char.put_other>:
c0001a9d:	66 d1 e3             	shl    %bx
c0001aa0:	65 67 88 0f          	mov    %cl,%gs:(%bx)
c0001aa4:	66 43                	inc    %bx
c0001aa6:	65 67 c6 07 07       	movb   $0x7,%gs:(%bx)
c0001aab:	66 d1 eb             	shr    %bx
c0001aae:	66 43                	inc    %bx
c0001ab0:	66 81 fb d0 07       	cmp    $0x7d0,%bx
c0001ab5:	7c 58                	jl     c0001b0f <set_cursor>

c0001ab7 <put_char.is_carriage_return>:
c0001ab7:	66 31 d2             	xor    %dx,%dx
c0001aba:	66 89 d8             	mov    %bx,%ax
c0001abd:	66 be 50 00          	mov    $0x50,%si
c0001ac1:	66 f7 f6             	div    %si
c0001ac4:	66 29 d3             	sub    %dx,%bx

c0001ac7 <put_char.is_carriage_return_end>:
c0001ac7:	66 83 c3 50          	add    $0x50,%bx
c0001acb:	66 81 fb d0 07       	cmp    $0x7d0,%bx

c0001ad0 <put_char.is_line_feed_end>:
c0001ad0:	7c 3d                	jl     c0001b0f <set_cursor>

c0001ad2 <put_char.roll_screen>:
c0001ad2:	fc                   	cld    
c0001ad3:	b9 c0 03 00 00       	mov    $0x3c0,%ecx
c0001ad8:	be a0 80 0b c0       	mov    $0xc00b80a0,%esi
c0001add:	bf 00 80 0b c0       	mov    $0xc00b8000,%edi
c0001ae2:	f3 a5                	rep movsl %ds:(%esi),%es:(%edi)
c0001ae4:	bb 00 0f 00 00       	mov    $0xf00,%ebx
c0001ae9:	b9 50 00 00 00       	mov    $0x50,%ecx

c0001aee <cls_screen>:
c0001aee:	60                   	pusha  
c0001aef:	66 b8 18 00          	mov    $0x18,%ax
c0001af3:	8e e8                	mov    %eax,%gs
c0001af5:	bb 00 00 00 00       	mov    $0x0,%ebx
c0001afa:	b9 d0 07 00 00       	mov    $0x7d0,%ecx

c0001aff <cls_screen.cls>:
c0001aff:	65 c7 03 20 07 00 00 	movl   $0x720,%gs:(%ebx)
c0001b06:	83 c3 02             	add    $0x2,%ebx
c0001b09:	e2 f4                	loop   c0001aff <cls_screen.cls>
c0001b0b:	66 bb 80 07          	mov    $0x780,%bx

c0001b0f <set_cursor>:
c0001b0f:	66 ba d4 03          	mov    $0x3d4,%dx
c0001b13:	b0 0e                	mov    $0xe,%al
c0001b15:	ee                   	out    %al,(%dx)
c0001b16:	66 ba d5 03          	mov    $0x3d5,%dx
c0001b1a:	88 f8                	mov    %bh,%al
c0001b1c:	ee                   	out    %al,(%dx)
c0001b1d:	66 ba d4 03          	mov    $0x3d4,%dx
c0001b21:	b0 0f                	mov    $0xf,%al
c0001b23:	ee                   	out    %al,(%dx)
c0001b24:	66 ba d5 03          	mov    $0x3d5,%dx
c0001b28:	88 d8                	mov    %bl,%al
c0001b2a:	ee                   	out    %al,(%dx)

c0001b2b <set_cursor.put_char_done>:
c0001b2b:	61                   	popa   
c0001b2c:	c3                   	ret    

c0001b2d <put_int>:
c0001b2d:	60                   	pusha  
c0001b2e:	89 e5                	mov    %esp,%ebp
c0001b30:	8b 45 24             	mov    0x24(%ebp),%eax
c0001b33:	89 c2                	mov    %eax,%edx
c0001b35:	bf 07 00 00 00       	mov    $0x7,%edi
c0001b3a:	b9 08 00 00 00       	mov    $0x8,%ecx
c0001b3f:	bb 00 10 01 c0       	mov    $0xc0011000,%ebx

c0001b44 <put_int.16based_4bits>:
c0001b44:	83 e2 0f             	and    $0xf,%edx
c0001b47:	83 fa 09             	cmp    $0x9,%edx
c0001b4a:	7f 05                	jg     c0001b51 <put_int.is_A2F>
c0001b4c:	83 c2 30             	add    $0x30,%edx
c0001b4f:	eb 06                	jmp    c0001b57 <put_int.store>

c0001b51 <put_int.is_A2F>:
c0001b51:	83 ea 0a             	sub    $0xa,%edx
c0001b54:	83 c2 41             	add    $0x41,%edx

c0001b57 <put_int.store>:
c0001b57:	88 14 3b             	mov    %dl,(%ebx,%edi,1)
c0001b5a:	4f                   	dec    %edi
c0001b5b:	c1 e8 04             	shr    $0x4,%eax
c0001b5e:	89 c2                	mov    %eax,%edx
c0001b60:	e2 e2                	loop   c0001b44 <put_int.16based_4bits>

c0001b62 <put_int.ready_to_print>:
c0001b62:	47                   	inc    %edi

c0001b63 <put_int.skip_prefix_0>:
c0001b63:	83 ff 08             	cmp    $0x8,%edi
c0001b66:	74 0f                	je     c0001b77 <put_int.full0>

c0001b68 <put_int.go_on_skip>:
c0001b68:	8a 8f 00 10 01 c0    	mov    -0x3ffef000(%edi),%cl
c0001b6e:	47                   	inc    %edi
c0001b6f:	80 f9 30             	cmp    $0x30,%cl
c0001b72:	74 ef                	je     c0001b63 <put_int.skip_prefix_0>
c0001b74:	4f                   	dec    %edi
c0001b75:	eb 02                	jmp    c0001b79 <put_int.put_each_num>

c0001b77 <put_int.full0>:
c0001b77:	b1 30                	mov    $0x30,%cl

c0001b79 <put_int.put_each_num>:
c0001b79:	51                   	push   %ecx
c0001b7a:	e8 cf fe ff ff       	call   c0001a4e <put_char>
c0001b7f:	83 c4 04             	add    $0x4,%esp
c0001b82:	47                   	inc    %edi
c0001b83:	8a 8f 00 10 01 c0    	mov    -0x3ffef000(%edi),%cl
c0001b89:	83 ff 08             	cmp    $0x8,%edi
c0001b8c:	7c eb                	jl     c0001b79 <put_int.put_each_num>
c0001b8e:	61                   	popa   
c0001b8f:	c3                   	ret    

c0001b90 <intr_exit>:
c0001b90:	83 c4 04             	add    $0x4,%esp
c0001b93:	61                   	popa   
c0001b94:	0f a9                	pop    %gs
c0001b96:	0f a1                	pop    %fs
c0001b98:	07                   	pop    %es
c0001b99:	1f                   	pop    %ds
c0001b9a:	83 c4 04             	add    $0x4,%esp
c0001b9d:	cf                   	iret   

c0001b9e <intr0x00entry>:
c0001b9e:	6a 00                	push   $0x0
c0001ba0:	1e                   	push   %ds
c0001ba1:	06                   	push   %es
c0001ba2:	0f a0                	push   %fs
c0001ba4:	0f a8                	push   %gs
c0001ba6:	60                   	pusha  
c0001ba7:	b0 20                	mov    $0x20,%al
c0001ba9:	e6 a0                	out    %al,$0xa0
c0001bab:	e6 20                	out    %al,$0x20
c0001bad:	6a 00                	push   $0x0
c0001baf:	ff 15 80 13 01 c0    	call   *0xc0011380
c0001bb5:	eb d9                	jmp    c0001b90 <intr_exit>

c0001bb7 <intr0x01entry>:
c0001bb7:	6a 00                	push   $0x0
c0001bb9:	1e                   	push   %ds
c0001bba:	06                   	push   %es
c0001bbb:	0f a0                	push   %fs
c0001bbd:	0f a8                	push   %gs
c0001bbf:	60                   	pusha  
c0001bc0:	b0 20                	mov    $0x20,%al
c0001bc2:	e6 a0                	out    %al,$0xa0
c0001bc4:	e6 20                	out    %al,$0x20
c0001bc6:	6a 01                	push   $0x1
c0001bc8:	ff 15 84 13 01 c0    	call   *0xc0011384
c0001bce:	eb c0                	jmp    c0001b90 <intr_exit>

c0001bd0 <intr0x02entry>:
c0001bd0:	6a 00                	push   $0x0
c0001bd2:	1e                   	push   %ds
c0001bd3:	06                   	push   %es
c0001bd4:	0f a0                	push   %fs
c0001bd6:	0f a8                	push   %gs
c0001bd8:	60                   	pusha  
c0001bd9:	b0 20                	mov    $0x20,%al
c0001bdb:	e6 a0                	out    %al,$0xa0
c0001bdd:	e6 20                	out    %al,$0x20
c0001bdf:	6a 02                	push   $0x2
c0001be1:	ff 15 88 13 01 c0    	call   *0xc0011388
c0001be7:	eb a7                	jmp    c0001b90 <intr_exit>

c0001be9 <intr0x03entry>:
c0001be9:	6a 00                	push   $0x0
c0001beb:	1e                   	push   %ds
c0001bec:	06                   	push   %es
c0001bed:	0f a0                	push   %fs
c0001bef:	0f a8                	push   %gs
c0001bf1:	60                   	pusha  
c0001bf2:	b0 20                	mov    $0x20,%al
c0001bf4:	e6 a0                	out    %al,$0xa0
c0001bf6:	e6 20                	out    %al,$0x20
c0001bf8:	6a 03                	push   $0x3
c0001bfa:	ff 15 8c 13 01 c0    	call   *0xc001138c
c0001c00:	eb 8e                	jmp    c0001b90 <intr_exit>

c0001c02 <intr0x04entry>:
c0001c02:	6a 00                	push   $0x0
c0001c04:	1e                   	push   %ds
c0001c05:	06                   	push   %es
c0001c06:	0f a0                	push   %fs
c0001c08:	0f a8                	push   %gs
c0001c0a:	60                   	pusha  
c0001c0b:	b0 20                	mov    $0x20,%al
c0001c0d:	e6 a0                	out    %al,$0xa0
c0001c0f:	e6 20                	out    %al,$0x20
c0001c11:	6a 04                	push   $0x4
c0001c13:	ff 15 90 13 01 c0    	call   *0xc0011390
c0001c19:	e9 72 ff ff ff       	jmp    c0001b90 <intr_exit>

c0001c1e <intr0x05entry>:
c0001c1e:	6a 00                	push   $0x0
c0001c20:	1e                   	push   %ds
c0001c21:	06                   	push   %es
c0001c22:	0f a0                	push   %fs
c0001c24:	0f a8                	push   %gs
c0001c26:	60                   	pusha  
c0001c27:	b0 20                	mov    $0x20,%al
c0001c29:	e6 a0                	out    %al,$0xa0
c0001c2b:	e6 20                	out    %al,$0x20
c0001c2d:	6a 05                	push   $0x5
c0001c2f:	ff 15 94 13 01 c0    	call   *0xc0011394
c0001c35:	e9 56 ff ff ff       	jmp    c0001b90 <intr_exit>

c0001c3a <intr0x06entry>:
c0001c3a:	6a 00                	push   $0x0
c0001c3c:	1e                   	push   %ds
c0001c3d:	06                   	push   %es
c0001c3e:	0f a0                	push   %fs
c0001c40:	0f a8                	push   %gs
c0001c42:	60                   	pusha  
c0001c43:	b0 20                	mov    $0x20,%al
c0001c45:	e6 a0                	out    %al,$0xa0
c0001c47:	e6 20                	out    %al,$0x20
c0001c49:	6a 06                	push   $0x6
c0001c4b:	ff 15 98 13 01 c0    	call   *0xc0011398
c0001c51:	e9 3a ff ff ff       	jmp    c0001b90 <intr_exit>

c0001c56 <intr0x07entry>:
c0001c56:	6a 00                	push   $0x0
c0001c58:	1e                   	push   %ds
c0001c59:	06                   	push   %es
c0001c5a:	0f a0                	push   %fs
c0001c5c:	0f a8                	push   %gs
c0001c5e:	60                   	pusha  
c0001c5f:	b0 20                	mov    $0x20,%al
c0001c61:	e6 a0                	out    %al,$0xa0
c0001c63:	e6 20                	out    %al,$0x20
c0001c65:	6a 07                	push   $0x7
c0001c67:	ff 15 9c 13 01 c0    	call   *0xc001139c
c0001c6d:	e9 1e ff ff ff       	jmp    c0001b90 <intr_exit>

c0001c72 <intr0x08entry>:
c0001c72:	90                   	nop
c0001c73:	1e                   	push   %ds
c0001c74:	06                   	push   %es
c0001c75:	0f a0                	push   %fs
c0001c77:	0f a8                	push   %gs
c0001c79:	60                   	pusha  
c0001c7a:	b0 20                	mov    $0x20,%al
c0001c7c:	e6 a0                	out    %al,$0xa0
c0001c7e:	e6 20                	out    %al,$0x20
c0001c80:	6a 08                	push   $0x8
c0001c82:	ff 15 a0 13 01 c0    	call   *0xc00113a0
c0001c88:	e9 03 ff ff ff       	jmp    c0001b90 <intr_exit>

c0001c8d <intr0x09entry>:
c0001c8d:	6a 00                	push   $0x0
c0001c8f:	1e                   	push   %ds
c0001c90:	06                   	push   %es
c0001c91:	0f a0                	push   %fs
c0001c93:	0f a8                	push   %gs
c0001c95:	60                   	pusha  
c0001c96:	b0 20                	mov    $0x20,%al
c0001c98:	e6 a0                	out    %al,$0xa0
c0001c9a:	e6 20                	out    %al,$0x20
c0001c9c:	6a 09                	push   $0x9
c0001c9e:	ff 15 a4 13 01 c0    	call   *0xc00113a4
c0001ca4:	e9 e7 fe ff ff       	jmp    c0001b90 <intr_exit>

c0001ca9 <intr0x0aentry>:
c0001ca9:	90                   	nop
c0001caa:	1e                   	push   %ds
c0001cab:	06                   	push   %es
c0001cac:	0f a0                	push   %fs
c0001cae:	0f a8                	push   %gs
c0001cb0:	60                   	pusha  
c0001cb1:	b0 20                	mov    $0x20,%al
c0001cb3:	e6 a0                	out    %al,$0xa0
c0001cb5:	e6 20                	out    %al,$0x20
c0001cb7:	6a 0a                	push   $0xa
c0001cb9:	ff 15 a8 13 01 c0    	call   *0xc00113a8
c0001cbf:	e9 cc fe ff ff       	jmp    c0001b90 <intr_exit>

c0001cc4 <intr0x0bentry>:
c0001cc4:	90                   	nop
c0001cc5:	1e                   	push   %ds
c0001cc6:	06                   	push   %es
c0001cc7:	0f a0                	push   %fs
c0001cc9:	0f a8                	push   %gs
c0001ccb:	60                   	pusha  
c0001ccc:	b0 20                	mov    $0x20,%al
c0001cce:	e6 a0                	out    %al,$0xa0
c0001cd0:	e6 20                	out    %al,$0x20
c0001cd2:	6a 0b                	push   $0xb
c0001cd4:	ff 15 ac 13 01 c0    	call   *0xc00113ac
c0001cda:	e9 b1 fe ff ff       	jmp    c0001b90 <intr_exit>

c0001cdf <intr0x0centry>:
c0001cdf:	90                   	nop
c0001ce0:	1e                   	push   %ds
c0001ce1:	06                   	push   %es
c0001ce2:	0f a0                	push   %fs
c0001ce4:	0f a8                	push   %gs
c0001ce6:	60                   	pusha  
c0001ce7:	b0 20                	mov    $0x20,%al
c0001ce9:	e6 a0                	out    %al,$0xa0
c0001ceb:	e6 20                	out    %al,$0x20
c0001ced:	6a 0c                	push   $0xc
c0001cef:	ff 15 b0 13 01 c0    	call   *0xc00113b0
c0001cf5:	e9 96 fe ff ff       	jmp    c0001b90 <intr_exit>

c0001cfa <intr0x0dentry>:
c0001cfa:	90                   	nop
c0001cfb:	1e                   	push   %ds
c0001cfc:	06                   	push   %es
c0001cfd:	0f a0                	push   %fs
c0001cff:	0f a8                	push   %gs
c0001d01:	60                   	pusha  
c0001d02:	b0 20                	mov    $0x20,%al
c0001d04:	e6 a0                	out    %al,$0xa0
c0001d06:	e6 20                	out    %al,$0x20
c0001d08:	6a 0d                	push   $0xd
c0001d0a:	ff 15 b4 13 01 c0    	call   *0xc00113b4
c0001d10:	e9 7b fe ff ff       	jmp    c0001b90 <intr_exit>

c0001d15 <intr0x0eentry>:
c0001d15:	90                   	nop
c0001d16:	1e                   	push   %ds
c0001d17:	06                   	push   %es
c0001d18:	0f a0                	push   %fs
c0001d1a:	0f a8                	push   %gs
c0001d1c:	60                   	pusha  
c0001d1d:	b0 20                	mov    $0x20,%al
c0001d1f:	e6 a0                	out    %al,$0xa0
c0001d21:	e6 20                	out    %al,$0x20
c0001d23:	6a 0e                	push   $0xe
c0001d25:	ff 15 b8 13 01 c0    	call   *0xc00113b8
c0001d2b:	e9 60 fe ff ff       	jmp    c0001b90 <intr_exit>

c0001d30 <intr0x0fentry>:
c0001d30:	6a 00                	push   $0x0
c0001d32:	1e                   	push   %ds
c0001d33:	06                   	push   %es
c0001d34:	0f a0                	push   %fs
c0001d36:	0f a8                	push   %gs
c0001d38:	60                   	pusha  
c0001d39:	b0 20                	mov    $0x20,%al
c0001d3b:	e6 a0                	out    %al,$0xa0
c0001d3d:	e6 20                	out    %al,$0x20
c0001d3f:	6a 0f                	push   $0xf
c0001d41:	ff 15 bc 13 01 c0    	call   *0xc00113bc
c0001d47:	e9 44 fe ff ff       	jmp    c0001b90 <intr_exit>

c0001d4c <intr0x10entry>:
c0001d4c:	6a 00                	push   $0x0
c0001d4e:	1e                   	push   %ds
c0001d4f:	06                   	push   %es
c0001d50:	0f a0                	push   %fs
c0001d52:	0f a8                	push   %gs
c0001d54:	60                   	pusha  
c0001d55:	b0 20                	mov    $0x20,%al
c0001d57:	e6 a0                	out    %al,$0xa0
c0001d59:	e6 20                	out    %al,$0x20
c0001d5b:	6a 10                	push   $0x10
c0001d5d:	ff 15 c0 13 01 c0    	call   *0xc00113c0
c0001d63:	e9 28 fe ff ff       	jmp    c0001b90 <intr_exit>

c0001d68 <intr0x11entry>:
c0001d68:	90                   	nop
c0001d69:	1e                   	push   %ds
c0001d6a:	06                   	push   %es
c0001d6b:	0f a0                	push   %fs
c0001d6d:	0f a8                	push   %gs
c0001d6f:	60                   	pusha  
c0001d70:	b0 20                	mov    $0x20,%al
c0001d72:	e6 a0                	out    %al,$0xa0
c0001d74:	e6 20                	out    %al,$0x20
c0001d76:	6a 11                	push   $0x11
c0001d78:	ff 15 c4 13 01 c0    	call   *0xc00113c4
c0001d7e:	e9 0d fe ff ff       	jmp    c0001b90 <intr_exit>

c0001d83 <intr0x12entry>:
c0001d83:	6a 00                	push   $0x0
c0001d85:	1e                   	push   %ds
c0001d86:	06                   	push   %es
c0001d87:	0f a0                	push   %fs
c0001d89:	0f a8                	push   %gs
c0001d8b:	60                   	pusha  
c0001d8c:	b0 20                	mov    $0x20,%al
c0001d8e:	e6 a0                	out    %al,$0xa0
c0001d90:	e6 20                	out    %al,$0x20
c0001d92:	6a 12                	push   $0x12
c0001d94:	ff 15 c8 13 01 c0    	call   *0xc00113c8
c0001d9a:	e9 f1 fd ff ff       	jmp    c0001b90 <intr_exit>

c0001d9f <intr0x13entry>:
c0001d9f:	6a 00                	push   $0x0
c0001da1:	1e                   	push   %ds
c0001da2:	06                   	push   %es
c0001da3:	0f a0                	push   %fs
c0001da5:	0f a8                	push   %gs
c0001da7:	60                   	pusha  
c0001da8:	b0 20                	mov    $0x20,%al
c0001daa:	e6 a0                	out    %al,$0xa0
c0001dac:	e6 20                	out    %al,$0x20
c0001dae:	6a 13                	push   $0x13
c0001db0:	ff 15 cc 13 01 c0    	call   *0xc00113cc
c0001db6:	e9 d5 fd ff ff       	jmp    c0001b90 <intr_exit>

c0001dbb <intr0x14entry>:
c0001dbb:	6a 00                	push   $0x0
c0001dbd:	1e                   	push   %ds
c0001dbe:	06                   	push   %es
c0001dbf:	0f a0                	push   %fs
c0001dc1:	0f a8                	push   %gs
c0001dc3:	60                   	pusha  
c0001dc4:	b0 20                	mov    $0x20,%al
c0001dc6:	e6 a0                	out    %al,$0xa0
c0001dc8:	e6 20                	out    %al,$0x20
c0001dca:	6a 14                	push   $0x14
c0001dcc:	ff 15 d0 13 01 c0    	call   *0xc00113d0
c0001dd2:	e9 b9 fd ff ff       	jmp    c0001b90 <intr_exit>

c0001dd7 <intr0x15entry>:
c0001dd7:	6a 00                	push   $0x0
c0001dd9:	1e                   	push   %ds
c0001dda:	06                   	push   %es
c0001ddb:	0f a0                	push   %fs
c0001ddd:	0f a8                	push   %gs
c0001ddf:	60                   	pusha  
c0001de0:	b0 20                	mov    $0x20,%al
c0001de2:	e6 a0                	out    %al,$0xa0
c0001de4:	e6 20                	out    %al,$0x20
c0001de6:	6a 15                	push   $0x15
c0001de8:	ff 15 d4 13 01 c0    	call   *0xc00113d4
c0001dee:	e9 9d fd ff ff       	jmp    c0001b90 <intr_exit>

c0001df3 <intr0x16entry>:
c0001df3:	6a 00                	push   $0x0
c0001df5:	1e                   	push   %ds
c0001df6:	06                   	push   %es
c0001df7:	0f a0                	push   %fs
c0001df9:	0f a8                	push   %gs
c0001dfb:	60                   	pusha  
c0001dfc:	b0 20                	mov    $0x20,%al
c0001dfe:	e6 a0                	out    %al,$0xa0
c0001e00:	e6 20                	out    %al,$0x20
c0001e02:	6a 16                	push   $0x16
c0001e04:	ff 15 d8 13 01 c0    	call   *0xc00113d8
c0001e0a:	e9 81 fd ff ff       	jmp    c0001b90 <intr_exit>

c0001e0f <intr0x17entry>:
c0001e0f:	6a 00                	push   $0x0
c0001e11:	1e                   	push   %ds
c0001e12:	06                   	push   %es
c0001e13:	0f a0                	push   %fs
c0001e15:	0f a8                	push   %gs
c0001e17:	60                   	pusha  
c0001e18:	b0 20                	mov    $0x20,%al
c0001e1a:	e6 a0                	out    %al,$0xa0
c0001e1c:	e6 20                	out    %al,$0x20
c0001e1e:	6a 17                	push   $0x17
c0001e20:	ff 15 dc 13 01 c0    	call   *0xc00113dc
c0001e26:	e9 65 fd ff ff       	jmp    c0001b90 <intr_exit>

c0001e2b <intr0x18entry>:
c0001e2b:	6a 00                	push   $0x0
c0001e2d:	1e                   	push   %ds
c0001e2e:	06                   	push   %es
c0001e2f:	0f a0                	push   %fs
c0001e31:	0f a8                	push   %gs
c0001e33:	60                   	pusha  
c0001e34:	b0 20                	mov    $0x20,%al
c0001e36:	e6 a0                	out    %al,$0xa0
c0001e38:	e6 20                	out    %al,$0x20
c0001e3a:	6a 18                	push   $0x18
c0001e3c:	ff 15 e0 13 01 c0    	call   *0xc00113e0
c0001e42:	e9 49 fd ff ff       	jmp    c0001b90 <intr_exit>

c0001e47 <intr0x19entry>:
c0001e47:	6a 00                	push   $0x0
c0001e49:	1e                   	push   %ds
c0001e4a:	06                   	push   %es
c0001e4b:	0f a0                	push   %fs
c0001e4d:	0f a8                	push   %gs
c0001e4f:	60                   	pusha  
c0001e50:	b0 20                	mov    $0x20,%al
c0001e52:	e6 a0                	out    %al,$0xa0
c0001e54:	e6 20                	out    %al,$0x20
c0001e56:	6a 19                	push   $0x19
c0001e58:	ff 15 e4 13 01 c0    	call   *0xc00113e4
c0001e5e:	e9 2d fd ff ff       	jmp    c0001b90 <intr_exit>

c0001e63 <intr0x1aentry>:
c0001e63:	6a 00                	push   $0x0
c0001e65:	1e                   	push   %ds
c0001e66:	06                   	push   %es
c0001e67:	0f a0                	push   %fs
c0001e69:	0f a8                	push   %gs
c0001e6b:	60                   	pusha  
c0001e6c:	b0 20                	mov    $0x20,%al
c0001e6e:	e6 a0                	out    %al,$0xa0
c0001e70:	e6 20                	out    %al,$0x20
c0001e72:	6a 1a                	push   $0x1a
c0001e74:	ff 15 e8 13 01 c0    	call   *0xc00113e8
c0001e7a:	e9 11 fd ff ff       	jmp    c0001b90 <intr_exit>

c0001e7f <intr0x1bentry>:
c0001e7f:	6a 00                	push   $0x0
c0001e81:	1e                   	push   %ds
c0001e82:	06                   	push   %es
c0001e83:	0f a0                	push   %fs
c0001e85:	0f a8                	push   %gs
c0001e87:	60                   	pusha  
c0001e88:	b0 20                	mov    $0x20,%al
c0001e8a:	e6 a0                	out    %al,$0xa0
c0001e8c:	e6 20                	out    %al,$0x20
c0001e8e:	6a 1b                	push   $0x1b
c0001e90:	ff 15 ec 13 01 c0    	call   *0xc00113ec
c0001e96:	e9 f5 fc ff ff       	jmp    c0001b90 <intr_exit>

c0001e9b <intr0x1centry>:
c0001e9b:	6a 00                	push   $0x0
c0001e9d:	1e                   	push   %ds
c0001e9e:	06                   	push   %es
c0001e9f:	0f a0                	push   %fs
c0001ea1:	0f a8                	push   %gs
c0001ea3:	60                   	pusha  
c0001ea4:	b0 20                	mov    $0x20,%al
c0001ea6:	e6 a0                	out    %al,$0xa0
c0001ea8:	e6 20                	out    %al,$0x20
c0001eaa:	6a 1c                	push   $0x1c
c0001eac:	ff 15 f0 13 01 c0    	call   *0xc00113f0
c0001eb2:	e9 d9 fc ff ff       	jmp    c0001b90 <intr_exit>

c0001eb7 <intr0x1dentry>:
c0001eb7:	6a 00                	push   $0x0
c0001eb9:	1e                   	push   %ds
c0001eba:	06                   	push   %es
c0001ebb:	0f a0                	push   %fs
c0001ebd:	0f a8                	push   %gs
c0001ebf:	60                   	pusha  
c0001ec0:	b0 20                	mov    $0x20,%al
c0001ec2:	e6 a0                	out    %al,$0xa0
c0001ec4:	e6 20                	out    %al,$0x20
c0001ec6:	6a 1d                	push   $0x1d
c0001ec8:	ff 15 f4 13 01 c0    	call   *0xc00113f4
c0001ece:	e9 bd fc ff ff       	jmp    c0001b90 <intr_exit>

c0001ed3 <intr0x1eentry>:
c0001ed3:	90                   	nop
c0001ed4:	1e                   	push   %ds
c0001ed5:	06                   	push   %es
c0001ed6:	0f a0                	push   %fs
c0001ed8:	0f a8                	push   %gs
c0001eda:	60                   	pusha  
c0001edb:	b0 20                	mov    $0x20,%al
c0001edd:	e6 a0                	out    %al,$0xa0
c0001edf:	e6 20                	out    %al,$0x20
c0001ee1:	6a 1e                	push   $0x1e
c0001ee3:	ff 15 f8 13 01 c0    	call   *0xc00113f8
c0001ee9:	e9 a2 fc ff ff       	jmp    c0001b90 <intr_exit>

c0001eee <intr0x1fentry>:
c0001eee:	6a 00                	push   $0x0
c0001ef0:	1e                   	push   %ds
c0001ef1:	06                   	push   %es
c0001ef2:	0f a0                	push   %fs
c0001ef4:	0f a8                	push   %gs
c0001ef6:	60                   	pusha  
c0001ef7:	b0 20                	mov    $0x20,%al
c0001ef9:	e6 a0                	out    %al,$0xa0
c0001efb:	e6 20                	out    %al,$0x20
c0001efd:	6a 1f                	push   $0x1f
c0001eff:	ff 15 fc 13 01 c0    	call   *0xc00113fc
c0001f05:	e9 86 fc ff ff       	jmp    c0001b90 <intr_exit>

c0001f0a <intr0x20entry>:
c0001f0a:	6a 00                	push   $0x0
c0001f0c:	1e                   	push   %ds
c0001f0d:	06                   	push   %es
c0001f0e:	0f a0                	push   %fs
c0001f10:	0f a8                	push   %gs
c0001f12:	60                   	pusha  
c0001f13:	b0 20                	mov    $0x20,%al
c0001f15:	e6 a0                	out    %al,$0xa0
c0001f17:	e6 20                	out    %al,$0x20
c0001f19:	6a 20                	push   $0x20
c0001f1b:	ff 15 00 14 01 c0    	call   *0xc0011400
c0001f21:	e9 6a fc ff ff       	jmp    c0001b90 <intr_exit>

c0001f26 <intr0x21entry>:
c0001f26:	6a 00                	push   $0x0
c0001f28:	1e                   	push   %ds
c0001f29:	06                   	push   %es
c0001f2a:	0f a0                	push   %fs
c0001f2c:	0f a8                	push   %gs
c0001f2e:	60                   	pusha  
c0001f2f:	b0 20                	mov    $0x20,%al
c0001f31:	e6 a0                	out    %al,$0xa0
c0001f33:	e6 20                	out    %al,$0x20
c0001f35:	6a 21                	push   $0x21
c0001f37:	ff 15 04 14 01 c0    	call   *0xc0011404
c0001f3d:	e9 4e fc ff ff       	jmp    c0001b90 <intr_exit>

c0001f42 <intr0x22entry>:
c0001f42:	6a 00                	push   $0x0
c0001f44:	1e                   	push   %ds
c0001f45:	06                   	push   %es
c0001f46:	0f a0                	push   %fs
c0001f48:	0f a8                	push   %gs
c0001f4a:	60                   	pusha  
c0001f4b:	b0 20                	mov    $0x20,%al
c0001f4d:	e6 a0                	out    %al,$0xa0
c0001f4f:	e6 20                	out    %al,$0x20
c0001f51:	6a 22                	push   $0x22
c0001f53:	ff 15 08 14 01 c0    	call   *0xc0011408
c0001f59:	e9 32 fc ff ff       	jmp    c0001b90 <intr_exit>

c0001f5e <intr0x23entry>:
c0001f5e:	6a 00                	push   $0x0
c0001f60:	1e                   	push   %ds
c0001f61:	06                   	push   %es
c0001f62:	0f a0                	push   %fs
c0001f64:	0f a8                	push   %gs
c0001f66:	60                   	pusha  
c0001f67:	b0 20                	mov    $0x20,%al
c0001f69:	e6 a0                	out    %al,$0xa0
c0001f6b:	e6 20                	out    %al,$0x20
c0001f6d:	6a 23                	push   $0x23
c0001f6f:	ff 15 0c 14 01 c0    	call   *0xc001140c
c0001f75:	e9 16 fc ff ff       	jmp    c0001b90 <intr_exit>

c0001f7a <intr0x24entry>:
c0001f7a:	6a 00                	push   $0x0
c0001f7c:	1e                   	push   %ds
c0001f7d:	06                   	push   %es
c0001f7e:	0f a0                	push   %fs
c0001f80:	0f a8                	push   %gs
c0001f82:	60                   	pusha  
c0001f83:	b0 20                	mov    $0x20,%al
c0001f85:	e6 a0                	out    %al,$0xa0
c0001f87:	e6 20                	out    %al,$0x20
c0001f89:	6a 24                	push   $0x24
c0001f8b:	ff 15 10 14 01 c0    	call   *0xc0011410
c0001f91:	e9 fa fb ff ff       	jmp    c0001b90 <intr_exit>

c0001f96 <intr0x25entry>:
c0001f96:	6a 00                	push   $0x0
c0001f98:	1e                   	push   %ds
c0001f99:	06                   	push   %es
c0001f9a:	0f a0                	push   %fs
c0001f9c:	0f a8                	push   %gs
c0001f9e:	60                   	pusha  
c0001f9f:	b0 20                	mov    $0x20,%al
c0001fa1:	e6 a0                	out    %al,$0xa0
c0001fa3:	e6 20                	out    %al,$0x20
c0001fa5:	6a 25                	push   $0x25
c0001fa7:	ff 15 14 14 01 c0    	call   *0xc0011414
c0001fad:	e9 de fb ff ff       	jmp    c0001b90 <intr_exit>

c0001fb2 <intr0x26entry>:
c0001fb2:	6a 00                	push   $0x0
c0001fb4:	1e                   	push   %ds
c0001fb5:	06                   	push   %es
c0001fb6:	0f a0                	push   %fs
c0001fb8:	0f a8                	push   %gs
c0001fba:	60                   	pusha  
c0001fbb:	b0 20                	mov    $0x20,%al
c0001fbd:	e6 a0                	out    %al,$0xa0
c0001fbf:	e6 20                	out    %al,$0x20
c0001fc1:	6a 26                	push   $0x26
c0001fc3:	ff 15 18 14 01 c0    	call   *0xc0011418
c0001fc9:	e9 c2 fb ff ff       	jmp    c0001b90 <intr_exit>

c0001fce <intr0x27entry>:
c0001fce:	6a 00                	push   $0x0
c0001fd0:	1e                   	push   %ds
c0001fd1:	06                   	push   %es
c0001fd2:	0f a0                	push   %fs
c0001fd4:	0f a8                	push   %gs
c0001fd6:	60                   	pusha  
c0001fd7:	b0 20                	mov    $0x20,%al
c0001fd9:	e6 a0                	out    %al,$0xa0
c0001fdb:	e6 20                	out    %al,$0x20
c0001fdd:	6a 27                	push   $0x27
c0001fdf:	ff 15 1c 14 01 c0    	call   *0xc001141c
c0001fe5:	e9 a6 fb ff ff       	jmp    c0001b90 <intr_exit>

c0001fea <intr0x28entry>:
c0001fea:	6a 00                	push   $0x0
c0001fec:	1e                   	push   %ds
c0001fed:	06                   	push   %es
c0001fee:	0f a0                	push   %fs
c0001ff0:	0f a8                	push   %gs
c0001ff2:	60                   	pusha  
c0001ff3:	b0 20                	mov    $0x20,%al
c0001ff5:	e6 a0                	out    %al,$0xa0
c0001ff7:	e6 20                	out    %al,$0x20
c0001ff9:	6a 28                	push   $0x28
c0001ffb:	ff 15 20 14 01 c0    	call   *0xc0011420
c0002001:	e9 8a fb ff ff       	jmp    c0001b90 <intr_exit>

c0002006 <intr0x29entry>:
c0002006:	6a 00                	push   $0x0
c0002008:	1e                   	push   %ds
c0002009:	06                   	push   %es
c000200a:	0f a0                	push   %fs
c000200c:	0f a8                	push   %gs
c000200e:	60                   	pusha  
c000200f:	b0 20                	mov    $0x20,%al
c0002011:	e6 a0                	out    %al,$0xa0
c0002013:	e6 20                	out    %al,$0x20
c0002015:	6a 29                	push   $0x29
c0002017:	ff 15 24 14 01 c0    	call   *0xc0011424
c000201d:	e9 6e fb ff ff       	jmp    c0001b90 <intr_exit>

c0002022 <intr0x2aentry>:
c0002022:	6a 00                	push   $0x0
c0002024:	1e                   	push   %ds
c0002025:	06                   	push   %es
c0002026:	0f a0                	push   %fs
c0002028:	0f a8                	push   %gs
c000202a:	60                   	pusha  
c000202b:	b0 20                	mov    $0x20,%al
c000202d:	e6 a0                	out    %al,$0xa0
c000202f:	e6 20                	out    %al,$0x20
c0002031:	6a 2a                	push   $0x2a
c0002033:	ff 15 28 14 01 c0    	call   *0xc0011428
c0002039:	e9 52 fb ff ff       	jmp    c0001b90 <intr_exit>

c000203e <intr0x2bentry>:
c000203e:	6a 00                	push   $0x0
c0002040:	1e                   	push   %ds
c0002041:	06                   	push   %es
c0002042:	0f a0                	push   %fs
c0002044:	0f a8                	push   %gs
c0002046:	60                   	pusha  
c0002047:	b0 20                	mov    $0x20,%al
c0002049:	e6 a0                	out    %al,$0xa0
c000204b:	e6 20                	out    %al,$0x20
c000204d:	6a 2b                	push   $0x2b
c000204f:	ff 15 2c 14 01 c0    	call   *0xc001142c
c0002055:	e9 36 fb ff ff       	jmp    c0001b90 <intr_exit>

c000205a <intr0x2centry>:
c000205a:	6a 00                	push   $0x0
c000205c:	1e                   	push   %ds
c000205d:	06                   	push   %es
c000205e:	0f a0                	push   %fs
c0002060:	0f a8                	push   %gs
c0002062:	60                   	pusha  
c0002063:	b0 20                	mov    $0x20,%al
c0002065:	e6 a0                	out    %al,$0xa0
c0002067:	e6 20                	out    %al,$0x20
c0002069:	6a 2c                	push   $0x2c
c000206b:	ff 15 30 14 01 c0    	call   *0xc0011430
c0002071:	e9 1a fb ff ff       	jmp    c0001b90 <intr_exit>

c0002076 <intr0x2dentry>:
c0002076:	6a 00                	push   $0x0
c0002078:	1e                   	push   %ds
c0002079:	06                   	push   %es
c000207a:	0f a0                	push   %fs
c000207c:	0f a8                	push   %gs
c000207e:	60                   	pusha  
c000207f:	b0 20                	mov    $0x20,%al
c0002081:	e6 a0                	out    %al,$0xa0
c0002083:	e6 20                	out    %al,$0x20
c0002085:	6a 2d                	push   $0x2d
c0002087:	ff 15 34 14 01 c0    	call   *0xc0011434
c000208d:	e9 fe fa ff ff       	jmp    c0001b90 <intr_exit>

c0002092 <intr0x2eentry>:
c0002092:	6a 00                	push   $0x0
c0002094:	1e                   	push   %ds
c0002095:	06                   	push   %es
c0002096:	0f a0                	push   %fs
c0002098:	0f a8                	push   %gs
c000209a:	60                   	pusha  
c000209b:	b0 20                	mov    $0x20,%al
c000209d:	e6 a0                	out    %al,$0xa0
c000209f:	e6 20                	out    %al,$0x20
c00020a1:	6a 2e                	push   $0x2e
c00020a3:	ff 15 38 14 01 c0    	call   *0xc0011438
c00020a9:	e9 e2 fa ff ff       	jmp    c0001b90 <intr_exit>

c00020ae <intr0x2fentry>:
c00020ae:	6a 00                	push   $0x0
c00020b0:	1e                   	push   %ds
c00020b1:	06                   	push   %es
c00020b2:	0f a0                	push   %fs
c00020b4:	0f a8                	push   %gs
c00020b6:	60                   	pusha  
c00020b7:	b0 20                	mov    $0x20,%al
c00020b9:	e6 a0                	out    %al,$0xa0
c00020bb:	e6 20                	out    %al,$0x20
c00020bd:	6a 2f                	push   $0x2f
c00020bf:	ff 15 3c 14 01 c0    	call   *0xc001143c
c00020c5:	e9 c6 fa ff ff       	jmp    c0001b90 <intr_exit>

c00020ca <syscall_handler>:
c00020ca:	6a 00                	push   $0x0
c00020cc:	1e                   	push   %ds
c00020cd:	06                   	push   %es
c00020ce:	0f a0                	push   %fs
c00020d0:	0f a8                	push   %gs
c00020d2:	60                   	pusha  
c00020d3:	68 80 00 00 00       	push   $0x80
c00020d8:	52                   	push   %edx
c00020d9:	51                   	push   %ecx
c00020da:	53                   	push   %ebx
c00020db:	ff 14 85 60 1c 01 c0 	call   *-0x3ffee3a0(,%eax,4)
c00020e2:	83 c4 0c             	add    $0xc,%esp
c00020e5:	89 44 24 20          	mov    %eax,0x20(%esp)
c00020e9:	e9 a2 fa ff ff       	jmp    c0001b90 <intr_exit>

c00020ee <outb>:
static inline void outb(uint16_t port, uint8_t data) {
c00020ee:	55                   	push   %ebp
c00020ef:	89 e5                	mov    %esp,%ebp
c00020f1:	83 ec 08             	sub    $0x8,%esp
c00020f4:	8b 45 08             	mov    0x8(%ebp),%eax
c00020f7:	8b 55 0c             	mov    0xc(%ebp),%edx
c00020fa:	66 89 45 fc          	mov    %ax,-0x4(%ebp)
c00020fe:	89 d0                	mov    %edx,%eax
c0002100:	88 45 f8             	mov    %al,-0x8(%ebp)
  asm volatile("outb %b0, %w1" ::"a"(data), "Nd"(port));
c0002103:	0f b6 45 f8          	movzbl -0x8(%ebp),%eax
c0002107:	0f b7 55 fc          	movzwl -0x4(%ebp),%edx
c000210b:	ee                   	out    %al,(%dx)
}
c000210c:	90                   	nop
c000210d:	c9                   	leave  
c000210e:	c3                   	ret    

c000210f <frequency_set>:
#define mil_seconds_per_intr (1000 / IRQ0_FREQUENCY)

uint32_t ticks; // 内核发生的总中断次数（系统运行时长）

static void frequency_set(uint8_t counter_port, uint8_t counter_no, uint8_t rwl,
                          uint8_t counter_mode, uint16_t counter_value) {
c000210f:	55                   	push   %ebp
c0002110:	89 e5                	mov    %esp,%ebp
c0002112:	57                   	push   %edi
c0002113:	56                   	push   %esi
c0002114:	53                   	push   %ebx
c0002115:	83 ec 14             	sub    $0x14,%esp
c0002118:	8b 75 08             	mov    0x8(%ebp),%esi
c000211b:	8b 5d 0c             	mov    0xc(%ebp),%ebx
c000211e:	8b 4d 10             	mov    0x10(%ebp),%ecx
c0002121:	8b 55 14             	mov    0x14(%ebp),%edx
c0002124:	8b 7d 18             	mov    0x18(%ebp),%edi
c0002127:	89 f0                	mov    %esi,%eax
c0002129:	88 45 f0             	mov    %al,-0x10(%ebp)
c000212c:	88 5d ec             	mov    %bl,-0x14(%ebp)
c000212f:	88 4d e8             	mov    %cl,-0x18(%ebp)
c0002132:	88 55 e4             	mov    %dl,-0x1c(%ebp)
c0002135:	89 f8                	mov    %edi,%eax
c0002137:	66 89 45 e0          	mov    %ax,-0x20(%ebp)
  // 往控制字寄存器端口0x43中写入控制字
  outb(PIT_CONTROL_PORT,
       (uint8_t)(counter_no << 6 | rwl << 4 | counter_mode << 1));
c000213b:	0f b6 45 ec          	movzbl -0x14(%ebp),%eax
c000213f:	c1 e0 06             	shl    $0x6,%eax
c0002142:	89 c2                	mov    %eax,%edx
c0002144:	0f b6 45 e8          	movzbl -0x18(%ebp),%eax
c0002148:	c1 e0 04             	shl    $0x4,%eax
c000214b:	09 c2                	or     %eax,%edx
c000214d:	0f b6 45 e4          	movzbl -0x1c(%ebp),%eax
c0002151:	01 c0                	add    %eax,%eax
c0002153:	09 d0                	or     %edx,%eax
  outb(PIT_CONTROL_PORT,
c0002155:	0f b6 c0             	movzbl %al,%eax
c0002158:	50                   	push   %eax
c0002159:	6a 43                	push   $0x43
c000215b:	e8 8e ff ff ff       	call   c00020ee <outb>
c0002160:	83 c4 08             	add    $0x8,%esp
  // 先写入counter_value低8位，再写高8位
  outb(counter_port, (uint8_t)counter_value);
c0002163:	0f b7 45 e0          	movzwl -0x20(%ebp),%eax
c0002167:	0f b6 d0             	movzbl %al,%edx
c000216a:	0f b6 45 f0          	movzbl -0x10(%ebp),%eax
c000216e:	52                   	push   %edx
c000216f:	50                   	push   %eax
c0002170:	e8 79 ff ff ff       	call   c00020ee <outb>
c0002175:	83 c4 08             	add    $0x8,%esp
  outb(counter_port, (uint8_t)counter_value >> 8);
c0002178:	0f b7 45 e0          	movzwl -0x20(%ebp),%eax
c000217c:	0f b6 c0             	movzbl %al,%eax
c000217f:	c1 f8 08             	sar    $0x8,%eax
c0002182:	0f b6 d0             	movzbl %al,%edx
c0002185:	0f b6 45 f0          	movzbl -0x10(%ebp),%eax
c0002189:	52                   	push   %edx
c000218a:	50                   	push   %eax
c000218b:	e8 5e ff ff ff       	call   c00020ee <outb>
c0002190:	83 c4 08             	add    $0x8,%esp
}
c0002193:	90                   	nop
c0002194:	8d 65 f4             	lea    -0xc(%ebp),%esp
c0002197:	5b                   	pop    %ebx
c0002198:	5e                   	pop    %esi
c0002199:	5f                   	pop    %edi
c000219a:	5d                   	pop    %ebp
c000219b:	c3                   	ret    

c000219c <intr_timer_handler>:

// 时钟中断处理函数
static void intr_timer_handler(void) {
c000219c:	55                   	push   %ebp
c000219d:	89 e5                	mov    %esp,%ebp
c000219f:	83 ec 18             	sub    $0x18,%esp
  struct task_struct *cur_thread = running_thread();
c00021a2:	e8 68 19 00 00       	call   c0003b0f <running_thread>
c00021a7:	89 45 f4             	mov    %eax,-0xc(%ebp)
  ASSERT(cur_thread->stack_magic == 0x20021112);
c00021aa:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00021ad:	8b 80 14 01 00 00    	mov    0x114(%eax),%eax
c00021b3:	3d 12 11 02 20       	cmp    $0x20021112,%eax
c00021b8:	74 19                	je     c00021d3 <intr_timer_handler+0x37>
c00021ba:	68 28 c3 00 c0       	push   $0xc000c328
c00021bf:	68 90 c3 00 c0       	push   $0xc000c390
c00021c4:	6a 23                	push   $0x23
c00021c6:	68 4e c3 00 c0       	push   $0xc000c34e
c00021cb:	e8 08 01 00 00       	call   c00022d8 <panic_spin>
c00021d0:	83 c4 10             	add    $0x10,%esp
  cur_thread->elapsed_ticks++; // 记录此线程占用cpu时间
c00021d3:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00021d6:	8b 40 20             	mov    0x20(%eax),%eax
c00021d9:	8d 50 01             	lea    0x1(%eax),%edx
c00021dc:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00021df:	89 50 20             	mov    %edx,0x20(%eax)
  ticks++;
c00021e2:	a1 a8 19 01 c0       	mov    0xc00119a8,%eax
c00021e7:	83 c0 01             	add    $0x1,%eax
c00021ea:	a3 a8 19 01 c0       	mov    %eax,0xc00119a8

  if (cur_thread->ticks == 0) { // 时间片用完，调度新进程上cpu
c00021ef:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00021f2:	0f b6 40 1d          	movzbl 0x1d(%eax),%eax
c00021f6:	84 c0                	test   %al,%al
c00021f8:	75 07                	jne    c0002201 <intr_timer_handler+0x65>
    schedule();
c00021fa:	e8 6e 1c 00 00       	call   c0003e6d <schedule>
  } else {
    cur_thread->ticks--;
  }
}
c00021ff:	eb 10                	jmp    c0002211 <intr_timer_handler+0x75>
    cur_thread->ticks--;
c0002201:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002204:	0f b6 40 1d          	movzbl 0x1d(%eax),%eax
c0002208:	8d 50 ff             	lea    -0x1(%eax),%edx
c000220b:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000220e:	88 50 1d             	mov    %dl,0x1d(%eax)
}
c0002211:	90                   	nop
c0002212:	c9                   	leave  
c0002213:	c3                   	ret    

c0002214 <timer_init>:

// 初始化PIT8253
void timer_init() {
c0002214:	55                   	push   %ebp
c0002215:	89 e5                	mov    %esp,%ebp
c0002217:	83 ec 08             	sub    $0x8,%esp
  put_str("timer_init start\n");
c000221a:	83 ec 0c             	sub    $0xc,%esp
c000221d:	68 5d c3 00 c0       	push   $0xc000c35d
c0002222:	e8 09 f8 ff ff       	call   c0001a30 <put_str>
c0002227:	83 c4 10             	add    $0x10,%esp
  // 设置8253定时周期-> 发中断周期
  frequency_set(CONTRER0_PORT, COUNTER0_NO, READ_WRITE_LATCH, COUNTER_MODE,
c000222a:	83 ec 0c             	sub    $0xc,%esp
c000222d:	68 9b 2e 00 00       	push   $0x2e9b
c0002232:	6a 02                	push   $0x2
c0002234:	6a 03                	push   $0x3
c0002236:	6a 00                	push   $0x0
c0002238:	6a 40                	push   $0x40
c000223a:	e8 d0 fe ff ff       	call   c000210f <frequency_set>
c000223f:	83 c4 20             	add    $0x20,%esp
                COUNTER0_VALUE);
  register_handler(0x20, intr_timer_handler); // 注册时钟中断处理函数
c0002242:	83 ec 08             	sub    $0x8,%esp
c0002245:	68 9c 21 00 c0       	push   $0xc000219c
c000224a:	6a 20                	push   $0x20
c000224c:	e8 15 f7 ff ff       	call   c0001966 <register_handler>
c0002251:	83 c4 10             	add    $0x10,%esp
  put_str("timer_init done\n");
c0002254:	83 ec 0c             	sub    $0xc,%esp
c0002257:	68 6f c3 00 c0       	push   $0xc000c36f
c000225c:	e8 cf f7 ff ff       	call   c0001a30 <put_str>
c0002261:	83 c4 10             	add    $0x10,%esp
}
c0002264:	90                   	nop
c0002265:	c9                   	leave  
c0002266:	c3                   	ret    

c0002267 <ticks_to_sleep>:

// 以tick为单位的sleep，任何时间形式的sleep会转换此ticks形式
static void ticks_to_sleep(uint32_t sleep_ticks) {
c0002267:	55                   	push   %ebp
c0002268:	89 e5                	mov    %esp,%ebp
c000226a:	83 ec 18             	sub    $0x18,%esp
  uint32_t start_tick = ticks;
c000226d:	a1 a8 19 01 c0       	mov    0xc00119a8,%eax
c0002272:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while (ticks - start_tick < sleep_ticks) {
c0002275:	eb 05                	jmp    c000227c <ticks_to_sleep+0x15>
    thread_yield();
c0002277:	e8 0e 1d 00 00       	call   c0003f8a <thread_yield>
  while (ticks - start_tick < sleep_ticks) {
c000227c:	a1 a8 19 01 c0       	mov    0xc00119a8,%eax
c0002281:	2b 45 f4             	sub    -0xc(%ebp),%eax
c0002284:	39 45 08             	cmp    %eax,0x8(%ebp)
c0002287:	77 ee                	ja     c0002277 <ticks_to_sleep+0x10>
  }
}
c0002289:	90                   	nop
c000228a:	90                   	nop
c000228b:	c9                   	leave  
c000228c:	c3                   	ret    

c000228d <mtime_sleep>:

// 以ms为单位的sleep
void mtime_sleep(uint32_t m_seconds) {
c000228d:	55                   	push   %ebp
c000228e:	89 e5                	mov    %esp,%ebp
c0002290:	83 ec 18             	sub    $0x18,%esp
  uint32_t sleep_ticks = DIV_ROUND_UP(m_seconds, mil_seconds_per_intr);
c0002293:	8b 45 08             	mov    0x8(%ebp),%eax
c0002296:	83 c0 09             	add    $0x9,%eax
c0002299:	ba cd cc cc cc       	mov    $0xcccccccd,%edx
c000229e:	f7 e2                	mul    %edx
c00022a0:	89 d0                	mov    %edx,%eax
c00022a2:	c1 e8 03             	shr    $0x3,%eax
c00022a5:	89 45 f4             	mov    %eax,-0xc(%ebp)
  ASSERT(sleep_ticks > 0);
c00022a8:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
c00022ac:	75 19                	jne    c00022c7 <mtime_sleep+0x3a>
c00022ae:	68 80 c3 00 c0       	push   $0xc000c380
c00022b3:	68 a4 c3 00 c0       	push   $0xc000c3a4
c00022b8:	6a 43                	push   $0x43
c00022ba:	68 4e c3 00 c0       	push   $0xc000c34e
c00022bf:	e8 14 00 00 00       	call   c00022d8 <panic_spin>
c00022c4:	83 c4 10             	add    $0x10,%esp
  ticks_to_sleep(sleep_ticks);
c00022c7:	83 ec 0c             	sub    $0xc,%esp
c00022ca:	ff 75 f4             	push   -0xc(%ebp)
c00022cd:	e8 95 ff ff ff       	call   c0002267 <ticks_to_sleep>
c00022d2:	83 c4 10             	add    $0x10,%esp
c00022d5:	90                   	nop
c00022d6:	c9                   	leave  
c00022d7:	c3                   	ret    

c00022d8 <panic_spin>:
#include "interrupt.h"
#include "print.h"

// 打印文件名、行号、函数名、条件并使程序悬停
void panic_spin(char *filename, int line, const char *func,
                const char *condition) {
c00022d8:	55                   	push   %ebp
c00022d9:	89 e5                	mov    %esp,%ebp
c00022db:	83 ec 08             	sub    $0x8,%esp
  intr_disable(); // 因为有时候会单独调用 panic_spin，所以在此处关中断
c00022de:	e8 5a f6 ff ff       	call   c000193d <intr_disable>
  put_str("\n\n\n!!!!! error !!!!!\n");
c00022e3:	83 ec 0c             	sub    $0xc,%esp
c00022e6:	68 b0 c3 00 c0       	push   $0xc000c3b0
c00022eb:	e8 40 f7 ff ff       	call   c0001a30 <put_str>
c00022f0:	83 c4 10             	add    $0x10,%esp
  put_str("filename:");
c00022f3:	83 ec 0c             	sub    $0xc,%esp
c00022f6:	68 c6 c3 00 c0       	push   $0xc000c3c6
c00022fb:	e8 30 f7 ff ff       	call   c0001a30 <put_str>
c0002300:	83 c4 10             	add    $0x10,%esp
  put_str(filename);
c0002303:	83 ec 0c             	sub    $0xc,%esp
c0002306:	ff 75 08             	push   0x8(%ebp)
c0002309:	e8 22 f7 ff ff       	call   c0001a30 <put_str>
c000230e:	83 c4 10             	add    $0x10,%esp
  put_str("\n");
c0002311:	83 ec 0c             	sub    $0xc,%esp
c0002314:	68 d0 c3 00 c0       	push   $0xc000c3d0
c0002319:	e8 12 f7 ff ff       	call   c0001a30 <put_str>
c000231e:	83 c4 10             	add    $0x10,%esp

  put_str("line:0x");
c0002321:	83 ec 0c             	sub    $0xc,%esp
c0002324:	68 d2 c3 00 c0       	push   $0xc000c3d2
c0002329:	e8 02 f7 ff ff       	call   c0001a30 <put_str>
c000232e:	83 c4 10             	add    $0x10,%esp
  put_int(line);
c0002331:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002334:	83 ec 0c             	sub    $0xc,%esp
c0002337:	50                   	push   %eax
c0002338:	e8 f0 f7 ff ff       	call   c0001b2d <put_int>
c000233d:	83 c4 10             	add    $0x10,%esp
  put_str("\n");
c0002340:	83 ec 0c             	sub    $0xc,%esp
c0002343:	68 d0 c3 00 c0       	push   $0xc000c3d0
c0002348:	e8 e3 f6 ff ff       	call   c0001a30 <put_str>
c000234d:	83 c4 10             	add    $0x10,%esp

  put_str("function:");
c0002350:	83 ec 0c             	sub    $0xc,%esp
c0002353:	68 da c3 00 c0       	push   $0xc000c3da
c0002358:	e8 d3 f6 ff ff       	call   c0001a30 <put_str>
c000235d:	83 c4 10             	add    $0x10,%esp
  put_str((char *)func);
c0002360:	83 ec 0c             	sub    $0xc,%esp
c0002363:	ff 75 10             	push   0x10(%ebp)
c0002366:	e8 c5 f6 ff ff       	call   c0001a30 <put_str>
c000236b:	83 c4 10             	add    $0x10,%esp
  put_str("\n");
c000236e:	83 ec 0c             	sub    $0xc,%esp
c0002371:	68 d0 c3 00 c0       	push   $0xc000c3d0
c0002376:	e8 b5 f6 ff ff       	call   c0001a30 <put_str>
c000237b:	83 c4 10             	add    $0x10,%esp

  put_str("condition:");
c000237e:	83 ec 0c             	sub    $0xc,%esp
c0002381:	68 e4 c3 00 c0       	push   $0xc000c3e4
c0002386:	e8 a5 f6 ff ff       	call   c0001a30 <put_str>
c000238b:	83 c4 10             	add    $0x10,%esp
  put_str((char *)condition);
c000238e:	83 ec 0c             	sub    $0xc,%esp
c0002391:	ff 75 14             	push   0x14(%ebp)
c0002394:	e8 97 f6 ff ff       	call   c0001a30 <put_str>
c0002399:	83 c4 10             	add    $0x10,%esp
  put_str("\n");
c000239c:	83 ec 0c             	sub    $0xc,%esp
c000239f:	68 d0 c3 00 c0       	push   $0xc000c3d0
c00023a4:	e8 87 f6 ff ff       	call   c0001a30 <put_str>
c00023a9:	83 c4 10             	add    $0x10,%esp
  while (1) {
c00023ac:	eb fe                	jmp    c00023ac <panic_spin+0xd4>

c00023ae <memset>:
#include "debug.h"
#include "global.h"

// 内存区域的数据初始化（内存分配时的数据清零）=>
// 将dst_起始的size个字节置为value
void memset(void *dst_, uint8_t value, uint32_t size) {
c00023ae:	55                   	push   %ebp
c00023af:	89 e5                	mov    %esp,%ebp
c00023b1:	83 ec 28             	sub    $0x28,%esp
c00023b4:	8b 45 0c             	mov    0xc(%ebp),%eax
c00023b7:	88 45 e4             	mov    %al,-0x1c(%ebp)
  ASSERT(dst_ != NULL);
c00023ba:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c00023be:	75 19                	jne    c00023d9 <memset+0x2b>
c00023c0:	68 f0 c3 00 c0       	push   $0xc000c3f0
c00023c5:	68 4c c4 00 c0       	push   $0xc000c44c
c00023ca:	6a 08                	push   $0x8
c00023cc:	68 fd c3 00 c0       	push   $0xc000c3fd
c00023d1:	e8 02 ff ff ff       	call   c00022d8 <panic_spin>
c00023d6:	83 c4 10             	add    $0x10,%esp
  uint8_t *dst = (uint8_t *)dst_;
c00023d9:	8b 45 08             	mov    0x8(%ebp),%eax
c00023dc:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while (size-- > 0) {
c00023df:	eb 0f                	jmp    c00023f0 <memset+0x42>
    *dst++ = value;
c00023e1:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00023e4:	8d 50 01             	lea    0x1(%eax),%edx
c00023e7:	89 55 f4             	mov    %edx,-0xc(%ebp)
c00023ea:	0f b6 55 e4          	movzbl -0x1c(%ebp),%edx
c00023ee:	88 10                	mov    %dl,(%eax)
  while (size-- > 0) {
c00023f0:	8b 45 10             	mov    0x10(%ebp),%eax
c00023f3:	8d 50 ff             	lea    -0x1(%eax),%edx
c00023f6:	89 55 10             	mov    %edx,0x10(%ebp)
c00023f9:	85 c0                	test   %eax,%eax
c00023fb:	75 e4                	jne    c00023e1 <memset+0x33>
  }
}
c00023fd:	90                   	nop
c00023fe:	90                   	nop
c00023ff:	c9                   	leave  
c0002400:	c3                   	ret    

c0002401 <memcpy>:

// 内存数据拷贝=> 终止条件：size
// 将src_起始的size个字节复制到dst_
void memcpy(void *dst_, const void *src_, uint32_t size) {
c0002401:	55                   	push   %ebp
c0002402:	89 e5                	mov    %esp,%ebp
c0002404:	83 ec 18             	sub    $0x18,%esp
  ASSERT(dst_ != NULL && src_ != NULL);
c0002407:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c000240b:	74 06                	je     c0002413 <memcpy+0x12>
c000240d:	83 7d 0c 00          	cmpl   $0x0,0xc(%ebp)
c0002411:	75 19                	jne    c000242c <memcpy+0x2b>
c0002413:	68 0a c4 00 c0       	push   $0xc000c40a
c0002418:	68 54 c4 00 c0       	push   $0xc000c454
c000241d:	6a 12                	push   $0x12
c000241f:	68 fd c3 00 c0       	push   $0xc000c3fd
c0002424:	e8 af fe ff ff       	call   c00022d8 <panic_spin>
c0002429:	83 c4 10             	add    $0x10,%esp
  uint8_t *dst = dst_;
c000242c:	8b 45 08             	mov    0x8(%ebp),%eax
c000242f:	89 45 f4             	mov    %eax,-0xc(%ebp)
  const uint8_t *src = src_;
c0002432:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002435:	89 45 f0             	mov    %eax,-0x10(%ebp)
  while (size-- > 0) {
c0002438:	eb 17                	jmp    c0002451 <memcpy+0x50>
    *dst++ = *src++;
c000243a:	8b 55 f0             	mov    -0x10(%ebp),%edx
c000243d:	8d 42 01             	lea    0x1(%edx),%eax
c0002440:	89 45 f0             	mov    %eax,-0x10(%ebp)
c0002443:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002446:	8d 48 01             	lea    0x1(%eax),%ecx
c0002449:	89 4d f4             	mov    %ecx,-0xc(%ebp)
c000244c:	0f b6 12             	movzbl (%edx),%edx
c000244f:	88 10                	mov    %dl,(%eax)
  while (size-- > 0) {
c0002451:	8b 45 10             	mov    0x10(%ebp),%eax
c0002454:	8d 50 ff             	lea    -0x1(%eax),%edx
c0002457:	89 55 10             	mov    %edx,0x10(%ebp)
c000245a:	85 c0                	test   %eax,%eax
c000245c:	75 dc                	jne    c000243a <memcpy+0x39>
  }
}
c000245e:	90                   	nop
c000245f:	90                   	nop
c0002460:	c9                   	leave  
c0002461:	c3                   	ret    

c0002462 <memcmp>:

// 用于一段内存数据比较=>
// 连续比较以地址a_和b_开头的size个字节，相等返回0，a_>b_返回+1，否则返回−1
int memcmp(const void *a_, const void *b_, uint32_t size) {
c0002462:	55                   	push   %ebp
c0002463:	89 e5                	mov    %esp,%ebp
c0002465:	83 ec 18             	sub    $0x18,%esp
  const char *a = a_;
c0002468:	8b 45 08             	mov    0x8(%ebp),%eax
c000246b:	89 45 f4             	mov    %eax,-0xc(%ebp)
  const char *b = b_;
c000246e:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002471:	89 45 f0             	mov    %eax,-0x10(%ebp)
  ASSERT(a != NULL && b != NULL);
c0002474:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
c0002478:	74 06                	je     c0002480 <memcmp+0x1e>
c000247a:	83 7d f0 00          	cmpl   $0x0,-0x10(%ebp)
c000247e:	75 19                	jne    c0002499 <memcmp+0x37>
c0002480:	68 27 c4 00 c0       	push   $0xc000c427
c0002485:	68 5c c4 00 c0       	push   $0xc000c45c
c000248a:	6a 1f                	push   $0x1f
c000248c:	68 fd c3 00 c0       	push   $0xc000c3fd
c0002491:	e8 42 fe ff ff       	call   c00022d8 <panic_spin>
c0002496:	83 c4 10             	add    $0x10,%esp
  while (size-- > 0) {
c0002499:	eb 36                	jmp    c00024d1 <memcmp+0x6f>
    if (*a != *b) {
c000249b:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000249e:	0f b6 10             	movzbl (%eax),%edx
c00024a1:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00024a4:	0f b6 00             	movzbl (%eax),%eax
c00024a7:	38 c2                	cmp    %al,%dl
c00024a9:	74 1e                	je     c00024c9 <memcmp+0x67>
      return *a > *b ? 1 : -1;
c00024ab:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00024ae:	0f b6 10             	movzbl (%eax),%edx
c00024b1:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00024b4:	0f b6 00             	movzbl (%eax),%eax
c00024b7:	38 c2                	cmp    %al,%dl
c00024b9:	7e 07                	jle    c00024c2 <memcmp+0x60>
c00024bb:	b8 01 00 00 00       	mov    $0x1,%eax
c00024c0:	eb 21                	jmp    c00024e3 <memcmp+0x81>
c00024c2:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c00024c7:	eb 1a                	jmp    c00024e3 <memcmp+0x81>
    }
    a++;
c00024c9:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
    b++;
c00024cd:	83 45 f0 01          	addl   $0x1,-0x10(%ebp)
  while (size-- > 0) {
c00024d1:	8b 45 10             	mov    0x10(%ebp),%eax
c00024d4:	8d 50 ff             	lea    -0x1(%eax),%edx
c00024d7:	89 55 10             	mov    %edx,0x10(%ebp)
c00024da:	85 c0                	test   %eax,%eax
c00024dc:	75 bd                	jne    c000249b <memcmp+0x39>
  }
  return 0;
c00024de:	b8 00 00 00 00       	mov    $0x0,%eax
}
c00024e3:	c9                   	leave  
c00024e4:	c3                   	ret    

c00024e5 <strcpy>:

// 字符串拷贝=> 终止条件：src_处的字符‘0’
// 将字符串从src_复制到dst_
char *strcpy(char *dst_, const char *src_) {
c00024e5:	55                   	push   %ebp
c00024e6:	89 e5                	mov    %esp,%ebp
c00024e8:	83 ec 18             	sub    $0x18,%esp
  ASSERT(dst_ != NULL && src_ != NULL);
c00024eb:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c00024ef:	74 06                	je     c00024f7 <strcpy+0x12>
c00024f1:	83 7d 0c 00          	cmpl   $0x0,0xc(%ebp)
c00024f5:	75 19                	jne    c0002510 <strcpy+0x2b>
c00024f7:	68 0a c4 00 c0       	push   $0xc000c40a
c00024fc:	68 64 c4 00 c0       	push   $0xc000c464
c0002501:	6a 2d                	push   $0x2d
c0002503:	68 fd c3 00 c0       	push   $0xc000c3fd
c0002508:	e8 cb fd ff ff       	call   c00022d8 <panic_spin>
c000250d:	83 c4 10             	add    $0x10,%esp
  char *r = dst_; // 用来返回目的字符串dst_起始地址
c0002510:	8b 45 08             	mov    0x8(%ebp),%eax
c0002513:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while ((*dst_++ = *src_++))
c0002516:	90                   	nop
c0002517:	8b 55 0c             	mov    0xc(%ebp),%edx
c000251a:	8d 42 01             	lea    0x1(%edx),%eax
c000251d:	89 45 0c             	mov    %eax,0xc(%ebp)
c0002520:	8b 45 08             	mov    0x8(%ebp),%eax
c0002523:	8d 48 01             	lea    0x1(%eax),%ecx
c0002526:	89 4d 08             	mov    %ecx,0x8(%ebp)
c0002529:	0f b6 12             	movzbl (%edx),%edx
c000252c:	88 10                	mov    %dl,(%eax)
c000252e:	0f b6 00             	movzbl (%eax),%eax
c0002531:	84 c0                	test   %al,%al
c0002533:	75 e2                	jne    c0002517 <strcpy+0x32>
    ;
  return r;
c0002535:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0002538:	c9                   	leave  
c0002539:	c3                   	ret    

c000253a <strlen>:

// 返回字符串长度
uint32_t strlen(const char *str) {
c000253a:	55                   	push   %ebp
c000253b:	89 e5                	mov    %esp,%ebp
c000253d:	83 ec 18             	sub    $0x18,%esp
  ASSERT(str != NULL);
c0002540:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c0002544:	75 19                	jne    c000255f <strlen+0x25>
c0002546:	68 3e c4 00 c0       	push   $0xc000c43e
c000254b:	68 6c c4 00 c0       	push   $0xc000c46c
c0002550:	6a 36                	push   $0x36
c0002552:	68 fd c3 00 c0       	push   $0xc000c3fd
c0002557:	e8 7c fd ff ff       	call   c00022d8 <panic_spin>
c000255c:	83 c4 10             	add    $0x10,%esp
  const char *p = str;
c000255f:	8b 45 08             	mov    0x8(%ebp),%eax
c0002562:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while (*p++)
c0002565:	90                   	nop
c0002566:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002569:	8d 50 01             	lea    0x1(%eax),%edx
c000256c:	89 55 f4             	mov    %edx,-0xc(%ebp)
c000256f:	0f b6 00             	movzbl (%eax),%eax
c0002572:	84 c0                	test   %al,%al
c0002574:	75 f0                	jne    c0002566 <strlen+0x2c>
    ;
  return (p - str - 1);
c0002576:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002579:	2b 45 08             	sub    0x8(%ebp),%eax
c000257c:	83 e8 01             	sub    $0x1,%eax
}
c000257f:	c9                   	leave  
c0002580:	c3                   	ret    

c0002581 <strcmp>:

// 比较两个字符串，若a_中字符大于b_返回1，相等返回0，否则返回−1
uint8_t strcmp(const char *a, const char *b) {
c0002581:	55                   	push   %ebp
c0002582:	89 e5                	mov    %esp,%ebp
c0002584:	83 ec 08             	sub    $0x8,%esp
  ASSERT(a != NULL && b != NULL);
c0002587:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c000258b:	74 06                	je     c0002593 <strcmp+0x12>
c000258d:	83 7d 0c 00          	cmpl   $0x0,0xc(%ebp)
c0002591:	75 19                	jne    c00025ac <strcmp+0x2b>
c0002593:	68 27 c4 00 c0       	push   $0xc000c427
c0002598:	68 74 c4 00 c0       	push   $0xc000c474
c000259d:	6a 3f                	push   $0x3f
c000259f:	68 fd c3 00 c0       	push   $0xc000c3fd
c00025a4:	e8 2f fd ff ff       	call   c00022d8 <panic_spin>
c00025a9:	83 c4 10             	add    $0x10,%esp
  while (*a != 0 && *a == *b) {
c00025ac:	eb 08                	jmp    c00025b6 <strcmp+0x35>
    a++;
c00025ae:	83 45 08 01          	addl   $0x1,0x8(%ebp)
    b++;
c00025b2:	83 45 0c 01          	addl   $0x1,0xc(%ebp)
  while (*a != 0 && *a == *b) {
c00025b6:	8b 45 08             	mov    0x8(%ebp),%eax
c00025b9:	0f b6 00             	movzbl (%eax),%eax
c00025bc:	84 c0                	test   %al,%al
c00025be:	74 10                	je     c00025d0 <strcmp+0x4f>
c00025c0:	8b 45 08             	mov    0x8(%ebp),%eax
c00025c3:	0f b6 10             	movzbl (%eax),%edx
c00025c6:	8b 45 0c             	mov    0xc(%ebp),%eax
c00025c9:	0f b6 00             	movzbl (%eax),%eax
c00025cc:	38 c2                	cmp    %al,%dl
c00025ce:	74 de                	je     c00025ae <strcmp+0x2d>
  }
  return *a < *b ? -1 : *a > *b;
c00025d0:	8b 45 08             	mov    0x8(%ebp),%eax
c00025d3:	0f b6 10             	movzbl (%eax),%edx
c00025d6:	8b 45 0c             	mov    0xc(%ebp),%eax
c00025d9:	0f b6 00             	movzbl (%eax),%eax
c00025dc:	38 c2                	cmp    %al,%dl
c00025de:	7c 13                	jl     c00025f3 <strcmp+0x72>
c00025e0:	8b 45 08             	mov    0x8(%ebp),%eax
c00025e3:	0f b6 10             	movzbl (%eax),%edx
c00025e6:	8b 45 0c             	mov    0xc(%ebp),%eax
c00025e9:	0f b6 00             	movzbl (%eax),%eax
c00025ec:	38 c2                	cmp    %al,%dl
c00025ee:	0f 9f c0             	setg   %al
c00025f1:	eb 05                	jmp    c00025f8 <strcmp+0x77>
c00025f3:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
}
c00025f8:	c9                   	leave  
c00025f9:	c3                   	ret    

c00025fa <strchr>:

// 从左到右 查找字符串str中首次出现字符ch的地址
char *strchr(const char *str, const uint8_t ch) {
c00025fa:	55                   	push   %ebp
c00025fb:	89 e5                	mov    %esp,%ebp
c00025fd:	83 ec 18             	sub    $0x18,%esp
c0002600:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002603:	88 45 f4             	mov    %al,-0xc(%ebp)
  ASSERT(str != NULL);
c0002606:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c000260a:	75 35                	jne    c0002641 <strchr+0x47>
c000260c:	68 3e c4 00 c0       	push   $0xc000c43e
c0002611:	68 7c c4 00 c0       	push   $0xc000c47c
c0002616:	6a 49                	push   $0x49
c0002618:	68 fd c3 00 c0       	push   $0xc000c3fd
c000261d:	e8 b6 fc ff ff       	call   c00022d8 <panic_spin>
c0002622:	83 c4 10             	add    $0x10,%esp
  while (*str != 0) {
c0002625:	eb 1a                	jmp    c0002641 <strchr+0x47>
    if (*str == ch) {
c0002627:	8b 45 08             	mov    0x8(%ebp),%eax
c000262a:	0f b6 00             	movzbl (%eax),%eax
c000262d:	0f be d0             	movsbl %al,%edx
c0002630:	0f b6 45 f4          	movzbl -0xc(%ebp),%eax
c0002634:	39 c2                	cmp    %eax,%edx
c0002636:	75 05                	jne    c000263d <strchr+0x43>
      return (char *)str;
c0002638:	8b 45 08             	mov    0x8(%ebp),%eax
c000263b:	eb 13                	jmp    c0002650 <strchr+0x56>
    }
    str++;
c000263d:	83 45 08 01          	addl   $0x1,0x8(%ebp)
  while (*str != 0) {
c0002641:	8b 45 08             	mov    0x8(%ebp),%eax
c0002644:	0f b6 00             	movzbl (%eax),%eax
c0002647:	84 c0                	test   %al,%al
c0002649:	75 dc                	jne    c0002627 <strchr+0x2d>
  }
  return NULL;
c000264b:	b8 00 00 00 00       	mov    $0x0,%eax
}
c0002650:	c9                   	leave  
c0002651:	c3                   	ret    

c0002652 <strrchr>:

// 从后往前 查找字符串str中最后一次出现字符ch的地址
char *strrchr(const char *str, const uint8_t ch) {
c0002652:	55                   	push   %ebp
c0002653:	89 e5                	mov    %esp,%ebp
c0002655:	83 ec 28             	sub    $0x28,%esp
c0002658:	8b 45 0c             	mov    0xc(%ebp),%eax
c000265b:	88 45 e4             	mov    %al,-0x1c(%ebp)
  ASSERT(str != NULL);
c000265e:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c0002662:	75 19                	jne    c000267d <strrchr+0x2b>
c0002664:	68 3e c4 00 c0       	push   $0xc000c43e
c0002669:	68 84 c4 00 c0       	push   $0xc000c484
c000266e:	6a 55                	push   $0x55
c0002670:	68 fd c3 00 c0       	push   $0xc000c3fd
c0002675:	e8 5e fc ff ff       	call   c00022d8 <panic_spin>
c000267a:	83 c4 10             	add    $0x10,%esp
  const char *last_char = NULL;
c000267d:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  while (*str != 0) {
c0002684:	eb 1b                	jmp    c00026a1 <strrchr+0x4f>
    if (*str == ch) {
c0002686:	8b 45 08             	mov    0x8(%ebp),%eax
c0002689:	0f b6 00             	movzbl (%eax),%eax
c000268c:	0f be d0             	movsbl %al,%edx
c000268f:	0f b6 45 e4          	movzbl -0x1c(%ebp),%eax
c0002693:	39 c2                	cmp    %eax,%edx
c0002695:	75 06                	jne    c000269d <strrchr+0x4b>
      last_char = str;
c0002697:	8b 45 08             	mov    0x8(%ebp),%eax
c000269a:	89 45 f4             	mov    %eax,-0xc(%ebp)
    }
    str++;
c000269d:	83 45 08 01          	addl   $0x1,0x8(%ebp)
  while (*str != 0) {
c00026a1:	8b 45 08             	mov    0x8(%ebp),%eax
c00026a4:	0f b6 00             	movzbl (%eax),%eax
c00026a7:	84 c0                	test   %al,%al
c00026a9:	75 db                	jne    c0002686 <strrchr+0x34>
  }
  return (char *)last_char;
c00026ab:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c00026ae:	c9                   	leave  
c00026af:	c3                   	ret    

c00026b0 <strcat>:

// 字符串拼接=>
// 将字符串src_拼接到dst_后，返回dst_地址
char *strcat(char *dst_, const char *src_) {
c00026b0:	55                   	push   %ebp
c00026b1:	89 e5                	mov    %esp,%ebp
c00026b3:	83 ec 18             	sub    $0x18,%esp
  ASSERT(dst_ != NULL && src_ != NULL);
c00026b6:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c00026ba:	74 06                	je     c00026c2 <strcat+0x12>
c00026bc:	83 7d 0c 00          	cmpl   $0x0,0xc(%ebp)
c00026c0:	75 19                	jne    c00026db <strcat+0x2b>
c00026c2:	68 0a c4 00 c0       	push   $0xc000c40a
c00026c7:	68 8c c4 00 c0       	push   $0xc000c48c
c00026cc:	6a 63                	push   $0x63
c00026ce:	68 fd c3 00 c0       	push   $0xc000c3fd
c00026d3:	e8 00 fc ff ff       	call   c00022d8 <panic_spin>
c00026d8:	83 c4 10             	add    $0x10,%esp
  char *str = dst_;
c00026db:	8b 45 08             	mov    0x8(%ebp),%eax
c00026de:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while (*str++)
c00026e1:	90                   	nop
c00026e2:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00026e5:	8d 50 01             	lea    0x1(%eax),%edx
c00026e8:	89 55 f4             	mov    %edx,-0xc(%ebp)
c00026eb:	0f b6 00             	movzbl (%eax),%eax
c00026ee:	84 c0                	test   %al,%al
c00026f0:	75 f0                	jne    c00026e2 <strcat+0x32>
    ;
  --str;
c00026f2:	83 6d f4 01          	subl   $0x1,-0xc(%ebp)
  while ((*str++ = *src_++)) // 当*str被赋值0时
c00026f6:	90                   	nop
c00026f7:	8b 55 0c             	mov    0xc(%ebp),%edx
c00026fa:	8d 42 01             	lea    0x1(%edx),%eax
c00026fd:	89 45 0c             	mov    %eax,0xc(%ebp)
c0002700:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002703:	8d 48 01             	lea    0x1(%eax),%ecx
c0002706:	89 4d f4             	mov    %ecx,-0xc(%ebp)
c0002709:	0f b6 12             	movzbl (%edx),%edx
c000270c:	88 10                	mov    %dl,(%eax)
c000270e:	0f b6 00             	movzbl (%eax),%eax
c0002711:	84 c0                	test   %al,%al
c0002713:	75 e2                	jne    c00026f7 <strcat+0x47>
    ; //也就是表达式不成立，正好添加了字符串结尾的0
  return dst_;
c0002715:	8b 45 08             	mov    0x8(%ebp),%eax
}
c0002718:	c9                   	leave  
c0002719:	c3                   	ret    

c000271a <strchrs>:

// 在字符串str中查找字符ch出现的次数
uint32_t strchrs(const char *str, uint8_t ch) {
c000271a:	55                   	push   %ebp
c000271b:	89 e5                	mov    %esp,%ebp
c000271d:	83 ec 28             	sub    $0x28,%esp
c0002720:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002723:	88 45 e4             	mov    %al,-0x1c(%ebp)
  ASSERT(str != NULL);
c0002726:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c000272a:	75 19                	jne    c0002745 <strchrs+0x2b>
c000272c:	68 3e c4 00 c0       	push   $0xc000c43e
c0002731:	68 94 c4 00 c0       	push   $0xc000c494
c0002736:	6a 6f                	push   $0x6f
c0002738:	68 fd c3 00 c0       	push   $0xc000c3fd
c000273d:	e8 96 fb ff ff       	call   c00022d8 <panic_spin>
c0002742:	83 c4 10             	add    $0x10,%esp
  uint32_t ch_cnt = 0;
c0002745:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  const char *p = str;
c000274c:	8b 45 08             	mov    0x8(%ebp),%eax
c000274f:	89 45 f0             	mov    %eax,-0x10(%ebp)
  while (*p != 0) {
c0002752:	eb 19                	jmp    c000276d <strchrs+0x53>
    if (*p == ch) {
c0002754:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002757:	0f b6 00             	movzbl (%eax),%eax
c000275a:	0f be d0             	movsbl %al,%edx
c000275d:	0f b6 45 e4          	movzbl -0x1c(%ebp),%eax
c0002761:	39 c2                	cmp    %eax,%edx
c0002763:	75 04                	jne    c0002769 <strchrs+0x4f>
      ch_cnt++;
c0002765:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
    }
    p++;
c0002769:	83 45 f0 01          	addl   $0x1,-0x10(%ebp)
  while (*p != 0) {
c000276d:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002770:	0f b6 00             	movzbl (%eax),%eax
c0002773:	84 c0                	test   %al,%al
c0002775:	75 dd                	jne    c0002754 <strchrs+0x3a>
  }
  return ch_cnt;
c0002777:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c000277a:	c9                   	leave  
c000277b:	c3                   	ret    

c000277c <bitmap_init>:
#include "print.h"
#include "stdint.h"
#include "string.h"

// 初始化位图btmp
void bitmap_init(struct bitmap *btmp) {
c000277c:	55                   	push   %ebp
c000277d:	89 e5                	mov    %esp,%ebp
c000277f:	83 ec 08             	sub    $0x8,%esp
  memset(btmp->bits, 0, btmp->btmp_bytes_len);
c0002782:	8b 45 08             	mov    0x8(%ebp),%eax
c0002785:	8b 10                	mov    (%eax),%edx
c0002787:	8b 45 08             	mov    0x8(%ebp),%eax
c000278a:	8b 40 04             	mov    0x4(%eax),%eax
c000278d:	83 ec 04             	sub    $0x4,%esp
c0002790:	52                   	push   %edx
c0002791:	6a 00                	push   $0x0
c0002793:	50                   	push   %eax
c0002794:	e8 15 fc ff ff       	call   c00023ae <memset>
c0002799:	83 c4 10             	add    $0x10,%esp
}
c000279c:	90                   	nop
c000279d:	c9                   	leave  
c000279e:	c3                   	ret    

c000279f <bitmap_scan_test>:

// 判断bit_idx位是否为1，为1返回true，否则返回false
bool bitmap_scan_test(struct bitmap *btmp, uint32_t bit_idx) {
c000279f:	55                   	push   %ebp
c00027a0:	89 e5                	mov    %esp,%ebp
c00027a2:	53                   	push   %ebx
c00027a3:	83 ec 10             	sub    $0x10,%esp
  uint32_t byte_idx = bit_idx / 8; // 向下取整用于索引数组下标
c00027a6:	8b 45 0c             	mov    0xc(%ebp),%eax
c00027a9:	c1 e8 03             	shr    $0x3,%eax
c00027ac:	89 45 f8             	mov    %eax,-0x8(%ebp)
  uint32_t bit_odd = bit_idx % 8;  //取余用于索引数组内的位
c00027af:	8b 45 0c             	mov    0xc(%ebp),%eax
c00027b2:	83 e0 07             	and    $0x7,%eax
c00027b5:	89 45 f4             	mov    %eax,-0xc(%ebp)
  return (btmp->bits[byte_idx] & (BITMAP_MASK << bit_odd));
c00027b8:	8b 45 08             	mov    0x8(%ebp),%eax
c00027bb:	8b 50 04             	mov    0x4(%eax),%edx
c00027be:	8b 45 f8             	mov    -0x8(%ebp),%eax
c00027c1:	01 d0                	add    %edx,%eax
c00027c3:	0f b6 00             	movzbl (%eax),%eax
c00027c6:	0f b6 d0             	movzbl %al,%edx
c00027c9:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00027cc:	bb 01 00 00 00       	mov    $0x1,%ebx
c00027d1:	89 c1                	mov    %eax,%ecx
c00027d3:	d3 e3                	shl    %cl,%ebx
c00027d5:	89 d8                	mov    %ebx,%eax
c00027d7:	21 d0                	and    %edx,%eax
}
c00027d9:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c00027dc:	c9                   	leave  
c00027dd:	c3                   	ret    

c00027de <bitmap_scan>:

// 在位图中申请cnt个位，成功返回其起始下标地址，失败返回-1
int bitmap_scan(struct bitmap *btmp, uint32_t cnt) {
c00027de:	55                   	push   %ebp
c00027df:	89 e5                	mov    %esp,%ebp
c00027e1:	83 ec 28             	sub    $0x28,%esp
  uint32_t idx_byte = 0; //用于记录空闲位所在字节索引
c00027e4:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  //逐个字节比较
  while ((0xff == btmp->bits[idx_byte]) && (idx_byte < btmp->btmp_bytes_len)) {
c00027eb:	eb 04                	jmp    c00027f1 <bitmap_scan+0x13>
    // 0xff表示该字节内已无空闲位，继续下一个字节
    idx_byte++;
c00027ed:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
  while ((0xff == btmp->bits[idx_byte]) && (idx_byte < btmp->btmp_bytes_len)) {
c00027f1:	8b 45 08             	mov    0x8(%ebp),%eax
c00027f4:	8b 50 04             	mov    0x4(%eax),%edx
c00027f7:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00027fa:	01 d0                	add    %edx,%eax
c00027fc:	0f b6 00             	movzbl (%eax),%eax
c00027ff:	3c ff                	cmp    $0xff,%al
c0002801:	75 0a                	jne    c000280d <bitmap_scan+0x2f>
c0002803:	8b 45 08             	mov    0x8(%ebp),%eax
c0002806:	8b 00                	mov    (%eax),%eax
c0002808:	39 45 f4             	cmp    %eax,-0xc(%ebp)
c000280b:	72 e0                	jb     c00027ed <bitmap_scan+0xf>
  }

  ASSERT(idx_byte < btmp->btmp_bytes_len);
c000280d:	8b 45 08             	mov    0x8(%ebp),%eax
c0002810:	8b 00                	mov    (%eax),%eax
c0002812:	39 45 f4             	cmp    %eax,-0xc(%ebp)
c0002815:	72 19                	jb     c0002830 <bitmap_scan+0x52>
c0002817:	68 9c c4 00 c0       	push   $0xc000c49c
c000281c:	68 f0 c4 00 c0       	push   $0xc000c4f0
c0002821:	6a 1d                	push   $0x1d
c0002823:	68 bc c4 00 c0       	push   $0xc000c4bc
c0002828:	e8 ab fa ff ff       	call   c00022d8 <panic_spin>
c000282d:	83 c4 10             	add    $0x10,%esp
  if (idx_byte == btmp->btmp_bytes_len) { //该内存池已找不到空间
c0002830:	8b 45 08             	mov    0x8(%ebp),%eax
c0002833:	8b 00                	mov    (%eax),%eax
c0002835:	39 45 f4             	cmp    %eax,-0xc(%ebp)
c0002838:	75 0a                	jne    c0002844 <bitmap_scan+0x66>
    return -1;
c000283a:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000283f:	e9 c3 00 00 00       	jmp    c0002907 <bitmap_scan+0x129>
  }

  //在位图数组范围内的某字节内找到了空闲位，在该字节内逐位比对，返回空闲位的索引
  int idx_bit = 0; // 字节内的索引(范围0-7)
c0002844:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
  while ((uint8_t)(BITMAP_MASK << idx_bit) & btmp->bits[idx_byte]) {
c000284b:	eb 04                	jmp    c0002851 <bitmap_scan+0x73>
    idx_bit++;
c000284d:	83 45 f0 01          	addl   $0x1,-0x10(%ebp)
  while ((uint8_t)(BITMAP_MASK << idx_bit) & btmp->bits[idx_byte]) {
c0002851:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002854:	ba 01 00 00 00       	mov    $0x1,%edx
c0002859:	89 c1                	mov    %eax,%ecx
c000285b:	d3 e2                	shl    %cl,%edx
c000285d:	89 d0                	mov    %edx,%eax
c000285f:	89 c1                	mov    %eax,%ecx
c0002861:	8b 45 08             	mov    0x8(%ebp),%eax
c0002864:	8b 50 04             	mov    0x4(%eax),%edx
c0002867:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000286a:	01 d0                	add    %edx,%eax
c000286c:	0f b6 00             	movzbl (%eax),%eax
c000286f:	21 c8                	and    %ecx,%eax
c0002871:	84 c0                	test   %al,%al
c0002873:	75 d8                	jne    c000284d <bitmap_scan+0x6f>
  }

  int bit_idx_start = idx_byte * 8 + idx_bit; // 空闲位在位图内的下标
c0002875:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002878:	8d 14 c5 00 00 00 00 	lea    0x0(,%eax,8),%edx
c000287f:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002882:	01 d0                	add    %edx,%eax
c0002884:	89 45 ec             	mov    %eax,-0x14(%ebp)
  if (cnt == 1) {
c0002887:	83 7d 0c 01          	cmpl   $0x1,0xc(%ebp)
c000288b:	75 05                	jne    c0002892 <bitmap_scan+0xb4>
    return bit_idx_start;
c000288d:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002890:	eb 75                	jmp    c0002907 <bitmap_scan+0x129>
  }

  uint32_t bit_left = (btmp->btmp_bytes_len * 8 - bit_idx_start);
c0002892:	8b 45 08             	mov    0x8(%ebp),%eax
c0002895:	8b 00                	mov    (%eax),%eax
c0002897:	c1 e0 03             	shl    $0x3,%eax
c000289a:	8b 55 ec             	mov    -0x14(%ebp),%edx
c000289d:	29 d0                	sub    %edx,%eax
c000289f:	89 45 e8             	mov    %eax,-0x18(%ebp)
  // 记录还有多少位可以判断
  uint32_t next_bit = bit_idx_start + 1;
c00028a2:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00028a5:	83 c0 01             	add    $0x1,%eax
c00028a8:	89 45 e4             	mov    %eax,-0x1c(%ebp)
  uint32_t count = 1; //用于记录找到的空闲位数
c00028ab:	c7 45 e0 01 00 00 00 	movl   $0x1,-0x20(%ebp)

  bit_idx_start = -1; // 先将其置为-1，若找不到连续的位置就直接返回
c00028b2:	c7 45 ec ff ff ff ff 	movl   $0xffffffff,-0x14(%ebp)
  while (bit_left-- > 0) {
c00028b9:	eb 3c                	jmp    c00028f7 <bitmap_scan+0x119>
    if (!(bitmap_scan_test(btmp, next_bit))) { //如果next_bit为0
c00028bb:	83 ec 08             	sub    $0x8,%esp
c00028be:	ff 75 e4             	push   -0x1c(%ebp)
c00028c1:	ff 75 08             	push   0x8(%ebp)
c00028c4:	e8 d6 fe ff ff       	call   c000279f <bitmap_scan_test>
c00028c9:	83 c4 10             	add    $0x10,%esp
c00028cc:	85 c0                	test   %eax,%eax
c00028ce:	75 06                	jne    c00028d6 <bitmap_scan+0xf8>
      count++;
c00028d0:	83 45 e0 01          	addl   $0x1,-0x20(%ebp)
c00028d4:	eb 07                	jmp    c00028dd <bitmap_scan+0xff>
    } else {
      count = 0;
c00028d6:	c7 45 e0 00 00 00 00 	movl   $0x0,-0x20(%ebp)
    }
    if (count == cnt) { // 若找到连续的cnt个空位
c00028dd:	8b 45 e0             	mov    -0x20(%ebp),%eax
c00028e0:	3b 45 0c             	cmp    0xc(%ebp),%eax
c00028e3:	75 0e                	jne    c00028f3 <bitmap_scan+0x115>
      bit_idx_start = next_bit - cnt + 1;
c00028e5:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c00028e8:	2b 45 0c             	sub    0xc(%ebp),%eax
c00028eb:	83 c0 01             	add    $0x1,%eax
c00028ee:	89 45 ec             	mov    %eax,-0x14(%ebp)
      break;
c00028f1:	eb 11                	jmp    c0002904 <bitmap_scan+0x126>
    }
    next_bit++;
c00028f3:	83 45 e4 01          	addl   $0x1,-0x1c(%ebp)
  while (bit_left-- > 0) {
c00028f7:	8b 45 e8             	mov    -0x18(%ebp),%eax
c00028fa:	8d 50 ff             	lea    -0x1(%eax),%edx
c00028fd:	89 55 e8             	mov    %edx,-0x18(%ebp)
c0002900:	85 c0                	test   %eax,%eax
c0002902:	75 b7                	jne    c00028bb <bitmap_scan+0xdd>
  }
  return bit_idx_start;
c0002904:	8b 45 ec             	mov    -0x14(%ebp),%eax
}
c0002907:	c9                   	leave  
c0002908:	c3                   	ret    

c0002909 <bitmap_set>:

// 将位图的btmp的bit_idx位设置为value
void bitmap_set(struct bitmap *btmp, uint32_t bit_idx, int8_t value) {
c0002909:	55                   	push   %ebp
c000290a:	89 e5                	mov    %esp,%ebp
c000290c:	53                   	push   %ebx
c000290d:	83 ec 24             	sub    $0x24,%esp
c0002910:	8b 45 10             	mov    0x10(%ebp),%eax
c0002913:	88 45 e4             	mov    %al,-0x1c(%ebp)
  ASSERT((value == 0) || (value == 1));
c0002916:	80 7d e4 00          	cmpb   $0x0,-0x1c(%ebp)
c000291a:	74 1f                	je     c000293b <bitmap_set+0x32>
c000291c:	80 7d e4 01          	cmpb   $0x1,-0x1c(%ebp)
c0002920:	74 19                	je     c000293b <bitmap_set+0x32>
c0002922:	68 d0 c4 00 c0       	push   $0xc000c4d0
c0002927:	68 fc c4 00 c0       	push   $0xc000c4fc
c000292c:	6a 44                	push   $0x44
c000292e:	68 bc c4 00 c0       	push   $0xc000c4bc
c0002933:	e8 a0 f9 ff ff       	call   c00022d8 <panic_spin>
c0002938:	83 c4 10             	add    $0x10,%esp
  uint32_t byte_idx = bit_idx / 8; //向下取整用于索引数组下标
c000293b:	8b 45 0c             	mov    0xc(%ebp),%eax
c000293e:	c1 e8 03             	shr    $0x3,%eax
c0002941:	89 45 f4             	mov    %eax,-0xc(%ebp)
  uint32_t bit_odd = bit_idx % 8;  // 取余用于索引数组内的位
c0002944:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002947:	83 e0 07             	and    $0x7,%eax
c000294a:	89 45 f0             	mov    %eax,-0x10(%ebp)

  // 一般用0x1这样的数对字节中的位操作，将1任意移动后再取反，或者先取反再移位，可用来对位置0操作
  if (value) { // value==1
c000294d:	80 7d e4 00          	cmpb   $0x0,-0x1c(%ebp)
c0002951:	74 33                	je     c0002986 <bitmap_set+0x7d>
    btmp->bits[byte_idx] |= (BITMAP_MASK << bit_odd);
c0002953:	8b 45 08             	mov    0x8(%ebp),%eax
c0002956:	8b 50 04             	mov    0x4(%eax),%edx
c0002959:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000295c:	01 d0                	add    %edx,%eax
c000295e:	0f b6 00             	movzbl (%eax),%eax
c0002961:	89 c3                	mov    %eax,%ebx
c0002963:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002966:	ba 01 00 00 00       	mov    $0x1,%edx
c000296b:	89 c1                	mov    %eax,%ecx
c000296d:	d3 e2                	shl    %cl,%edx
c000296f:	89 d0                	mov    %edx,%eax
c0002971:	09 c3                	or     %eax,%ebx
c0002973:	89 d9                	mov    %ebx,%ecx
c0002975:	8b 45 08             	mov    0x8(%ebp),%eax
c0002978:	8b 50 04             	mov    0x4(%eax),%edx
c000297b:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000297e:	01 d0                	add    %edx,%eax
c0002980:	89 ca                	mov    %ecx,%edx
c0002982:	88 10                	mov    %dl,(%eax)
  } else {
    btmp->bits[byte_idx] &= ~(BITMAP_MASK << bit_odd);
  }
c0002984:	eb 33                	jmp    c00029b9 <bitmap_set+0xb0>
    btmp->bits[byte_idx] &= ~(BITMAP_MASK << bit_odd);
c0002986:	8b 45 08             	mov    0x8(%ebp),%eax
c0002989:	8b 50 04             	mov    0x4(%eax),%edx
c000298c:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000298f:	01 d0                	add    %edx,%eax
c0002991:	0f b6 00             	movzbl (%eax),%eax
c0002994:	89 c3                	mov    %eax,%ebx
c0002996:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002999:	ba 01 00 00 00       	mov    $0x1,%edx
c000299e:	89 c1                	mov    %eax,%ecx
c00029a0:	d3 e2                	shl    %cl,%edx
c00029a2:	89 d0                	mov    %edx,%eax
c00029a4:	f7 d0                	not    %eax
c00029a6:	21 c3                	and    %eax,%ebx
c00029a8:	89 d9                	mov    %ebx,%ecx
c00029aa:	8b 45 08             	mov    0x8(%ebp),%eax
c00029ad:	8b 50 04             	mov    0x4(%eax),%edx
c00029b0:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00029b3:	01 d0                	add    %edx,%eax
c00029b5:	89 ca                	mov    %ecx,%edx
c00029b7:	88 10                	mov    %dl,(%eax)
c00029b9:	90                   	nop
c00029ba:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c00029bd:	c9                   	leave  
c00029be:	c3                   	ret    

c00029bf <pte_ptr>:
struct mem_block_desc k_block_descs[DESC_CNT]; // 内核内存块描述符数组
struct pool kernel_pool, user_pool;
struct virtual_addr kernel_vaddr; // 用来给内核分配虚拟地址

// 得到虚拟地址对应的pte指针
uint32_t *pte_ptr(uint32_t vaddr) {
c00029bf:	55                   	push   %ebp
c00029c0:	89 e5                	mov    %esp,%ebp
c00029c2:	83 ec 10             	sub    $0x10,%esp
  /* 先访问到页表自己
   * 再用页目录项 pde（页目录内页表的索引）作为 pte 的索引访问到页表
   * 再用 pte 的索引作为页内偏移
   */
  uint32_t *pte = (uint32_t *)(0xffc00000 + ((vaddr & 0xffc00000) >> 10) +
c00029c5:	8b 45 08             	mov    0x8(%ebp),%eax
c00029c8:	c1 e8 0a             	shr    $0xa,%eax
c00029cb:	25 00 f0 3f 00       	and    $0x3ff000,%eax
c00029d0:	89 c2                	mov    %eax,%edx
                               PTE_IDX(vaddr) * 4);
c00029d2:	8b 45 08             	mov    0x8(%ebp),%eax
c00029d5:	c1 e8 0c             	shr    $0xc,%eax
c00029d8:	25 ff 03 00 00       	and    $0x3ff,%eax
c00029dd:	c1 e0 02             	shl    $0x2,%eax
  uint32_t *pte = (uint32_t *)(0xffc00000 + ((vaddr & 0xffc00000) >> 10) +
c00029e0:	01 d0                	add    %edx,%eax
c00029e2:	2d 00 00 40 00       	sub    $0x400000,%eax
c00029e7:	89 45 fc             	mov    %eax,-0x4(%ebp)
  return pte;
c00029ea:	8b 45 fc             	mov    -0x4(%ebp),%eax
}
c00029ed:	c9                   	leave  
c00029ee:	c3                   	ret    

c00029ef <pde_ptr>:

// 得到虚拟地址对应的pde指针
uint32_t *pde_ptr(uint32_t vaddr) {
c00029ef:	55                   	push   %ebp
c00029f0:	89 e5                	mov    %esp,%ebp
c00029f2:	83 ec 10             	sub    $0x10,%esp
  // 0xfffff用来访问到页表本身所在的地址
  uint32_t *pde = (uint32_t *)((0xfffff000) + PDE_IDX(vaddr) * 4);
c00029f5:	8b 45 08             	mov    0x8(%ebp),%eax
c00029f8:	c1 e8 16             	shr    $0x16,%eax
c00029fb:	05 00 fc ff 3f       	add    $0x3ffffc00,%eax
c0002a00:	c1 e0 02             	shl    $0x2,%eax
c0002a03:	89 45 fc             	mov    %eax,-0x4(%ebp)
  return pde;
c0002a06:	8b 45 fc             	mov    -0x4(%ebp),%eax
}
c0002a09:	c9                   	leave  
c0002a0a:	c3                   	ret    

c0002a0b <addr_v2p>:

// 得到vaddr映射的物理地址
uint32_t addr_v2p(uint32_t vaddr) {
c0002a0b:	55                   	push   %ebp
c0002a0c:	89 e5                	mov    %esp,%ebp
c0002a0e:	83 ec 10             	sub    $0x10,%esp
  uint32_t *pte = pte_ptr(vaddr);
c0002a11:	ff 75 08             	push   0x8(%ebp)
c0002a14:	e8 a6 ff ff ff       	call   c00029bf <pte_ptr>
c0002a19:	83 c4 04             	add    $0x4,%esp
c0002a1c:	89 45 fc             	mov    %eax,-0x4(%ebp)
  return ((*pte & 0xfffff000) +
c0002a1f:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0002a22:	8b 00                	mov    (%eax),%eax
c0002a24:	25 00 f0 ff ff       	and    $0xfffff000,%eax
c0002a29:	89 c2                	mov    %eax,%edx
          (vaddr & 0x00000fff)); // 去掉页表物理地址低12位属性 + vaddr低12位
c0002a2b:	8b 45 08             	mov    0x8(%ebp),%eax
c0002a2e:	25 ff 0f 00 00       	and    $0xfff,%eax
  return ((*pte & 0xfffff000) +
c0002a33:	09 d0                	or     %edx,%eax
}
c0002a35:	c9                   	leave  
c0002a36:	c3                   	ret    

c0002a37 <arena2block>:

// 返回arena中第idx个内存块的地址
static struct mem_block *arena2block(struct arena *a, uint32_t idx) {
c0002a37:	55                   	push   %ebp
c0002a38:	89 e5                	mov    %esp,%ebp
  return (struct mem_block *)((uint32_t)a + sizeof(struct arena) +
                              idx * a->desc->block_size);
c0002a3a:	8b 45 08             	mov    0x8(%ebp),%eax
c0002a3d:	8b 00                	mov    (%eax),%eax
c0002a3f:	8b 00                	mov    (%eax),%eax
c0002a41:	0f af 45 0c          	imul   0xc(%ebp),%eax
c0002a45:	89 c2                	mov    %eax,%edx
  return (struct mem_block *)((uint32_t)a + sizeof(struct arena) +
c0002a47:	8b 45 08             	mov    0x8(%ebp),%eax
c0002a4a:	01 d0                	add    %edx,%eax
c0002a4c:	83 c0 0c             	add    $0xc,%eax
}
c0002a4f:	5d                   	pop    %ebp
c0002a50:	c3                   	ret    

c0002a51 <block2arena>:

// 返回内存块b所在的arena地址
static struct arena *block2arena(struct mem_block *b) {
c0002a51:	55                   	push   %ebp
c0002a52:	89 e5                	mov    %esp,%ebp
  return (struct arena *)((uint32_t)b & 0xfffff000);
c0002a54:	8b 45 08             	mov    0x8(%ebp),%eax
c0002a57:	25 00 f0 ff ff       	and    $0xfffff000,%eax
}
c0002a5c:	5d                   	pop    %ebp
c0002a5d:	c3                   	ret    

c0002a5e <vaddr_get>:

// --------------------------------------------------------------------------------------------

// 在虚拟内存池（pf指定类型）中申请pg_cnt个虚拟页p *(struct arena*)0xc0101000
static void *vaddr_get(enum pool_flags pf, uint32_t pg_cnt) {
c0002a5e:	55                   	push   %ebp
c0002a5f:	89 e5                	mov    %esp,%ebp
c0002a61:	83 ec 18             	sub    $0x18,%esp
  int vaddr_start = 0, bit_idx_start = -1;
c0002a64:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
c0002a6b:	c7 45 ec ff ff ff ff 	movl   $0xffffffff,-0x14(%ebp)
  uint32_t cnt = 0;
c0002a72:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)

  if (pf == PF_KERNEL) {
c0002a79:	83 7d 08 01          	cmpl   $0x1,0x8(%ebp)
c0002a7d:	75 65                	jne    c0002ae4 <vaddr_get+0x86>
    bit_idx_start = bitmap_scan(&kernel_vaddr.vaddr_bitmap, pg_cnt);
c0002a7f:	83 ec 08             	sub    $0x8,%esp
c0002a82:	ff 75 0c             	push   0xc(%ebp)
c0002a85:	68 ec 1a 01 c0       	push   $0xc0011aec
c0002a8a:	e8 4f fd ff ff       	call   c00027de <bitmap_scan>
c0002a8f:	83 c4 10             	add    $0x10,%esp
c0002a92:	89 45 ec             	mov    %eax,-0x14(%ebp)
    if (bit_idx_start == -1) {
c0002a95:	83 7d ec ff          	cmpl   $0xffffffff,-0x14(%ebp)
c0002a99:	75 2b                	jne    c0002ac6 <vaddr_get+0x68>
      return NULL; // 失败
c0002a9b:	b8 00 00 00 00       	mov    $0x0,%eax
c0002aa0:	e9 ce 00 00 00       	jmp    c0002b73 <vaddr_get+0x115>
    }
    while (cnt < pg_cnt) {
      bitmap_set(&kernel_vaddr.vaddr_bitmap, bit_idx_start + cnt++, 1);
c0002aa5:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002aa8:	8d 50 01             	lea    0x1(%eax),%edx
c0002aab:	89 55 f0             	mov    %edx,-0x10(%ebp)
c0002aae:	8b 55 ec             	mov    -0x14(%ebp),%edx
c0002ab1:	01 d0                	add    %edx,%eax
c0002ab3:	83 ec 04             	sub    $0x4,%esp
c0002ab6:	6a 01                	push   $0x1
c0002ab8:	50                   	push   %eax
c0002ab9:	68 ec 1a 01 c0       	push   $0xc0011aec
c0002abe:	e8 46 fe ff ff       	call   c0002909 <bitmap_set>
c0002ac3:	83 c4 10             	add    $0x10,%esp
    while (cnt < pg_cnt) {
c0002ac6:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002ac9:	3b 45 0c             	cmp    0xc(%ebp),%eax
c0002acc:	72 d7                	jb     c0002aa5 <vaddr_get+0x47>
    }
    // 将bit_idx_start转为虚拟地址
    vaddr_start = kernel_vaddr.vaddr_start + bit_idx_start * PG_SIZE;
c0002ace:	8b 15 f4 1a 01 c0    	mov    0xc0011af4,%edx
c0002ad4:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002ad7:	c1 e0 0c             	shl    $0xc,%eax
c0002ada:	01 d0                	add    %edx,%eax
c0002adc:	89 45 f4             	mov    %eax,-0xc(%ebp)
c0002adf:	e9 8c 00 00 00       	jmp    c0002b70 <vaddr_get+0x112>
  } else {
    struct task_struct *cur = running_thread();
c0002ae4:	e8 26 10 00 00       	call   c0003b0f <running_thread>
c0002ae9:	89 45 e8             	mov    %eax,-0x18(%ebp)
    bit_idx_start = bitmap_scan(&cur->userprog_vaddr.vaddr_bitmap, pg_cnt);
c0002aec:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002aef:	83 c0 38             	add    $0x38,%eax
c0002af2:	83 ec 08             	sub    $0x8,%esp
c0002af5:	ff 75 0c             	push   0xc(%ebp)
c0002af8:	50                   	push   %eax
c0002af9:	e8 e0 fc ff ff       	call   c00027de <bitmap_scan>
c0002afe:	83 c4 10             	add    $0x10,%esp
c0002b01:	89 45 ec             	mov    %eax,-0x14(%ebp)
    if (bit_idx_start == -1) {
c0002b04:	83 7d ec ff          	cmpl   $0xffffffff,-0x14(%ebp)
c0002b08:	75 2a                	jne    c0002b34 <vaddr_get+0xd6>
      return NULL;
c0002b0a:	b8 00 00 00 00       	mov    $0x0,%eax
c0002b0f:	eb 62                	jmp    c0002b73 <vaddr_get+0x115>
    }

    while (cnt < pg_cnt) {
      bitmap_set(&cur->userprog_vaddr.vaddr_bitmap, bit_idx_start + cnt++, 1);
c0002b11:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002b14:	8d 50 01             	lea    0x1(%eax),%edx
c0002b17:	89 55 f0             	mov    %edx,-0x10(%ebp)
c0002b1a:	8b 55 ec             	mov    -0x14(%ebp),%edx
c0002b1d:	01 c2                	add    %eax,%edx
c0002b1f:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002b22:	83 c0 38             	add    $0x38,%eax
c0002b25:	83 ec 04             	sub    $0x4,%esp
c0002b28:	6a 01                	push   $0x1
c0002b2a:	52                   	push   %edx
c0002b2b:	50                   	push   %eax
c0002b2c:	e8 d8 fd ff ff       	call   c0002909 <bitmap_set>
c0002b31:	83 c4 10             	add    $0x10,%esp
    while (cnt < pg_cnt) {
c0002b34:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002b37:	3b 45 0c             	cmp    0xc(%ebp),%eax
c0002b3a:	72 d5                	jb     c0002b11 <vaddr_get+0xb3>
    }
    vaddr_start = cur->userprog_vaddr.vaddr_start + bit_idx_start * PG_SIZE;
c0002b3c:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002b3f:	8b 50 40             	mov    0x40(%eax),%edx
c0002b42:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002b45:	c1 e0 0c             	shl    $0xc,%eax
c0002b48:	01 d0                	add    %edx,%eax
c0002b4a:	89 45 f4             	mov    %eax,-0xc(%ebp)

    // (0xc0000000-PG_SIZE)-> 用户3级栈
    ASSERT((uint32_t)vaddr_start < (0xc0000000 - PG_SIZE));
c0002b4d:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002b50:	3d ff ef ff bf       	cmp    $0xbfffefff,%eax
c0002b55:	76 19                	jbe    c0002b70 <vaddr_get+0x112>
c0002b57:	68 08 c5 00 c0       	push   $0xc000c508
c0002b5c:	68 74 c8 00 c0       	push   $0xc000c874
c0002b61:	6a 6d                	push   $0x6d
c0002b63:	68 37 c5 00 c0       	push   $0xc000c537
c0002b68:	e8 6b f7 ff ff       	call   c00022d8 <panic_spin>
c0002b6d:	83 c4 10             	add    $0x10,%esp
  }
  return (void *)vaddr_start;
c0002b70:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0002b73:	c9                   	leave  
c0002b74:	c3                   	ret    

c0002b75 <palloc>:

// 在m_pool指向的物理内存池中分配1个物理页
static void *palloc(struct pool *m_pool) {
c0002b75:	55                   	push   %ebp
c0002b76:	89 e5                	mov    %esp,%ebp
c0002b78:	83 ec 18             	sub    $0x18,%esp
  /* 扫描或设置位图要保证原子操作 */
  int bit_idx = bitmap_scan(&m_pool->pool_bitmap, 1); // 找一个物理页面
c0002b7b:	8b 45 08             	mov    0x8(%ebp),%eax
c0002b7e:	83 ec 08             	sub    $0x8,%esp
c0002b81:	6a 01                	push   $0x1
c0002b83:	50                   	push   %eax
c0002b84:	e8 55 fc ff ff       	call   c00027de <bitmap_scan>
c0002b89:	83 c4 10             	add    $0x10,%esp
c0002b8c:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (bit_idx == -1) {
c0002b8f:	83 7d f4 ff          	cmpl   $0xffffffff,-0xc(%ebp)
c0002b93:	75 07                	jne    c0002b9c <palloc+0x27>
    return NULL; // 失败
c0002b95:	b8 00 00 00 00       	mov    $0x0,%eax
c0002b9a:	eb 2b                	jmp    c0002bc7 <palloc+0x52>
  }
  bitmap_set(&m_pool->pool_bitmap, bit_idx, 1);
c0002b9c:	8b 55 f4             	mov    -0xc(%ebp),%edx
c0002b9f:	8b 45 08             	mov    0x8(%ebp),%eax
c0002ba2:	83 ec 04             	sub    $0x4,%esp
c0002ba5:	6a 01                	push   $0x1
c0002ba7:	52                   	push   %edx
c0002ba8:	50                   	push   %eax
c0002ba9:	e8 5b fd ff ff       	call   c0002909 <bitmap_set>
c0002bae:	83 c4 10             	add    $0x10,%esp
  uint32_t page_phyaddr = // 分配的物理页地址
      ((bit_idx * PG_SIZE) + m_pool->phy_addr_start);
c0002bb1:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002bb4:	c1 e0 0c             	shl    $0xc,%eax
c0002bb7:	89 c2                	mov    %eax,%edx
c0002bb9:	8b 45 08             	mov    0x8(%ebp),%eax
c0002bbc:	8b 40 08             	mov    0x8(%eax),%eax
  uint32_t page_phyaddr = // 分配的物理页地址
c0002bbf:	01 d0                	add    %edx,%eax
c0002bc1:	89 45 f0             	mov    %eax,-0x10(%ebp)
  return (void *)page_phyaddr;
c0002bc4:	8b 45 f0             	mov    -0x10(%ebp),%eax
}
c0002bc7:	c9                   	leave  
c0002bc8:	c3                   	ret    

c0002bc9 <page_table_add>:

// 页表中添加虚拟地址与物理地址的映射
static void page_table_add(void *_vaddr, void *_page_phyaddr) {
c0002bc9:	55                   	push   %ebp
c0002bca:	89 e5                	mov    %esp,%ebp
c0002bcc:	83 ec 28             	sub    $0x28,%esp
  uint32_t vaddr = (uint32_t)_vaddr, page_phyaddr = (uint32_t)_page_phyaddr;
c0002bcf:	8b 45 08             	mov    0x8(%ebp),%eax
c0002bd2:	89 45 f4             	mov    %eax,-0xc(%ebp)
c0002bd5:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002bd8:	89 45 f0             	mov    %eax,-0x10(%ebp)
  uint32_t *pde = pde_ptr(vaddr);
c0002bdb:	ff 75 f4             	push   -0xc(%ebp)
c0002bde:	e8 0c fe ff ff       	call   c00029ef <pde_ptr>
c0002be3:	83 c4 04             	add    $0x4,%esp
c0002be6:	89 45 ec             	mov    %eax,-0x14(%ebp)
  uint32_t *pte = pte_ptr(vaddr);
c0002be9:	ff 75 f4             	push   -0xc(%ebp)
c0002bec:	e8 ce fd ff ff       	call   c00029bf <pte_ptr>
c0002bf1:	83 c4 04             	add    $0x4,%esp
c0002bf4:	89 45 e8             	mov    %eax,-0x18(%ebp)

  // 在页目录表内判断目录项的P位，为1表示该表已存在
  if (*pde & 0x00000001) {
c0002bf7:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002bfa:	8b 00                	mov    (%eax),%eax
c0002bfc:	83 e0 01             	and    $0x1,%eax
c0002bff:	85 c0                	test   %eax,%eax
c0002c01:	74 71                	je     c0002c74 <page_table_add+0xab>
    ASSERT(!(*pte & 0x00000001));
c0002c03:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002c06:	8b 00                	mov    (%eax),%eax
c0002c08:	83 e0 01             	and    $0x1,%eax
c0002c0b:	85 c0                	test   %eax,%eax
c0002c0d:	74 1c                	je     c0002c2b <page_table_add+0x62>
c0002c0f:	68 47 c5 00 c0       	push   $0xc000c547
c0002c14:	68 80 c8 00 c0       	push   $0xc000c880
c0002c19:	68 87 00 00 00       	push   $0x87
c0002c1e:	68 37 c5 00 c0       	push   $0xc000c537
c0002c23:	e8 b0 f6 ff ff       	call   c00022d8 <panic_spin>
c0002c28:	83 c4 10             	add    $0x10,%esp
    if (!(*pte & 0x00000001)) {
c0002c2b:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002c2e:	8b 00                	mov    (%eax),%eax
c0002c30:	83 e0 01             	and    $0x1,%eax
c0002c33:	85 c0                	test   %eax,%eax
c0002c35:	75 12                	jne    c0002c49 <page_table_add+0x80>
      *pte = (page_phyaddr | PG_US_U | PG_RW_W | PG_P_1); // US=1,RW=1,P=1
c0002c37:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002c3a:	83 c8 07             	or     $0x7,%eax
c0002c3d:	89 c2                	mov    %eax,%edx
c0002c3f:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002c42:	89 10                	mov    %edx,(%eax)
    // 取高20位，低12位置0
    memset((void *)((int)pte & 0xfffff000), 0, PG_SIZE);
    ASSERT(!(*pte & 0x00000001));
    *pte = (page_phyaddr | PG_US_U | PG_RW_W | PG_P_1); // US=1,RW=1,P=1
  }
}
c0002c44:	e9 9b 00 00 00       	jmp    c0002ce4 <page_table_add+0x11b>
      PANIC("pte repeat");
c0002c49:	68 5c c5 00 c0       	push   $0xc000c55c
c0002c4e:	68 80 c8 00 c0       	push   $0xc000c880
c0002c53:	68 8c 00 00 00       	push   $0x8c
c0002c58:	68 37 c5 00 c0       	push   $0xc000c537
c0002c5d:	e8 76 f6 ff ff       	call   c00022d8 <panic_spin>
c0002c62:	83 c4 10             	add    $0x10,%esp
      *pte = (page_phyaddr | PG_US_U | PG_RW_W | PG_P_1); // US=1,RW=1,P=1
c0002c65:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002c68:	83 c8 07             	or     $0x7,%eax
c0002c6b:	89 c2                	mov    %eax,%edx
c0002c6d:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002c70:	89 10                	mov    %edx,(%eax)
}
c0002c72:	eb 70                	jmp    c0002ce4 <page_table_add+0x11b>
    uint32_t pde_pyhaddr = (uint32_t)palloc(&kernel_pool);
c0002c74:	83 ec 0c             	sub    $0xc,%esp
c0002c77:	68 80 1a 01 c0       	push   $0xc0011a80
c0002c7c:	e8 f4 fe ff ff       	call   c0002b75 <palloc>
c0002c81:	83 c4 10             	add    $0x10,%esp
c0002c84:	89 45 e4             	mov    %eax,-0x1c(%ebp)
    *pde = (pde_pyhaddr | PG_US_U | PG_RW_W | PG_P_1);
c0002c87:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0002c8a:	83 c8 07             	or     $0x7,%eax
c0002c8d:	89 c2                	mov    %eax,%edx
c0002c8f:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002c92:	89 10                	mov    %edx,(%eax)
    memset((void *)((int)pte & 0xfffff000), 0, PG_SIZE);
c0002c94:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002c97:	25 00 f0 ff ff       	and    $0xfffff000,%eax
c0002c9c:	83 ec 04             	sub    $0x4,%esp
c0002c9f:	68 00 10 00 00       	push   $0x1000
c0002ca4:	6a 00                	push   $0x0
c0002ca6:	50                   	push   %eax
c0002ca7:	e8 02 f7 ff ff       	call   c00023ae <memset>
c0002cac:	83 c4 10             	add    $0x10,%esp
    ASSERT(!(*pte & 0x00000001));
c0002caf:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002cb2:	8b 00                	mov    (%eax),%eax
c0002cb4:	83 e0 01             	and    $0x1,%eax
c0002cb7:	85 c0                	test   %eax,%eax
c0002cb9:	74 1c                	je     c0002cd7 <page_table_add+0x10e>
c0002cbb:	68 47 c5 00 c0       	push   $0xc000c547
c0002cc0:	68 80 c8 00 c0       	push   $0xc000c880
c0002cc5:	68 96 00 00 00       	push   $0x96
c0002cca:	68 37 c5 00 c0       	push   $0xc000c537
c0002ccf:	e8 04 f6 ff ff       	call   c00022d8 <panic_spin>
c0002cd4:	83 c4 10             	add    $0x10,%esp
    *pte = (page_phyaddr | PG_US_U | PG_RW_W | PG_P_1); // US=1,RW=1,P=1
c0002cd7:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002cda:	83 c8 07             	or     $0x7,%eax
c0002cdd:	89 c2                	mov    %eax,%edx
c0002cdf:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002ce2:	89 10                	mov    %edx,(%eax)
}
c0002ce4:	90                   	nop
c0002ce5:	c9                   	leave  
c0002ce6:	c3                   	ret    

c0002ce7 <malloc_page>:
/***** malloc_page：分配pg_cnt个页，成功返回起始虚拟地址 *******
1、在虚拟内存池中申请虚拟地址（vaddr_get）
2、在物理内存池中申请物理页（palloc）
3、将以上得到的虚拟地址和物理地址在页表中完成映射（page_table_add）
**********************************************************/
void *malloc_page(enum pool_flags pf, uint32_t pg_cnt) {
c0002ce7:	55                   	push   %ebp
c0002ce8:	89 e5                	mov    %esp,%ebp
c0002cea:	83 ec 28             	sub    $0x28,%esp
  ASSERT(pg_cnt > 0 && pg_cnt < 3840);
c0002ced:	83 7d 0c 00          	cmpl   $0x0,0xc(%ebp)
c0002cf1:	74 09                	je     c0002cfc <malloc_page+0x15>
c0002cf3:	81 7d 0c ff 0e 00 00 	cmpl   $0xeff,0xc(%ebp)
c0002cfa:	76 1c                	jbe    c0002d18 <malloc_page+0x31>
c0002cfc:	68 67 c5 00 c0       	push   $0xc000c567
c0002d01:	68 90 c8 00 c0       	push   $0xc000c890
c0002d06:	68 a1 00 00 00       	push   $0xa1
c0002d0b:	68 37 c5 00 c0       	push   $0xc000c537
c0002d10:	e8 c3 f5 ff ff       	call   c00022d8 <panic_spin>
c0002d15:	83 c4 10             	add    $0x10,%esp
  void *vaddr_start = vaddr_get(pf, pg_cnt);
c0002d18:	83 ec 08             	sub    $0x8,%esp
c0002d1b:	ff 75 0c             	push   0xc(%ebp)
c0002d1e:	ff 75 08             	push   0x8(%ebp)
c0002d21:	e8 38 fd ff ff       	call   c0002a5e <vaddr_get>
c0002d26:	83 c4 10             	add    $0x10,%esp
c0002d29:	89 45 ec             	mov    %eax,-0x14(%ebp)
  if (vaddr_start == NULL) {
c0002d2c:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c0002d30:	75 07                	jne    c0002d39 <malloc_page+0x52>
    return NULL; // 失败
c0002d32:	b8 00 00 00 00       	mov    $0x0,%eax
c0002d37:	eb 6e                	jmp    c0002da7 <malloc_page+0xc0>
  }

  uint32_t vaddr = (uint32_t)vaddr_start, cnt = pg_cnt;
c0002d39:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002d3c:	89 45 f4             	mov    %eax,-0xc(%ebp)
c0002d3f:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002d42:	89 45 f0             	mov    %eax,-0x10(%ebp)
  struct pool *mem_pool = pf & PF_KERNEL ? &kernel_pool : &user_pool;
c0002d45:	8b 45 08             	mov    0x8(%ebp),%eax
c0002d48:	83 e0 01             	and    $0x1,%eax
c0002d4b:	85 c0                	test   %eax,%eax
c0002d4d:	74 07                	je     c0002d56 <malloc_page+0x6f>
c0002d4f:	b8 80 1a 01 c0       	mov    $0xc0011a80,%eax
c0002d54:	eb 05                	jmp    c0002d5b <malloc_page+0x74>
c0002d56:	b8 c0 1a 01 c0       	mov    $0xc0011ac0,%eax
c0002d5b:	89 45 e8             	mov    %eax,-0x18(%ebp)

  // 虚拟地址连续但物理地址可以不连续，所以逐个做映射
  while (cnt-- > 0) {
c0002d5e:	eb 37                	jmp    c0002d97 <malloc_page+0xb0>
    void *page_phyaddr = palloc(mem_pool);
c0002d60:	83 ec 0c             	sub    $0xc,%esp
c0002d63:	ff 75 e8             	push   -0x18(%ebp)
c0002d66:	e8 0a fe ff ff       	call   c0002b75 <palloc>
c0002d6b:	83 c4 10             	add    $0x10,%esp
c0002d6e:	89 45 e4             	mov    %eax,-0x1c(%ebp)
    if (page_phyaddr == NULL) {
c0002d71:	83 7d e4 00          	cmpl   $0x0,-0x1c(%ebp)
c0002d75:	75 07                	jne    c0002d7e <malloc_page+0x97>
      // TODO：失败时要将曾经已申请的虚拟地址和物理页全部回滚，完成内存回收时再补充
      return NULL;
c0002d77:	b8 00 00 00 00       	mov    $0x0,%eax
c0002d7c:	eb 29                	jmp    c0002da7 <malloc_page+0xc0>
    }
    page_table_add((void *)vaddr, page_phyaddr); // 在页表中作映射
c0002d7e:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002d81:	83 ec 08             	sub    $0x8,%esp
c0002d84:	ff 75 e4             	push   -0x1c(%ebp)
c0002d87:	50                   	push   %eax
c0002d88:	e8 3c fe ff ff       	call   c0002bc9 <page_table_add>
c0002d8d:	83 c4 10             	add    $0x10,%esp
    vaddr += PG_SIZE;                            // 下个虚拟页
c0002d90:	81 45 f4 00 10 00 00 	addl   $0x1000,-0xc(%ebp)
  while (cnt-- > 0) {
c0002d97:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002d9a:	8d 50 ff             	lea    -0x1(%eax),%edx
c0002d9d:	89 55 f0             	mov    %edx,-0x10(%ebp)
c0002da0:	85 c0                	test   %eax,%eax
c0002da2:	75 bc                	jne    c0002d60 <malloc_page+0x79>
  }
  return vaddr_start;
c0002da4:	8b 45 ec             	mov    -0x14(%ebp),%eax
}
c0002da7:	c9                   	leave  
c0002da8:	c3                   	ret    

c0002da9 <get_kernel_pages>:

// 从内核物理内存池中申请1页内存，成功则返回其虚拟地址
void *get_kernel_pages(uint32_t pg_cnt) {
c0002da9:	55                   	push   %ebp
c0002daa:	89 e5                	mov    %esp,%ebp
c0002dac:	83 ec 18             	sub    $0x18,%esp
  void *vaddr = malloc_page(PF_KERNEL, pg_cnt);
c0002daf:	83 ec 08             	sub    $0x8,%esp
c0002db2:	ff 75 08             	push   0x8(%ebp)
c0002db5:	6a 01                	push   $0x1
c0002db7:	e8 2b ff ff ff       	call   c0002ce7 <malloc_page>
c0002dbc:	83 c4 10             	add    $0x10,%esp
c0002dbf:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (vaddr != NULL) { // 若分配的地址不为空，将页框清0后返回
c0002dc2:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
c0002dc6:	74 17                	je     c0002ddf <get_kernel_pages+0x36>
    memset(vaddr, 0, pg_cnt * PG_SIZE);
c0002dc8:	8b 45 08             	mov    0x8(%ebp),%eax
c0002dcb:	c1 e0 0c             	shl    $0xc,%eax
c0002dce:	83 ec 04             	sub    $0x4,%esp
c0002dd1:	50                   	push   %eax
c0002dd2:	6a 00                	push   $0x0
c0002dd4:	ff 75 f4             	push   -0xc(%ebp)
c0002dd7:	e8 d2 f5 ff ff       	call   c00023ae <memset>
c0002ddc:	83 c4 10             	add    $0x10,%esp
  }
  return vaddr;
c0002ddf:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0002de2:	c9                   	leave  
c0002de3:	c3                   	ret    

c0002de4 <get_user_pages>:

// 在用户空间中申请4k内存，并返回其虚拟地址
void *get_user_pages(uint32_t pg_cnt) {
c0002de4:	55                   	push   %ebp
c0002de5:	89 e5                	mov    %esp,%ebp
c0002de7:	83 ec 18             	sub    $0x18,%esp
  lock_acquire(&user_pool.lock);
c0002dea:	83 ec 0c             	sub    $0xc,%esp
c0002ded:	68 d0 1a 01 c0       	push   $0xc0011ad0
c0002df2:	e8 22 18 00 00       	call   c0004619 <lock_acquire>
c0002df7:	83 c4 10             	add    $0x10,%esp
  void *vaddr = malloc_page(PF_USER, pg_cnt);
c0002dfa:	83 ec 08             	sub    $0x8,%esp
c0002dfd:	ff 75 08             	push   0x8(%ebp)
c0002e00:	6a 02                	push   $0x2
c0002e02:	e8 e0 fe ff ff       	call   c0002ce7 <malloc_page>
c0002e07:	83 c4 10             	add    $0x10,%esp
c0002e0a:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (vaddr != NULL) {
c0002e0d:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
c0002e11:	74 17                	je     c0002e2a <get_user_pages+0x46>
    memset(vaddr, 0, pg_cnt * PG_SIZE);
c0002e13:	8b 45 08             	mov    0x8(%ebp),%eax
c0002e16:	c1 e0 0c             	shl    $0xc,%eax
c0002e19:	83 ec 04             	sub    $0x4,%esp
c0002e1c:	50                   	push   %eax
c0002e1d:	6a 00                	push   $0x0
c0002e1f:	ff 75 f4             	push   -0xc(%ebp)
c0002e22:	e8 87 f5 ff ff       	call   c00023ae <memset>
c0002e27:	83 c4 10             	add    $0x10,%esp
  }
  lock_release(&user_pool.lock);
c0002e2a:	83 ec 0c             	sub    $0xc,%esp
c0002e2d:	68 d0 1a 01 c0       	push   $0xc0011ad0
c0002e32:	e8 57 18 00 00       	call   c000468e <lock_release>
c0002e37:	83 c4 10             	add    $0x10,%esp
  return vaddr;
c0002e3a:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0002e3d:	c9                   	leave  
c0002e3e:	c3                   	ret    

c0002e3f <get_a_page>:

// 申请一页内存，并将vaddr映射到该页（即可指定虚拟地址
void *get_a_page(enum pool_flags pf, uint32_t vaddr) {
c0002e3f:	55                   	push   %ebp
c0002e40:	89 e5                	mov    %esp,%ebp
c0002e42:	83 ec 18             	sub    $0x18,%esp
  struct pool *mem_pool = pf & PF_KERNEL ? &kernel_pool : &user_pool;
c0002e45:	8b 45 08             	mov    0x8(%ebp),%eax
c0002e48:	83 e0 01             	and    $0x1,%eax
c0002e4b:	85 c0                	test   %eax,%eax
c0002e4d:	74 07                	je     c0002e56 <get_a_page+0x17>
c0002e4f:	b8 80 1a 01 c0       	mov    $0xc0011a80,%eax
c0002e54:	eb 05                	jmp    c0002e5b <get_a_page+0x1c>
c0002e56:	b8 c0 1a 01 c0       	mov    $0xc0011ac0,%eax
c0002e5b:	89 45 f4             	mov    %eax,-0xc(%ebp)
  lock_acquire(&mem_pool->lock);
c0002e5e:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002e61:	83 c0 10             	add    $0x10,%eax
c0002e64:	83 ec 0c             	sub    $0xc,%esp
c0002e67:	50                   	push   %eax
c0002e68:	e8 ac 17 00 00       	call   c0004619 <lock_acquire>
c0002e6d:	83 c4 10             	add    $0x10,%esp
  struct task_struct *cur = running_thread();
c0002e70:	e8 9a 0c 00 00       	call   c0003b0f <running_thread>
c0002e75:	89 45 f0             	mov    %eax,-0x10(%ebp)
  int32_t bit_idx = -1;
c0002e78:	c7 45 ec ff ff ff ff 	movl   $0xffffffff,-0x14(%ebp)

  // 位图置1操作
  if (cur->pgdir != NULL && pf == PF_USER) {
c0002e7f:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002e82:	8b 40 34             	mov    0x34(%eax),%eax
c0002e85:	85 c0                	test   %eax,%eax
c0002e87:	74 53                	je     c0002edc <get_a_page+0x9d>
c0002e89:	83 7d 08 02          	cmpl   $0x2,0x8(%ebp)
c0002e8d:	75 4d                	jne    c0002edc <get_a_page+0x9d>
    bit_idx = (vaddr - cur->userprog_vaddr.vaddr_start) / PG_SIZE;
c0002e8f:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002e92:	8b 50 40             	mov    0x40(%eax),%edx
c0002e95:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002e98:	29 d0                	sub    %edx,%eax
c0002e9a:	c1 e8 0c             	shr    $0xc,%eax
c0002e9d:	89 45 ec             	mov    %eax,-0x14(%ebp)
    ASSERT(bit_idx > 0);
c0002ea0:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c0002ea4:	7f 1c                	jg     c0002ec2 <get_a_page+0x83>
c0002ea6:	68 83 c5 00 c0       	push   $0xc000c583
c0002eab:	68 9c c8 00 c0       	push   $0xc000c89c
c0002eb0:	68 d5 00 00 00       	push   $0xd5
c0002eb5:	68 37 c5 00 c0       	push   $0xc000c537
c0002eba:	e8 19 f4 ff ff       	call   c00022d8 <panic_spin>
c0002ebf:	83 c4 10             	add    $0x10,%esp
    bitmap_set(&cur->userprog_vaddr.vaddr_bitmap, bit_idx, 1);
c0002ec2:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002ec5:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0002ec8:	83 c2 38             	add    $0x38,%edx
c0002ecb:	83 ec 04             	sub    $0x4,%esp
c0002ece:	6a 01                	push   $0x1
c0002ed0:	50                   	push   %eax
c0002ed1:	52                   	push   %edx
c0002ed2:	e8 32 fa ff ff       	call   c0002909 <bitmap_set>
c0002ed7:	83 c4 10             	add    $0x10,%esp
c0002eda:	eb 77                	jmp    c0002f53 <get_a_page+0x114>
  } else if (cur->pgdir == NULL && pf == PF_KERNEL) {
c0002edc:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002edf:	8b 40 34             	mov    0x34(%eax),%eax
c0002ee2:	85 c0                	test   %eax,%eax
c0002ee4:	75 51                	jne    c0002f37 <get_a_page+0xf8>
c0002ee6:	83 7d 08 01          	cmpl   $0x1,0x8(%ebp)
c0002eea:	75 4b                	jne    c0002f37 <get_a_page+0xf8>
    bit_idx = (vaddr - kernel_vaddr.vaddr_start) / PG_SIZE;
c0002eec:	8b 15 f4 1a 01 c0    	mov    0xc0011af4,%edx
c0002ef2:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002ef5:	29 d0                	sub    %edx,%eax
c0002ef7:	c1 e8 0c             	shr    $0xc,%eax
c0002efa:	89 45 ec             	mov    %eax,-0x14(%ebp)
    ASSERT(bit_idx > 0);
c0002efd:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c0002f01:	7f 1c                	jg     c0002f1f <get_a_page+0xe0>
c0002f03:	68 83 c5 00 c0       	push   $0xc000c583
c0002f08:	68 9c c8 00 c0       	push   $0xc000c89c
c0002f0d:	68 d9 00 00 00       	push   $0xd9
c0002f12:	68 37 c5 00 c0       	push   $0xc000c537
c0002f17:	e8 bc f3 ff ff       	call   c00022d8 <panic_spin>
c0002f1c:	83 c4 10             	add    $0x10,%esp
    bitmap_set(&kernel_vaddr.vaddr_bitmap, bit_idx, 1);
c0002f1f:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002f22:	83 ec 04             	sub    $0x4,%esp
c0002f25:	6a 01                	push   $0x1
c0002f27:	50                   	push   %eax
c0002f28:	68 ec 1a 01 c0       	push   $0xc0011aec
c0002f2d:	e8 d7 f9 ff ff       	call   c0002909 <bitmap_set>
c0002f32:	83 c4 10             	add    $0x10,%esp
c0002f35:	eb 1c                	jmp    c0002f53 <get_a_page+0x114>
  } else {
    PANIC("get_a_pages: not allow kernel alloc userspace or user alloc "
c0002f37:	68 90 c5 00 c0       	push   $0xc000c590
c0002f3c:	68 9c c8 00 c0       	push   $0xc000c89c
c0002f41:	68 dc 00 00 00       	push   $0xdc
c0002f46:	68 37 c5 00 c0       	push   $0xc000c537
c0002f4b:	e8 88 f3 ff ff       	call   c00022d8 <panic_spin>
c0002f50:	83 c4 10             	add    $0x10,%esp
          "kernelspace by get_a_page");
  }

  void *page_phyaddr = palloc(mem_pool);
c0002f53:	83 ec 0c             	sub    $0xc,%esp
c0002f56:	ff 75 f4             	push   -0xc(%ebp)
c0002f59:	e8 17 fc ff ff       	call   c0002b75 <palloc>
c0002f5e:	83 c4 10             	add    $0x10,%esp
c0002f61:	89 45 e8             	mov    %eax,-0x18(%ebp)
  if (page_phyaddr == NULL) {
c0002f64:	83 7d e8 00          	cmpl   $0x0,-0x18(%ebp)
c0002f68:	75 07                	jne    c0002f71 <get_a_page+0x132>
    return NULL;
c0002f6a:	b8 00 00 00 00       	mov    $0x0,%eax
c0002f6f:	eb 27                	jmp    c0002f98 <get_a_page+0x159>
  }
  page_table_add((void *)vaddr, page_phyaddr);
c0002f71:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002f74:	83 ec 08             	sub    $0x8,%esp
c0002f77:	ff 75 e8             	push   -0x18(%ebp)
c0002f7a:	50                   	push   %eax
c0002f7b:	e8 49 fc ff ff       	call   c0002bc9 <page_table_add>
c0002f80:	83 c4 10             	add    $0x10,%esp
  lock_release(&mem_pool->lock);
c0002f83:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002f86:	83 c0 10             	add    $0x10,%eax
c0002f89:	83 ec 0c             	sub    $0xc,%esp
c0002f8c:	50                   	push   %eax
c0002f8d:	e8 fc 16 00 00       	call   c000468e <lock_release>
c0002f92:	83 c4 10             	add    $0x10,%esp
  return (void *)vaddr;
c0002f95:	8b 45 0c             	mov    0xc(%ebp),%eax
}
c0002f98:	c9                   	leave  
c0002f99:	c3                   	ret    

c0002f9a <get_a_page_without_opvaddrbitmap>:

// 安装一页大小vaddr而无需操作虚拟地址位图（fork
void *get_a_page_without_opvaddrbitmap(enum pool_flags pf, uint32_t vaddr) {
c0002f9a:	55                   	push   %ebp
c0002f9b:	89 e5                	mov    %esp,%ebp
c0002f9d:	83 ec 18             	sub    $0x18,%esp
  struct pool *mem_pool = pf & PF_KERNEL ? &kernel_pool : &user_pool;
c0002fa0:	8b 45 08             	mov    0x8(%ebp),%eax
c0002fa3:	83 e0 01             	and    $0x1,%eax
c0002fa6:	85 c0                	test   %eax,%eax
c0002fa8:	74 07                	je     c0002fb1 <get_a_page_without_opvaddrbitmap+0x17>
c0002faa:	b8 80 1a 01 c0       	mov    $0xc0011a80,%eax
c0002faf:	eb 05                	jmp    c0002fb6 <get_a_page_without_opvaddrbitmap+0x1c>
c0002fb1:	b8 c0 1a 01 c0       	mov    $0xc0011ac0,%eax
c0002fb6:	89 45 f4             	mov    %eax,-0xc(%ebp)
  lock_acquire(&mem_pool->lock);
c0002fb9:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002fbc:	83 c0 10             	add    $0x10,%eax
c0002fbf:	83 ec 0c             	sub    $0xc,%esp
c0002fc2:	50                   	push   %eax
c0002fc3:	e8 51 16 00 00       	call   c0004619 <lock_acquire>
c0002fc8:	83 c4 10             	add    $0x10,%esp
  void *page_phyaddr = palloc(mem_pool);
c0002fcb:	83 ec 0c             	sub    $0xc,%esp
c0002fce:	ff 75 f4             	push   -0xc(%ebp)
c0002fd1:	e8 9f fb ff ff       	call   c0002b75 <palloc>
c0002fd6:	83 c4 10             	add    $0x10,%esp
c0002fd9:	89 45 f0             	mov    %eax,-0x10(%ebp)
  if (page_phyaddr == NULL) {
c0002fdc:	83 7d f0 00          	cmpl   $0x0,-0x10(%ebp)
c0002fe0:	75 19                	jne    c0002ffb <get_a_page_without_opvaddrbitmap+0x61>
    lock_release(&mem_pool->lock);
c0002fe2:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002fe5:	83 c0 10             	add    $0x10,%eax
c0002fe8:	83 ec 0c             	sub    $0xc,%esp
c0002feb:	50                   	push   %eax
c0002fec:	e8 9d 16 00 00       	call   c000468e <lock_release>
c0002ff1:	83 c4 10             	add    $0x10,%esp
    return NULL;
c0002ff4:	b8 00 00 00 00       	mov    $0x0,%eax
c0002ff9:	eb 27                	jmp    c0003022 <get_a_page_without_opvaddrbitmap+0x88>
  }
  page_table_add((void *)vaddr, page_phyaddr);
c0002ffb:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002ffe:	83 ec 08             	sub    $0x8,%esp
c0003001:	ff 75 f0             	push   -0x10(%ebp)
c0003004:	50                   	push   %eax
c0003005:	e8 bf fb ff ff       	call   c0002bc9 <page_table_add>
c000300a:	83 c4 10             	add    $0x10,%esp
  lock_release(&mem_pool->lock);
c000300d:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003010:	83 c0 10             	add    $0x10,%eax
c0003013:	83 ec 0c             	sub    $0xc,%esp
c0003016:	50                   	push   %eax
c0003017:	e8 72 16 00 00       	call   c000468e <lock_release>
c000301c:	83 c4 10             	add    $0x10,%esp
  return (void *)vaddr;
c000301f:	8b 45 0c             	mov    0xc(%ebp),%eax
}
c0003022:	c9                   	leave  
c0003023:	c3                   	ret    

c0003024 <sys_malloc>:

// 从堆中申请size字节内存
void *sys_malloc(uint32_t size) {
c0003024:	55                   	push   %ebp
c0003025:	89 e5                	mov    %esp,%ebp
c0003027:	83 ec 38             	sub    $0x38,%esp
  enum pool_flags PF;
  struct pool *mem_pool;
  uint32_t pool_size;
  struct mem_block_desc *descs;
  struct task_struct *cur_thread = running_thread();
c000302a:	e8 e0 0a 00 00       	call   c0003b0f <running_thread>
c000302f:	89 45 dc             	mov    %eax,-0x24(%ebp)

  if (cur_thread->pgdir == NULL) { // 内核线程
c0003032:	8b 45 dc             	mov    -0x24(%ebp),%eax
c0003035:	8b 40 34             	mov    0x34(%eax),%eax
c0003038:	85 c0                	test   %eax,%eax
c000303a:	75 1f                	jne    c000305b <sys_malloc+0x37>
    PF = PF_KERNEL;
c000303c:	c7 45 f4 01 00 00 00 	movl   $0x1,-0xc(%ebp)
    mem_pool = &kernel_pool;
c0003043:	c7 45 f0 80 1a 01 c0 	movl   $0xc0011a80,-0x10(%ebp)
    pool_size = kernel_pool.pool_size;
c000304a:	a1 8c 1a 01 c0       	mov    0xc0011a8c,%eax
c000304f:	89 45 ec             	mov    %eax,-0x14(%ebp)
    descs = k_block_descs;
c0003052:	c7 45 e8 c0 19 01 c0 	movl   $0xc00119c0,-0x18(%ebp)
c0003059:	eb 1f                	jmp    c000307a <sys_malloc+0x56>
  } else { // 用户进程
    PF = PF_USER;
c000305b:	c7 45 f4 02 00 00 00 	movl   $0x2,-0xc(%ebp)
    mem_pool = &user_pool;
c0003062:	c7 45 f0 c0 1a 01 c0 	movl   $0xc0011ac0,-0x10(%ebp)
    pool_size = user_pool.pool_size;
c0003069:	a1 cc 1a 01 c0       	mov    0xc0011acc,%eax
c000306e:	89 45 ec             	mov    %eax,-0x14(%ebp)
    descs = cur_thread->u_block_desc;
c0003071:	8b 45 dc             	mov    -0x24(%ebp),%eax
c0003074:	83 c0 44             	add    $0x44,%eax
c0003077:	89 45 e8             	mov    %eax,-0x18(%ebp)
  }

  if (!(size > 0 && size < pool_size)) {
c000307a:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c000307e:	74 08                	je     c0003088 <sys_malloc+0x64>
c0003080:	8b 45 08             	mov    0x8(%ebp),%eax
c0003083:	3b 45 ec             	cmp    -0x14(%ebp),%eax
c0003086:	72 0a                	jb     c0003092 <sys_malloc+0x6e>
    return NULL;
c0003088:	b8 00 00 00 00       	mov    $0x0,%eax
c000308d:	e9 bc 02 00 00       	jmp    c000334e <sys_malloc+0x32a>
  }
  struct arena *a;
  struct mem_block *b;
  lock_acquire(&mem_pool->lock);
c0003092:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0003095:	83 c0 10             	add    $0x10,%eax
c0003098:	83 ec 0c             	sub    $0xc,%esp
c000309b:	50                   	push   %eax
c000309c:	e8 78 15 00 00       	call   c0004619 <lock_acquire>
c00030a1:	83 c4 10             	add    $0x10,%esp

  if (size > 1024) { // 直接分配页框
c00030a4:	81 7d 08 00 04 00 00 	cmpl   $0x400,0x8(%ebp)
c00030ab:	0f 86 95 00 00 00    	jbe    c0003146 <sys_malloc+0x122>
    uint32_t page_cnt = DIV_ROUND_UP(size + sizeof(struct arena), PG_SIZE);
c00030b1:	8b 45 08             	mov    0x8(%ebp),%eax
c00030b4:	05 0b 10 00 00       	add    $0x100b,%eax
c00030b9:	c1 e8 0c             	shr    $0xc,%eax
c00030bc:	89 45 cc             	mov    %eax,-0x34(%ebp)
    a = malloc_page(PF, page_cnt);
c00030bf:	83 ec 08             	sub    $0x8,%esp
c00030c2:	ff 75 cc             	push   -0x34(%ebp)
c00030c5:	ff 75 f4             	push   -0xc(%ebp)
c00030c8:	e8 1a fc ff ff       	call   c0002ce7 <malloc_page>
c00030cd:	83 c4 10             	add    $0x10,%esp
c00030d0:	89 45 d8             	mov    %eax,-0x28(%ebp)

    if (a != NULL) {
c00030d3:	83 7d d8 00          	cmpl   $0x0,-0x28(%ebp)
c00030d7:	74 51                	je     c000312a <sys_malloc+0x106>
      memset(a, 0, page_cnt * PG_SIZE); // 分配的内存清0
c00030d9:	8b 45 cc             	mov    -0x34(%ebp),%eax
c00030dc:	c1 e0 0c             	shl    $0xc,%eax
c00030df:	83 ec 04             	sub    $0x4,%esp
c00030e2:	50                   	push   %eax
c00030e3:	6a 00                	push   $0x0
c00030e5:	ff 75 d8             	push   -0x28(%ebp)
c00030e8:	e8 c1 f2 ff ff       	call   c00023ae <memset>
c00030ed:	83 c4 10             	add    $0x10,%esp

      // 分配大块页框-> desc置NULL，cnt置为页框数，large置true
      a->desc = NULL;
c00030f0:	8b 45 d8             	mov    -0x28(%ebp),%eax
c00030f3:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
      a->cnt = page_cnt;
c00030f9:	8b 45 d8             	mov    -0x28(%ebp),%eax
c00030fc:	8b 55 cc             	mov    -0x34(%ebp),%edx
c00030ff:	89 50 04             	mov    %edx,0x4(%eax)
      a->large = true;
c0003102:	8b 45 d8             	mov    -0x28(%ebp),%eax
c0003105:	c7 40 08 01 00 00 00 	movl   $0x1,0x8(%eax)
      lock_release(&mem_pool->lock);
c000310c:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000310f:	83 c0 10             	add    $0x10,%eax
c0003112:	83 ec 0c             	sub    $0xc,%esp
c0003115:	50                   	push   %eax
c0003116:	e8 73 15 00 00       	call   c000468e <lock_release>
c000311b:	83 c4 10             	add    $0x10,%esp
      return (void *)++a; // 跨过arena大小把剩下内存返回
c000311e:	83 45 d8 0c          	addl   $0xc,-0x28(%ebp)
c0003122:	8b 45 d8             	mov    -0x28(%ebp),%eax
c0003125:	e9 24 02 00 00       	jmp    c000334e <sys_malloc+0x32a>
    } else {
      lock_release(&mem_pool->lock);
c000312a:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000312d:	83 c0 10             	add    $0x10,%eax
c0003130:	83 ec 0c             	sub    $0xc,%esp
c0003133:	50                   	push   %eax
c0003134:	e8 55 15 00 00       	call   c000468e <lock_release>
c0003139:	83 c4 10             	add    $0x10,%esp
      return NULL;
c000313c:	b8 00 00 00 00       	mov    $0x0,%eax
c0003141:	e9 08 02 00 00       	jmp    c000334e <sys_malloc+0x32a>
    }
  } else { // 去各规格mem_block_desc中适配
    uint32_t desc_idx;
    for (desc_idx = 0; desc_idx < DESC_CNT; desc_idx++) {
c0003146:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%ebp)
c000314d:	eb 1e                	jmp    c000316d <sys_malloc+0x149>
      if (size <= descs[desc_idx].block_size) {
c000314f:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c0003152:	89 d0                	mov    %edx,%eax
c0003154:	01 c0                	add    %eax,%eax
c0003156:	01 d0                	add    %edx,%eax
c0003158:	c1 e0 03             	shl    $0x3,%eax
c000315b:	89 c2                	mov    %eax,%edx
c000315d:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0003160:	01 d0                	add    %edx,%eax
c0003162:	8b 00                	mov    (%eax),%eax
c0003164:	39 45 08             	cmp    %eax,0x8(%ebp)
c0003167:	76 0c                	jbe    c0003175 <sys_malloc+0x151>
    for (desc_idx = 0; desc_idx < DESC_CNT; desc_idx++) {
c0003169:	83 45 e4 01          	addl   $0x1,-0x1c(%ebp)
c000316d:	83 7d e4 06          	cmpl   $0x6,-0x1c(%ebp)
c0003171:	76 dc                	jbe    c000314f <sys_malloc+0x12b>
c0003173:	eb 01                	jmp    c0003176 <sys_malloc+0x152>
        break;
c0003175:	90                   	nop
      }
    }

    if (list_empty(&descs[desc_idx].free_list)) { // 没有可用mem_block->
c0003176:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c0003179:	89 d0                	mov    %edx,%eax
c000317b:	01 c0                	add    %eax,%eax
c000317d:	01 d0                	add    %edx,%eax
c000317f:	c1 e0 03             	shl    $0x3,%eax
c0003182:	89 c2                	mov    %eax,%edx
c0003184:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0003187:	01 d0                	add    %edx,%eax
c0003189:	83 c0 08             	add    $0x8,%eax
c000318c:	83 ec 0c             	sub    $0xc,%esp
c000318f:	50                   	push   %eax
c0003190:	e8 49 12 00 00       	call   c00043de <list_empty>
c0003195:	83 c4 10             	add    $0x10,%esp
c0003198:	85 c0                	test   %eax,%eax
c000319a:	0f 84 2e 01 00 00    	je     c00032ce <sys_malloc+0x2aa>
                                                  // 创建新arena提供mem_block
      a = malloc_page(PF, 1); // 分配1页框作为arena
c00031a0:	83 ec 08             	sub    $0x8,%esp
c00031a3:	6a 01                	push   $0x1
c00031a5:	ff 75 f4             	push   -0xc(%ebp)
c00031a8:	e8 3a fb ff ff       	call   c0002ce7 <malloc_page>
c00031ad:	83 c4 10             	add    $0x10,%esp
c00031b0:	89 45 d8             	mov    %eax,-0x28(%ebp)
      if (a == NULL) {
c00031b3:	83 7d d8 00          	cmpl   $0x0,-0x28(%ebp)
c00031b7:	75 1c                	jne    c00031d5 <sys_malloc+0x1b1>
        lock_release(&mem_pool->lock);
c00031b9:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00031bc:	83 c0 10             	add    $0x10,%eax
c00031bf:	83 ec 0c             	sub    $0xc,%esp
c00031c2:	50                   	push   %eax
c00031c3:	e8 c6 14 00 00       	call   c000468e <lock_release>
c00031c8:	83 c4 10             	add    $0x10,%esp
        return NULL;
c00031cb:	b8 00 00 00 00       	mov    $0x0,%eax
c00031d0:	e9 79 01 00 00       	jmp    c000334e <sys_malloc+0x32a>
      }
      memset(a, 0, PG_SIZE);
c00031d5:	83 ec 04             	sub    $0x4,%esp
c00031d8:	68 00 10 00 00       	push   $0x1000
c00031dd:	6a 00                	push   $0x0
c00031df:	ff 75 d8             	push   -0x28(%ebp)
c00031e2:	e8 c7 f1 ff ff       	call   c00023ae <memset>
c00031e7:	83 c4 10             	add    $0x10,%esp

      // 分配小块内存->
      // desc置为相应内存块描述符，cnt置为此arena可用的内存块数,large置false
      a->desc = &descs[desc_idx];
c00031ea:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c00031ed:	89 d0                	mov    %edx,%eax
c00031ef:	01 c0                	add    %eax,%eax
c00031f1:	01 d0                	add    %edx,%eax
c00031f3:	c1 e0 03             	shl    $0x3,%eax
c00031f6:	89 c2                	mov    %eax,%edx
c00031f8:	8b 45 e8             	mov    -0x18(%ebp),%eax
c00031fb:	01 c2                	add    %eax,%edx
c00031fd:	8b 45 d8             	mov    -0x28(%ebp),%eax
c0003200:	89 10                	mov    %edx,(%eax)
      a->large = false;
c0003202:	8b 45 d8             	mov    -0x28(%ebp),%eax
c0003205:	c7 40 08 00 00 00 00 	movl   $0x0,0x8(%eax)
      a->cnt = descs[desc_idx].block_per_arena;
c000320c:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c000320f:	89 d0                	mov    %edx,%eax
c0003211:	01 c0                	add    %eax,%eax
c0003213:	01 d0                	add    %edx,%eax
c0003215:	c1 e0 03             	shl    $0x3,%eax
c0003218:	89 c2                	mov    %eax,%edx
c000321a:	8b 45 e8             	mov    -0x18(%ebp),%eax
c000321d:	01 d0                	add    %edx,%eax
c000321f:	8b 50 04             	mov    0x4(%eax),%edx
c0003222:	8b 45 d8             	mov    -0x28(%ebp),%eax
c0003225:	89 50 04             	mov    %edx,0x4(%eax)
      uint32_t block_idx;

      enum intr_status old_status = intr_disable();
c0003228:	e8 10 e7 ff ff       	call   c000193d <intr_disable>
c000322d:	89 45 d4             	mov    %eax,-0x2c(%ebp)

      // 将arena拆分成内存块，并添加到内存块描述符的free_list中
      for (block_idx = 0; block_idx < descs[desc_idx].block_per_arena;
c0003230:	c7 45 e0 00 00 00 00 	movl   $0x0,-0x20(%ebp)
c0003237:	eb 68                	jmp    c00032a1 <sys_malloc+0x27d>
           block_idx++) {
        b = arena2block(a, block_idx);
c0003239:	83 ec 08             	sub    $0x8,%esp
c000323c:	ff 75 e0             	push   -0x20(%ebp)
c000323f:	ff 75 d8             	push   -0x28(%ebp)
c0003242:	e8 f0 f7 ff ff       	call   c0002a37 <arena2block>
c0003247:	83 c4 10             	add    $0x10,%esp
c000324a:	89 45 d0             	mov    %eax,-0x30(%ebp)
        ASSERT(!elem_find(&a->desc->free_list, &b->free_elem));
c000324d:	8b 45 d0             	mov    -0x30(%ebp),%eax
c0003250:	8b 55 d8             	mov    -0x28(%ebp),%edx
c0003253:	8b 12                	mov    (%edx),%edx
c0003255:	83 c2 08             	add    $0x8,%edx
c0003258:	83 ec 08             	sub    $0x8,%esp
c000325b:	50                   	push   %eax
c000325c:	52                   	push   %edx
c000325d:	e8 af 10 00 00       	call   c0004311 <elem_find>
c0003262:	83 c4 10             	add    $0x10,%esp
c0003265:	85 c0                	test   %eax,%eax
c0003267:	74 1c                	je     c0003285 <sys_malloc+0x261>
c0003269:	68 e8 c5 00 c0       	push   $0xc000c5e8
c000326e:	68 a8 c8 00 c0       	push   $0xc000c8a8
c0003273:	68 41 01 00 00       	push   $0x141
c0003278:	68 37 c5 00 c0       	push   $0xc000c537
c000327d:	e8 56 f0 ff ff       	call   c00022d8 <panic_spin>
c0003282:	83 c4 10             	add    $0x10,%esp
        list_append(&a->desc->free_list, &b->free_elem);
c0003285:	8b 45 d0             	mov    -0x30(%ebp),%eax
c0003288:	8b 55 d8             	mov    -0x28(%ebp),%edx
c000328b:	8b 12                	mov    (%edx),%edx
c000328d:	83 c2 08             	add    $0x8,%edx
c0003290:	83 ec 08             	sub    $0x8,%esp
c0003293:	50                   	push   %eax
c0003294:	52                   	push   %edx
c0003295:	e8 fd 0f 00 00       	call   c0004297 <list_append>
c000329a:	83 c4 10             	add    $0x10,%esp
           block_idx++) {
c000329d:	83 45 e0 01          	addl   $0x1,-0x20(%ebp)
      for (block_idx = 0; block_idx < descs[desc_idx].block_per_arena;
c00032a1:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c00032a4:	89 d0                	mov    %edx,%eax
c00032a6:	01 c0                	add    %eax,%eax
c00032a8:	01 d0                	add    %edx,%eax
c00032aa:	c1 e0 03             	shl    $0x3,%eax
c00032ad:	89 c2                	mov    %eax,%edx
c00032af:	8b 45 e8             	mov    -0x18(%ebp),%eax
c00032b2:	01 d0                	add    %edx,%eax
c00032b4:	8b 40 04             	mov    0x4(%eax),%eax
c00032b7:	39 45 e0             	cmp    %eax,-0x20(%ebp)
c00032ba:	0f 82 79 ff ff ff    	jb     c0003239 <sys_malloc+0x215>
      }
      intr_set_status(old_status);
c00032c0:	83 ec 0c             	sub    $0xc,%esp
c00032c3:	ff 75 d4             	push   -0x2c(%ebp)
c00032c6:	e8 b8 e6 ff ff       	call   c0001983 <intr_set_status>
c00032cb:	83 c4 10             	add    $0x10,%esp
    }

    // 开始分配内存块
    b = elem2entry(struct mem_block, free_elem,
c00032ce:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c00032d1:	89 d0                	mov    %edx,%eax
c00032d3:	01 c0                	add    %eax,%eax
c00032d5:	01 d0                	add    %edx,%eax
c00032d7:	c1 e0 03             	shl    $0x3,%eax
c00032da:	89 c2                	mov    %eax,%edx
c00032dc:	8b 45 e8             	mov    -0x18(%ebp),%eax
c00032df:	01 d0                	add    %edx,%eax
c00032e1:	83 c0 08             	add    $0x8,%eax
c00032e4:	83 ec 0c             	sub    $0xc,%esp
c00032e7:	50                   	push   %eax
c00032e8:	e8 02 10 00 00       	call   c00042ef <list_pop>
c00032ed:	83 c4 10             	add    $0x10,%esp
c00032f0:	89 45 d0             	mov    %eax,-0x30(%ebp)
                   list_pop(&(descs[desc_idx].free_list)));
    memset(b, 0, descs[desc_idx].block_size);
c00032f3:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c00032f6:	89 d0                	mov    %edx,%eax
c00032f8:	01 c0                	add    %eax,%eax
c00032fa:	01 d0                	add    %edx,%eax
c00032fc:	c1 e0 03             	shl    $0x3,%eax
c00032ff:	89 c2                	mov    %eax,%edx
c0003301:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0003304:	01 d0                	add    %edx,%eax
c0003306:	8b 00                	mov    (%eax),%eax
c0003308:	83 ec 04             	sub    $0x4,%esp
c000330b:	50                   	push   %eax
c000330c:	6a 00                	push   $0x0
c000330e:	ff 75 d0             	push   -0x30(%ebp)
c0003311:	e8 98 f0 ff ff       	call   c00023ae <memset>
c0003316:	83 c4 10             	add    $0x10,%esp

    a = block2arena(b); // 获取内存块b所在arena
c0003319:	83 ec 0c             	sub    $0xc,%esp
c000331c:	ff 75 d0             	push   -0x30(%ebp)
c000331f:	e8 2d f7 ff ff       	call   c0002a51 <block2arena>
c0003324:	83 c4 10             	add    $0x10,%esp
c0003327:	89 45 d8             	mov    %eax,-0x28(%ebp)
    a->cnt--;           // 此arena中的空闲内存块数--
c000332a:	8b 45 d8             	mov    -0x28(%ebp),%eax
c000332d:	8b 40 04             	mov    0x4(%eax),%eax
c0003330:	8d 50 ff             	lea    -0x1(%eax),%edx
c0003333:	8b 45 d8             	mov    -0x28(%ebp),%eax
c0003336:	89 50 04             	mov    %edx,0x4(%eax)
    lock_release(&mem_pool->lock);
c0003339:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000333c:	83 c0 10             	add    $0x10,%eax
c000333f:	83 ec 0c             	sub    $0xc,%esp
c0003342:	50                   	push   %eax
c0003343:	e8 46 13 00 00       	call   c000468e <lock_release>
c0003348:	83 c4 10             	add    $0x10,%esp
    return (void *)b;
c000334b:	8b 45 d0             	mov    -0x30(%ebp),%eax
  }
}
c000334e:	c9                   	leave  
c000334f:	c3                   	ret    

c0003350 <pfree>:

// --------------------------------------------------------------------------------------------

// 在内存池中释放一页物理页
void pfree(uint32_t pg_phy_addr) {
c0003350:	55                   	push   %ebp
c0003351:	89 e5                	mov    %esp,%ebp
c0003353:	83 ec 18             	sub    $0x18,%esp
  struct pool *mem_pool;
  uint32_t bit_idx = 0; // 地址在物理内存池中的偏移量
c0003356:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
  if (pg_phy_addr >= user_pool.phy_addr_start) { // 用户物理内存池
c000335d:	a1 c8 1a 01 c0       	mov    0xc0011ac8,%eax
c0003362:	39 45 08             	cmp    %eax,0x8(%ebp)
c0003365:	72 1a                	jb     c0003381 <pfree+0x31>
    mem_pool = &user_pool;
c0003367:	c7 45 f4 c0 1a 01 c0 	movl   $0xc0011ac0,-0xc(%ebp)
    bit_idx = (pg_phy_addr - user_pool.phy_addr_start) / PG_SIZE;
c000336e:	8b 15 c8 1a 01 c0    	mov    0xc0011ac8,%edx
c0003374:	8b 45 08             	mov    0x8(%ebp),%eax
c0003377:	29 d0                	sub    %edx,%eax
c0003379:	c1 e8 0c             	shr    $0xc,%eax
c000337c:	89 45 f0             	mov    %eax,-0x10(%ebp)
c000337f:	eb 18                	jmp    c0003399 <pfree+0x49>
  } else { // 内核物理内存池
    mem_pool = &kernel_pool;
c0003381:	c7 45 f4 80 1a 01 c0 	movl   $0xc0011a80,-0xc(%ebp)
    bit_idx = (pg_phy_addr - kernel_pool.phy_addr_start) / PG_SIZE;
c0003388:	8b 15 88 1a 01 c0    	mov    0xc0011a88,%edx
c000338e:	8b 45 08             	mov    0x8(%ebp),%eax
c0003391:	29 d0                	sub    %edx,%eax
c0003393:	c1 e8 0c             	shr    $0xc,%eax
c0003396:	89 45 f0             	mov    %eax,-0x10(%ebp)
  }
  bitmap_set(&mem_pool->pool_bitmap, bit_idx, 0); // 将位图中该位清0
c0003399:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000339c:	83 ec 04             	sub    $0x4,%esp
c000339f:	6a 00                	push   $0x0
c00033a1:	ff 75 f0             	push   -0x10(%ebp)
c00033a4:	50                   	push   %eax
c00033a5:	e8 5f f5 ff ff       	call   c0002909 <bitmap_set>
c00033aa:	83 c4 10             	add    $0x10,%esp
}
c00033ad:	90                   	nop
c00033ae:	c9                   	leave  
c00033af:	c3                   	ret    

c00033b0 <page_table_pte_remove>:

// 去掉页表中虚拟地址的映射，只去掉vaddr对应的pte
static void page_table_pte_remove(uint32_t vaddr) {
c00033b0:	55                   	push   %ebp
c00033b1:	89 e5                	mov    %esp,%ebp
c00033b3:	83 ec 10             	sub    $0x10,%esp
  uint32_t *pte = pte_ptr(vaddr);
c00033b6:	8b 45 08             	mov    0x8(%ebp),%eax
c00033b9:	50                   	push   %eax
c00033ba:	e8 00 f6 ff ff       	call   c00029bf <pte_ptr>
c00033bf:	83 c4 04             	add    $0x4,%esp
c00033c2:	89 45 fc             	mov    %eax,-0x4(%ebp)
  *pte &= ~PG_P_1;                                   // pte的P位取反置0
c00033c5:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00033c8:	8b 00                	mov    (%eax),%eax
c00033ca:	83 e0 fe             	and    $0xfffffffe,%eax
c00033cd:	89 c2                	mov    %eax,%edx
c00033cf:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00033d2:	89 10                	mov    %edx,(%eax)
  asm volatile("invlpg %0" ::"m"(vaddr) : "memory"); // 更新tlb
c00033d4:	0f 01 7d 08          	invlpg 0x8(%ebp)
}
c00033d8:	90                   	nop
c00033d9:	c9                   	leave  
c00033da:	c3                   	ret    

c00033db <vaddr_remove>:

// 在虚拟地址池中释放以_vaddr起始的连续pg_nct个虚拟页地址
static void vaddr_remove(enum pool_flags pf, void *_vaddr, uint32_t pg_cnt) {
c00033db:	55                   	push   %ebp
c00033dc:	89 e5                	mov    %esp,%ebp
c00033de:	83 ec 18             	sub    $0x18,%esp
  uint32_t bit_idx_start = 0;
c00033e1:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
  uint32_t vaddr = (uint32_t)_vaddr;
c00033e8:	8b 45 0c             	mov    0xc(%ebp),%eax
c00033eb:	89 45 ec             	mov    %eax,-0x14(%ebp)
  uint32_t cnt = 0;
c00033ee:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)

  if (pf == PF_KERNEL) {
c00033f5:	83 7d 08 01          	cmpl   $0x1,0x8(%ebp)
c00033f9:	75 3e                	jne    c0003439 <vaddr_remove+0x5e>
    bit_idx_start = (vaddr - kernel_vaddr.vaddr_start) / PG_SIZE;
c00033fb:	8b 15 f4 1a 01 c0    	mov    0xc0011af4,%edx
c0003401:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0003404:	29 d0                	sub    %edx,%eax
c0003406:	c1 e8 0c             	shr    $0xc,%eax
c0003409:	89 45 f0             	mov    %eax,-0x10(%ebp)
    while (cnt < pg_cnt) {
c000340c:	eb 21                	jmp    c000342f <vaddr_remove+0x54>
      bitmap_set(&kernel_vaddr.vaddr_bitmap, bit_idx_start + cnt++, 0);
c000340e:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003411:	8d 50 01             	lea    0x1(%eax),%edx
c0003414:	89 55 f4             	mov    %edx,-0xc(%ebp)
c0003417:	8b 55 f0             	mov    -0x10(%ebp),%edx
c000341a:	01 d0                	add    %edx,%eax
c000341c:	83 ec 04             	sub    $0x4,%esp
c000341f:	6a 00                	push   $0x0
c0003421:	50                   	push   %eax
c0003422:	68 ec 1a 01 c0       	push   $0xc0011aec
c0003427:	e8 dd f4 ff ff       	call   c0002909 <bitmap_set>
c000342c:	83 c4 10             	add    $0x10,%esp
    while (cnt < pg_cnt) {
c000342f:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003432:	3b 45 10             	cmp    0x10(%ebp),%eax
c0003435:	72 d7                	jb     c000340e <vaddr_remove+0x33>
    while (cnt < pg_cnt) {
      bitmap_set(&cur_thread->userprog_vaddr.vaddr_bitmap,
                 bit_idx_start + cnt++, 0);
    }
  }
}
c0003437:	eb 46                	jmp    c000347f <vaddr_remove+0xa4>
    struct task_struct *cur_thread = running_thread();
c0003439:	e8 d1 06 00 00       	call   c0003b0f <running_thread>
c000343e:	89 45 e8             	mov    %eax,-0x18(%ebp)
    bit_idx_start = (vaddr - cur_thread->userprog_vaddr.vaddr_start) / PG_SIZE;
c0003441:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0003444:	8b 50 40             	mov    0x40(%eax),%edx
c0003447:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000344a:	29 d0                	sub    %edx,%eax
c000344c:	c1 e8 0c             	shr    $0xc,%eax
c000344f:	89 45 f0             	mov    %eax,-0x10(%ebp)
    while (cnt < pg_cnt) {
c0003452:	eb 23                	jmp    c0003477 <vaddr_remove+0x9c>
                 bit_idx_start + cnt++, 0);
c0003454:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003457:	8d 50 01             	lea    0x1(%eax),%edx
c000345a:	89 55 f4             	mov    %edx,-0xc(%ebp)
      bitmap_set(&cur_thread->userprog_vaddr.vaddr_bitmap,
c000345d:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0003460:	01 c2                	add    %eax,%edx
c0003462:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0003465:	83 c0 38             	add    $0x38,%eax
c0003468:	83 ec 04             	sub    $0x4,%esp
c000346b:	6a 00                	push   $0x0
c000346d:	52                   	push   %edx
c000346e:	50                   	push   %eax
c000346f:	e8 95 f4 ff ff       	call   c0002909 <bitmap_set>
c0003474:	83 c4 10             	add    $0x10,%esp
    while (cnt < pg_cnt) {
c0003477:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000347a:	3b 45 10             	cmp    0x10(%ebp),%eax
c000347d:	72 d5                	jb     c0003454 <vaddr_remove+0x79>
}
c000347f:	90                   	nop
c0003480:	c9                   	leave  
c0003481:	c3                   	ret    

c0003482 <mfree_page>:
/***** mfree_page：释放以虚拟地址vaddr为始的cnt个物理页框 *******
1、在物理地址池中释放物理页地址（pfree）
2、在页表中去掉虚拟地址映射-> 虚拟地址对应pte的P置0（page_table_pte_remove）
3、在虚拟地址池中释放虚拟地址（vaddr_remove）
**********************************************************/
void mfree_page(enum pool_flags pf, void *_vaddr, uint32_t pg_cnt) {
c0003482:	55                   	push   %ebp
c0003483:	89 e5                	mov    %esp,%ebp
c0003485:	83 ec 18             	sub    $0x18,%esp
  uint32_t pg_phy_addr;
  uint32_t vaddr = (uint32_t)_vaddr;
c0003488:	8b 45 0c             	mov    0xc(%ebp),%eax
c000348b:	89 45 f4             	mov    %eax,-0xc(%ebp)
  uint32_t page_cnt = 0;
c000348e:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
  ASSERT(pg_cnt >= 1 && vaddr % PG_SIZE == 0);
c0003495:	83 7d 10 00          	cmpl   $0x0,0x10(%ebp)
c0003499:	74 0c                	je     c00034a7 <mfree_page+0x25>
c000349b:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000349e:	25 ff 0f 00 00       	and    $0xfff,%eax
c00034a3:	85 c0                	test   %eax,%eax
c00034a5:	74 1c                	je     c00034c3 <mfree_page+0x41>
c00034a7:	68 18 c6 00 c0       	push   $0xc000c618
c00034ac:	68 b4 c8 00 c0       	push   $0xc000c8b4
c00034b1:	68 88 01 00 00       	push   $0x188
c00034b6:	68 37 c5 00 c0       	push   $0xc000c537
c00034bb:	e8 18 ee ff ff       	call   c00022d8 <panic_spin>
c00034c0:	83 c4 10             	add    $0x10,%esp
  pg_phy_addr = addr_v2p(vaddr);
c00034c3:	83 ec 0c             	sub    $0xc,%esp
c00034c6:	ff 75 f4             	push   -0xc(%ebp)
c00034c9:	e8 3d f5 ff ff       	call   c0002a0b <addr_v2p>
c00034ce:	83 c4 10             	add    $0x10,%esp
c00034d1:	89 45 ec             	mov    %eax,-0x14(%ebp)

  // 确保释放的物理内存在低端1MB+1KB大小的页目录+1KB大小的页表地址范围外
  ASSERT((pg_phy_addr % PG_SIZE) == 0 && pg_phy_addr >= 0x102000);
c00034d4:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00034d7:	25 ff 0f 00 00       	and    $0xfff,%eax
c00034dc:	85 c0                	test   %eax,%eax
c00034de:	75 09                	jne    c00034e9 <mfree_page+0x67>
c00034e0:	81 7d ec ff 1f 10 00 	cmpl   $0x101fff,-0x14(%ebp)
c00034e7:	77 1c                	ja     c0003505 <mfree_page+0x83>
c00034e9:	68 3c c6 00 c0       	push   $0xc000c63c
c00034ee:	68 b4 c8 00 c0       	push   $0xc000c8b4
c00034f3:	68 8c 01 00 00       	push   $0x18c
c00034f8:	68 37 c5 00 c0       	push   $0xc000c537
c00034fd:	e8 d6 ed ff ff       	call   c00022d8 <panic_spin>
c0003502:	83 c4 10             	add    $0x10,%esp

  if (pg_phy_addr >= user_pool.phy_addr_start) {
c0003505:	a1 c8 1a 01 c0       	mov    0xc0011ac8,%eax
c000350a:	39 45 ec             	cmp    %eax,-0x14(%ebp)
c000350d:	0f 82 94 00 00 00    	jb     c00035a7 <mfree_page+0x125>
    vaddr -= PG_SIZE;
c0003513:	81 6d f4 00 10 00 00 	subl   $0x1000,-0xc(%ebp)
    while (page_cnt < pg_cnt) {
c000351a:	eb 6a                	jmp    c0003586 <mfree_page+0x104>
      vaddr += PG_SIZE;
c000351c:	81 45 f4 00 10 00 00 	addl   $0x1000,-0xc(%ebp)
      pg_phy_addr = addr_v2p(vaddr);
c0003523:	83 ec 0c             	sub    $0xc,%esp
c0003526:	ff 75 f4             	push   -0xc(%ebp)
c0003529:	e8 dd f4 ff ff       	call   c0002a0b <addr_v2p>
c000352e:	83 c4 10             	add    $0x10,%esp
c0003531:	89 45 ec             	mov    %eax,-0x14(%ebp)

      // 确保物理地址属于用户物理内存池
      ASSERT((pg_phy_addr % PG_SIZE) == 0 &&
c0003534:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0003537:	25 ff 0f 00 00       	and    $0xfff,%eax
c000353c:	85 c0                	test   %eax,%eax
c000353e:	75 0a                	jne    c000354a <mfree_page+0xc8>
c0003540:	a1 c8 1a 01 c0       	mov    0xc0011ac8,%eax
c0003545:	39 45 ec             	cmp    %eax,-0x14(%ebp)
c0003548:	73 1c                	jae    c0003566 <mfree_page+0xe4>
c000354a:	68 74 c6 00 c0       	push   $0xc000c674
c000354f:	68 b4 c8 00 c0       	push   $0xc000c8b4
c0003554:	68 95 01 00 00       	push   $0x195
c0003559:	68 37 c5 00 c0       	push   $0xc000c537
c000355e:	e8 75 ed ff ff       	call   c00022d8 <panic_spin>
c0003563:	83 c4 10             	add    $0x10,%esp
             pg_phy_addr >= user_pool.phy_addr_start);
      pfree(pg_phy_addr);
c0003566:	83 ec 0c             	sub    $0xc,%esp
c0003569:	ff 75 ec             	push   -0x14(%ebp)
c000356c:	e8 df fd ff ff       	call   c0003350 <pfree>
c0003571:	83 c4 10             	add    $0x10,%esp
      page_table_pte_remove(vaddr);
c0003574:	83 ec 0c             	sub    $0xc,%esp
c0003577:	ff 75 f4             	push   -0xc(%ebp)
c000357a:	e8 31 fe ff ff       	call   c00033b0 <page_table_pte_remove>
c000357f:	83 c4 10             	add    $0x10,%esp
      page_cnt++;
c0003582:	83 45 f0 01          	addl   $0x1,-0x10(%ebp)
    while (page_cnt < pg_cnt) {
c0003586:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0003589:	3b 45 10             	cmp    0x10(%ebp),%eax
c000358c:	72 8e                	jb     c000351c <mfree_page+0x9a>
    }
    vaddr_remove(pf, _vaddr, pg_cnt);
c000358e:	83 ec 04             	sub    $0x4,%esp
c0003591:	ff 75 10             	push   0x10(%ebp)
c0003594:	ff 75 0c             	push   0xc(%ebp)
c0003597:	ff 75 08             	push   0x8(%ebp)
c000359a:	e8 3c fe ff ff       	call   c00033db <vaddr_remove>
c000359f:	83 c4 10             	add    $0x10,%esp
      page_table_pte_remove(vaddr);
      page_cnt++;
    }
    vaddr_remove(pf, _vaddr, pg_cnt);
  }
}
c00035a2:	e9 99 00 00 00       	jmp    c0003640 <mfree_page+0x1be>
    vaddr -= PG_SIZE;
c00035a7:	81 6d f4 00 10 00 00 	subl   $0x1000,-0xc(%ebp)
    while (page_cnt < pg_cnt) {
c00035ae:	eb 74                	jmp    c0003624 <mfree_page+0x1a2>
      vaddr += PG_SIZE;
c00035b0:	81 45 f4 00 10 00 00 	addl   $0x1000,-0xc(%ebp)
      pg_phy_addr = addr_v2p(vaddr);
c00035b7:	83 ec 0c             	sub    $0xc,%esp
c00035ba:	ff 75 f4             	push   -0xc(%ebp)
c00035bd:	e8 49 f4 ff ff       	call   c0002a0b <addr_v2p>
c00035c2:	83 c4 10             	add    $0x10,%esp
c00035c5:	89 45 ec             	mov    %eax,-0x14(%ebp)
      ASSERT((pg_phy_addr % PG_SIZE) == 0 &&
c00035c8:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00035cb:	25 ff 0f 00 00       	and    $0xfff,%eax
c00035d0:	85 c0                	test   %eax,%eax
c00035d2:	75 14                	jne    c00035e8 <mfree_page+0x166>
c00035d4:	a1 88 1a 01 c0       	mov    0xc0011a88,%eax
c00035d9:	39 45 ec             	cmp    %eax,-0x14(%ebp)
c00035dc:	72 0a                	jb     c00035e8 <mfree_page+0x166>
c00035de:	a1 c8 1a 01 c0       	mov    0xc0011ac8,%eax
c00035e3:	39 45 ec             	cmp    %eax,-0x14(%ebp)
c00035e6:	72 1c                	jb     c0003604 <mfree_page+0x182>
c00035e8:	68 bc c6 00 c0       	push   $0xc000c6bc
c00035ed:	68 b4 c8 00 c0       	push   $0xc000c8b4
c00035f2:	68 a3 01 00 00       	push   $0x1a3
c00035f7:	68 37 c5 00 c0       	push   $0xc000c537
c00035fc:	e8 d7 ec ff ff       	call   c00022d8 <panic_spin>
c0003601:	83 c4 10             	add    $0x10,%esp
      pfree(pg_phy_addr);
c0003604:	83 ec 0c             	sub    $0xc,%esp
c0003607:	ff 75 ec             	push   -0x14(%ebp)
c000360a:	e8 41 fd ff ff       	call   c0003350 <pfree>
c000360f:	83 c4 10             	add    $0x10,%esp
      page_table_pte_remove(vaddr);
c0003612:	83 ec 0c             	sub    $0xc,%esp
c0003615:	ff 75 f4             	push   -0xc(%ebp)
c0003618:	e8 93 fd ff ff       	call   c00033b0 <page_table_pte_remove>
c000361d:	83 c4 10             	add    $0x10,%esp
      page_cnt++;
c0003620:	83 45 f0 01          	addl   $0x1,-0x10(%ebp)
    while (page_cnt < pg_cnt) {
c0003624:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0003627:	3b 45 10             	cmp    0x10(%ebp),%eax
c000362a:	72 84                	jb     c00035b0 <mfree_page+0x12e>
    vaddr_remove(pf, _vaddr, pg_cnt);
c000362c:	83 ec 04             	sub    $0x4,%esp
c000362f:	ff 75 10             	push   0x10(%ebp)
c0003632:	ff 75 0c             	push   0xc(%ebp)
c0003635:	ff 75 08             	push   0x8(%ebp)
c0003638:	e8 9e fd ff ff       	call   c00033db <vaddr_remove>
c000363d:	83 c4 10             	add    $0x10,%esp
}
c0003640:	90                   	nop
c0003641:	c9                   	leave  
c0003642:	c3                   	ret    

c0003643 <sys_free>:

// 释放ptr指向的内存
void sys_free(void *ptr) {
c0003643:	55                   	push   %ebp
c0003644:	89 e5                	mov    %esp,%ebp
c0003646:	83 ec 28             	sub    $0x28,%esp
  ASSERT(ptr != NULL);
c0003649:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c000364d:	75 1c                	jne    c000366b <sys_free+0x28>
c000364f:	68 30 c7 00 c0       	push   $0xc000c730
c0003654:	68 c0 c8 00 c0       	push   $0xc000c8c0
c0003659:	68 b0 01 00 00       	push   $0x1b0
c000365e:	68 37 c5 00 c0       	push   $0xc000c537
c0003663:	e8 70 ec ff ff       	call   c00022d8 <panic_spin>
c0003668:	83 c4 10             	add    $0x10,%esp
  if (ptr != NULL) {
c000366b:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c000366f:	0f 84 b2 01 00 00    	je     c0003827 <sys_free+0x1e4>
    enum pool_flags PF;
    struct pool *mem_pool;

    if (running_thread()->pgdir == NULL) {
c0003675:	e8 95 04 00 00       	call   c0003b0f <running_thread>
c000367a:	8b 40 34             	mov    0x34(%eax),%eax
c000367d:	85 c0                	test   %eax,%eax
c000367f:	75 36                	jne    c00036b7 <sys_free+0x74>
      ASSERT((uint32_t)ptr >= K_HEAP_START);
c0003681:	8b 45 08             	mov    0x8(%ebp),%eax
c0003684:	3d ff ff 0f c0       	cmp    $0xc00fffff,%eax
c0003689:	77 1c                	ja     c00036a7 <sys_free+0x64>
c000368b:	68 3c c7 00 c0       	push   $0xc000c73c
c0003690:	68 c0 c8 00 c0       	push   $0xc000c8c0
c0003695:	68 b6 01 00 00       	push   $0x1b6
c000369a:	68 37 c5 00 c0       	push   $0xc000c537
c000369f:	e8 34 ec ff ff       	call   c00022d8 <panic_spin>
c00036a4:	83 c4 10             	add    $0x10,%esp
      PF = PF_KERNEL;
c00036a7:	c7 45 f4 01 00 00 00 	movl   $0x1,-0xc(%ebp)
      mem_pool = &kernel_pool;
c00036ae:	c7 45 f0 80 1a 01 c0 	movl   $0xc0011a80,-0x10(%ebp)
c00036b5:	eb 0e                	jmp    c00036c5 <sys_free+0x82>
    } else {
      PF = PF_USER;
c00036b7:	c7 45 f4 02 00 00 00 	movl   $0x2,-0xc(%ebp)
      mem_pool = &user_pool;
c00036be:	c7 45 f0 c0 1a 01 c0 	movl   $0xc0011ac0,-0x10(%ebp)
    }

    lock_acquire(&mem_pool->lock);
c00036c5:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00036c8:	83 c0 10             	add    $0x10,%eax
c00036cb:	83 ec 0c             	sub    $0xc,%esp
c00036ce:	50                   	push   %eax
c00036cf:	e8 45 0f 00 00       	call   c0004619 <lock_acquire>
c00036d4:	83 c4 10             	add    $0x10,%esp
    struct mem_block *b = ptr;
c00036d7:	8b 45 08             	mov    0x8(%ebp),%eax
c00036da:	89 45 e8             	mov    %eax,-0x18(%ebp)
    struct arena *a = block2arena(b); // 把mem_block转换成arena，获取元信息
c00036dd:	83 ec 0c             	sub    $0xc,%esp
c00036e0:	ff 75 e8             	push   -0x18(%ebp)
c00036e3:	e8 69 f3 ff ff       	call   c0002a51 <block2arena>
c00036e8:	83 c4 10             	add    $0x10,%esp
c00036eb:	89 45 e4             	mov    %eax,-0x1c(%ebp)
    ASSERT(a->large == 0 || a->large == 1);
c00036ee:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c00036f1:	8b 40 08             	mov    0x8(%eax),%eax
c00036f4:	85 c0                	test   %eax,%eax
c00036f6:	74 27                	je     c000371f <sys_free+0xdc>
c00036f8:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c00036fb:	8b 40 08             	mov    0x8(%eax),%eax
c00036fe:	83 f8 01             	cmp    $0x1,%eax
c0003701:	74 1c                	je     c000371f <sys_free+0xdc>
c0003703:	68 5c c7 00 c0       	push   $0xc000c75c
c0003708:	68 c0 c8 00 c0       	push   $0xc000c8c0
c000370d:	68 c1 01 00 00       	push   $0x1c1
c0003712:	68 37 c5 00 c0       	push   $0xc000c537
c0003717:	e8 bc eb ff ff       	call   c00022d8 <panic_spin>
c000371c:	83 c4 10             	add    $0x10,%esp

    if (a->desc == NULL && a->large == true) { // >1024的内存
c000371f:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0003722:	8b 00                	mov    (%eax),%eax
c0003724:	85 c0                	test   %eax,%eax
c0003726:	75 28                	jne    c0003750 <sys_free+0x10d>
c0003728:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c000372b:	8b 40 08             	mov    0x8(%eax),%eax
c000372e:	83 f8 01             	cmp    $0x1,%eax
c0003731:	75 1d                	jne    c0003750 <sys_free+0x10d>
      mfree_page(PF, a, a->cnt);
c0003733:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0003736:	8b 40 04             	mov    0x4(%eax),%eax
c0003739:	83 ec 04             	sub    $0x4,%esp
c000373c:	50                   	push   %eax
c000373d:	ff 75 e4             	push   -0x1c(%ebp)
c0003740:	ff 75 f4             	push   -0xc(%ebp)
c0003743:	e8 3a fd ff ff       	call   c0003482 <mfree_page>
c0003748:	83 c4 10             	add    $0x10,%esp
c000374b:	e9 c5 00 00 00       	jmp    c0003815 <sys_free+0x1d2>
    } else { // <=1024的内存
      // 将内存块回收到free_list
      list_append(&a->desc->free_list, &b->free_elem);
c0003750:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0003753:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c0003756:	8b 12                	mov    (%edx),%edx
c0003758:	83 c2 08             	add    $0x8,%edx
c000375b:	83 ec 08             	sub    $0x8,%esp
c000375e:	50                   	push   %eax
c000375f:	52                   	push   %edx
c0003760:	e8 32 0b 00 00       	call   c0004297 <list_append>
c0003765:	83 c4 10             	add    $0x10,%esp
      // 判断此arena中的内存块是否都空闲，空闲释放arena
      if (++a->cnt == a->desc->block_per_arena) {
c0003768:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c000376b:	8b 40 04             	mov    0x4(%eax),%eax
c000376e:	8d 50 01             	lea    0x1(%eax),%edx
c0003771:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0003774:	89 50 04             	mov    %edx,0x4(%eax)
c0003777:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c000377a:	8b 50 04             	mov    0x4(%eax),%edx
c000377d:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0003780:	8b 00                	mov    (%eax),%eax
c0003782:	8b 40 04             	mov    0x4(%eax),%eax
c0003785:	39 c2                	cmp    %eax,%edx
c0003787:	0f 85 88 00 00 00    	jne    c0003815 <sys_free+0x1d2>
        uint32_t block_idx;
        for (block_idx = 0; block_idx < a->desc->block_per_arena; block_idx++) {
c000378d:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%ebp)
c0003794:	eb 5f                	jmp    c00037f5 <sys_free+0x1b2>
          struct mem_block *b = arena2block(a, block_idx);
c0003796:	83 ec 08             	sub    $0x8,%esp
c0003799:	ff 75 ec             	push   -0x14(%ebp)
c000379c:	ff 75 e4             	push   -0x1c(%ebp)
c000379f:	e8 93 f2 ff ff       	call   c0002a37 <arena2block>
c00037a4:	83 c4 10             	add    $0x10,%esp
c00037a7:	89 45 e0             	mov    %eax,-0x20(%ebp)
          ASSERT(elem_find(&a->desc->free_list, &b->free_elem));
c00037aa:	8b 45 e0             	mov    -0x20(%ebp),%eax
c00037ad:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c00037b0:	8b 12                	mov    (%edx),%edx
c00037b2:	83 c2 08             	add    $0x8,%edx
c00037b5:	83 ec 08             	sub    $0x8,%esp
c00037b8:	50                   	push   %eax
c00037b9:	52                   	push   %edx
c00037ba:	e8 52 0b 00 00       	call   c0004311 <elem_find>
c00037bf:	83 c4 10             	add    $0x10,%esp
c00037c2:	85 c0                	test   %eax,%eax
c00037c4:	75 1c                	jne    c00037e2 <sys_free+0x19f>
c00037c6:	68 7c c7 00 c0       	push   $0xc000c77c
c00037cb:	68 c0 c8 00 c0       	push   $0xc000c8c0
c00037d0:	68 cd 01 00 00       	push   $0x1cd
c00037d5:	68 37 c5 00 c0       	push   $0xc000c537
c00037da:	e8 f9 ea ff ff       	call   c00022d8 <panic_spin>
c00037df:	83 c4 10             	add    $0x10,%esp
          list_remove(&b->free_elem);
c00037e2:	8b 45 e0             	mov    -0x20(%ebp),%eax
c00037e5:	83 ec 0c             	sub    $0xc,%esp
c00037e8:	50                   	push   %eax
c00037e9:	e8 c7 0a 00 00       	call   c00042b5 <list_remove>
c00037ee:	83 c4 10             	add    $0x10,%esp
        for (block_idx = 0; block_idx < a->desc->block_per_arena; block_idx++) {
c00037f1:	83 45 ec 01          	addl   $0x1,-0x14(%ebp)
c00037f5:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c00037f8:	8b 00                	mov    (%eax),%eax
c00037fa:	8b 40 04             	mov    0x4(%eax),%eax
c00037fd:	39 45 ec             	cmp    %eax,-0x14(%ebp)
c0003800:	72 94                	jb     c0003796 <sys_free+0x153>
        }
        mfree_page(PF, a, 1);
c0003802:	83 ec 04             	sub    $0x4,%esp
c0003805:	6a 01                	push   $0x1
c0003807:	ff 75 e4             	push   -0x1c(%ebp)
c000380a:	ff 75 f4             	push   -0xc(%ebp)
c000380d:	e8 70 fc ff ff       	call   c0003482 <mfree_page>
c0003812:	83 c4 10             	add    $0x10,%esp
      }
    }
    lock_release(&mem_pool->lock);
c0003815:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0003818:	83 c0 10             	add    $0x10,%eax
c000381b:	83 ec 0c             	sub    $0xc,%esp
c000381e:	50                   	push   %eax
c000381f:	e8 6a 0e 00 00       	call   c000468e <lock_release>
c0003824:	83 c4 10             	add    $0x10,%esp
  }
}
c0003827:	90                   	nop
c0003828:	c9                   	leave  
c0003829:	c3                   	ret    

c000382a <mem_pool_init>:

// --------------------------------------------------------------------------------------------

// 初始化内存池
static void mem_pool_init(uint32_t all_mem) {
c000382a:	55                   	push   %ebp
c000382b:	89 e5                	mov    %esp,%ebp
c000382d:	83 ec 38             	sub    $0x38,%esp
  put_str("   mem_pool_init start\n");
c0003830:	83 ec 0c             	sub    $0xc,%esp
c0003833:	68 aa c7 00 c0       	push   $0xc000c7aa
c0003838:	e8 f3 e1 ff ff       	call   c0001a30 <put_str>
c000383d:	83 c4 10             	add    $0x10,%esp
  uint32_t page_table_size = PG_SIZE * 256; // 页表+页目录表
c0003840:	c7 45 f4 00 00 10 00 	movl   $0x100000,-0xc(%ebp)
  uint32_t used_mem = page_table_size + 0x100000; // 已用：页表占大小+低端1MB
c0003847:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000384a:	05 00 00 10 00       	add    $0x100000,%eax
c000384f:	89 45 f0             	mov    %eax,-0x10(%ebp)
  uint32_t free_mem = all_mem - used_mem;
c0003852:	8b 45 08             	mov    0x8(%ebp),%eax
c0003855:	2b 45 f0             	sub    -0x10(%ebp),%eax
c0003858:	89 45 ec             	mov    %eax,-0x14(%ebp)
  uint16_t all_free_pages = free_mem / PG_SIZE; // free_mem转为的物理内存页数
c000385b:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000385e:	c1 e8 0c             	shr    $0xc,%eax
c0003861:	66 89 45 ea          	mov    %ax,-0x16(%ebp)
  uint16_t kernel_free_pages = all_free_pages / 2;
c0003865:	0f b7 45 ea          	movzwl -0x16(%ebp),%eax
c0003869:	66 d1 e8             	shr    %ax
c000386c:	66 89 45 e8          	mov    %ax,-0x18(%ebp)
  uint16_t user_free_pages = all_free_pages - kernel_free_pages;
c0003870:	0f b7 45 ea          	movzwl -0x16(%ebp),%eax
c0003874:	66 2b 45 e8          	sub    -0x18(%ebp),%ax
c0003878:	66 89 45 e6          	mov    %ax,-0x1a(%ebp)

  uint32_t kbm_len = kernel_free_pages / 8;
c000387c:	0f b7 45 e8          	movzwl -0x18(%ebp),%eax
c0003880:	66 c1 e8 03          	shr    $0x3,%ax
c0003884:	0f b7 c0             	movzwl %ax,%eax
c0003887:	89 45 e0             	mov    %eax,-0x20(%ebp)
  uint32_t ubm_len = user_free_pages / 8;
c000388a:	0f b7 45 e6          	movzwl -0x1a(%ebp),%eax
c000388e:	66 c1 e8 03          	shr    $0x3,%ax
c0003892:	0f b7 c0             	movzwl %ax,%eax
c0003895:	89 45 dc             	mov    %eax,-0x24(%ebp)

  // 内核内存池起始地址
  uint32_t kp_start = used_mem;
c0003898:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000389b:	89 45 d8             	mov    %eax,-0x28(%ebp)
  // 用户内存池起始地址
  uint32_t up_start = kp_start + kernel_free_pages * PG_SIZE;
c000389e:	0f b7 45 e8          	movzwl -0x18(%ebp),%eax
c00038a2:	c1 e0 0c             	shl    $0xc,%eax
c00038a5:	89 c2                	mov    %eax,%edx
c00038a7:	8b 45 d8             	mov    -0x28(%ebp),%eax
c00038aa:	01 d0                	add    %edx,%eax
c00038ac:	89 45 d4             	mov    %eax,-0x2c(%ebp)

  kernel_pool.phy_addr_start = kp_start;
c00038af:	8b 45 d8             	mov    -0x28(%ebp),%eax
c00038b2:	a3 88 1a 01 c0       	mov    %eax,0xc0011a88
  user_pool.phy_addr_start = up_start;
c00038b7:	8b 45 d4             	mov    -0x2c(%ebp),%eax
c00038ba:	a3 c8 1a 01 c0       	mov    %eax,0xc0011ac8

  kernel_pool.pool_size = kernel_free_pages * PG_SIZE;
c00038bf:	0f b7 45 e8          	movzwl -0x18(%ebp),%eax
c00038c3:	c1 e0 0c             	shl    $0xc,%eax
c00038c6:	a3 8c 1a 01 c0       	mov    %eax,0xc0011a8c
  user_pool.pool_size = user_free_pages * PG_SIZE;
c00038cb:	0f b7 45 e6          	movzwl -0x1a(%ebp),%eax
c00038cf:	c1 e0 0c             	shl    $0xc,%eax
c00038d2:	a3 cc 1a 01 c0       	mov    %eax,0xc0011acc

  kernel_pool.pool_bitmap.btmp_bytes_len = kbm_len;
c00038d7:	8b 45 e0             	mov    -0x20(%ebp),%eax
c00038da:	a3 80 1a 01 c0       	mov    %eax,0xc0011a80
  user_pool.pool_bitmap.btmp_bytes_len = ubm_len;
c00038df:	8b 45 dc             	mov    -0x24(%ebp),%eax
c00038e2:	a3 c0 1a 01 c0       	mov    %eax,0xc0011ac0

  kernel_pool.pool_bitmap.bits = (void *)MEM_BITMAP_BASE;
c00038e7:	c7 05 84 1a 01 c0 00 	movl   $0xc009a000,0xc0011a84
c00038ee:	a0 09 c0 
  user_pool.pool_bitmap.bits = (void *)(MEM_BITMAP_BASE + kbm_len);
c00038f1:	8b 45 e0             	mov    -0x20(%ebp),%eax
c00038f4:	2d 00 60 f6 3f       	sub    $0x3ff66000,%eax
c00038f9:	a3 c4 1a 01 c0       	mov    %eax,0xc0011ac4

  /* -----------------------输出内存池信息 -----------------------*/
  put_str("     kernel_pool_bitmap start: ");
c00038fe:	83 ec 0c             	sub    $0xc,%esp
c0003901:	68 c4 c7 00 c0       	push   $0xc000c7c4
c0003906:	e8 25 e1 ff ff       	call   c0001a30 <put_str>
c000390b:	83 c4 10             	add    $0x10,%esp
  put_int((int)kernel_pool.pool_bitmap.bits);
c000390e:	a1 84 1a 01 c0       	mov    0xc0011a84,%eax
c0003913:	83 ec 0c             	sub    $0xc,%esp
c0003916:	50                   	push   %eax
c0003917:	e8 11 e2 ff ff       	call   c0001b2d <put_int>
c000391c:	83 c4 10             	add    $0x10,%esp
  put_str(" kernel_pool_phy_addr start: ");
c000391f:	83 ec 0c             	sub    $0xc,%esp
c0003922:	68 e4 c7 00 c0       	push   $0xc000c7e4
c0003927:	e8 04 e1 ff ff       	call   c0001a30 <put_str>
c000392c:	83 c4 10             	add    $0x10,%esp
  put_int(kernel_pool.phy_addr_start);
c000392f:	a1 88 1a 01 c0       	mov    0xc0011a88,%eax
c0003934:	83 ec 0c             	sub    $0xc,%esp
c0003937:	50                   	push   %eax
c0003938:	e8 f0 e1 ff ff       	call   c0001b2d <put_int>
c000393d:	83 c4 10             	add    $0x10,%esp
  put_str("\n");
c0003940:	83 ec 0c             	sub    $0xc,%esp
c0003943:	68 02 c8 00 c0       	push   $0xc000c802
c0003948:	e8 e3 e0 ff ff       	call   c0001a30 <put_str>
c000394d:	83 c4 10             	add    $0x10,%esp
  put_str("     user_pool_bitmap start: ");
c0003950:	83 ec 0c             	sub    $0xc,%esp
c0003953:	68 04 c8 00 c0       	push   $0xc000c804
c0003958:	e8 d3 e0 ff ff       	call   c0001a30 <put_str>
c000395d:	83 c4 10             	add    $0x10,%esp
  put_int((int)user_pool.pool_bitmap.bits);
c0003960:	a1 c4 1a 01 c0       	mov    0xc0011ac4,%eax
c0003965:	83 ec 0c             	sub    $0xc,%esp
c0003968:	50                   	push   %eax
c0003969:	e8 bf e1 ff ff       	call   c0001b2d <put_int>
c000396e:	83 c4 10             	add    $0x10,%esp
  put_str(" user_pool_phy_addr start: ");
c0003971:	83 ec 0c             	sub    $0xc,%esp
c0003974:	68 22 c8 00 c0       	push   $0xc000c822
c0003979:	e8 b2 e0 ff ff       	call   c0001a30 <put_str>
c000397e:	83 c4 10             	add    $0x10,%esp
  put_int(user_pool.phy_addr_start);
c0003981:	a1 c8 1a 01 c0       	mov    0xc0011ac8,%eax
c0003986:	83 ec 0c             	sub    $0xc,%esp
c0003989:	50                   	push   %eax
c000398a:	e8 9e e1 ff ff       	call   c0001b2d <put_int>
c000398f:	83 c4 10             	add    $0x10,%esp
  put_str("\n");
c0003992:	83 ec 0c             	sub    $0xc,%esp
c0003995:	68 02 c8 00 c0       	push   $0xc000c802
c000399a:	e8 91 e0 ff ff       	call   c0001a30 <put_str>
c000399f:	83 c4 10             	add    $0x10,%esp
  bitmap_init(&kernel_pool.pool_bitmap); // 将位图置0-> 表示位对应的页未分配
c00039a2:	83 ec 0c             	sub    $0xc,%esp
c00039a5:	68 80 1a 01 c0       	push   $0xc0011a80
c00039aa:	e8 cd ed ff ff       	call   c000277c <bitmap_init>
c00039af:	83 c4 10             	add    $0x10,%esp
  bitmap_init(&user_pool.pool_bitmap);
c00039b2:	83 ec 0c             	sub    $0xc,%esp
c00039b5:	68 c0 1a 01 c0       	push   $0xc0011ac0
c00039ba:	e8 bd ed ff ff       	call   c000277c <bitmap_init>
c00039bf:	83 c4 10             	add    $0x10,%esp
  lock_init(&kernel_pool.lock);
c00039c2:	83 ec 0c             	sub    $0xc,%esp
c00039c5:	68 90 1a 01 c0       	push   $0xc0011a90
c00039ca:	e8 70 0a 00 00       	call   c000443f <lock_init>
c00039cf:	83 c4 10             	add    $0x10,%esp
  lock_init(&user_pool.lock);
c00039d2:	83 ec 0c             	sub    $0xc,%esp
c00039d5:	68 d0 1a 01 c0       	push   $0xc0011ad0
c00039da:	e8 60 0a 00 00       	call   c000443f <lock_init>
c00039df:	83 c4 10             	add    $0x10,%esp

  // 初始化内核虚拟地址池
  kernel_vaddr.vaddr_bitmap.btmp_bytes_len = kbm_len;
c00039e2:	8b 45 e0             	mov    -0x20(%ebp),%eax
c00039e5:	a3 ec 1a 01 c0       	mov    %eax,0xc0011aec
  kernel_vaddr.vaddr_bitmap.bits =
      (void *)(MEM_BITMAP_BASE + kbm_len + ubm_len);
c00039ea:	8b 55 e0             	mov    -0x20(%ebp),%edx
c00039ed:	8b 45 dc             	mov    -0x24(%ebp),%eax
c00039f0:	01 d0                	add    %edx,%eax
c00039f2:	2d 00 60 f6 3f       	sub    $0x3ff66000,%eax
  kernel_vaddr.vaddr_bitmap.bits =
c00039f7:	a3 f0 1a 01 c0       	mov    %eax,0xc0011af0
  kernel_vaddr.vaddr_start = K_HEAP_START;
c00039fc:	c7 05 f4 1a 01 c0 00 	movl   $0xc0100000,0xc0011af4
c0003a03:	00 10 c0 
  bitmap_init(&kernel_vaddr.vaddr_bitmap);
c0003a06:	83 ec 0c             	sub    $0xc,%esp
c0003a09:	68 ec 1a 01 c0       	push   $0xc0011aec
c0003a0e:	e8 69 ed ff ff       	call   c000277c <bitmap_init>
c0003a13:	83 c4 10             	add    $0x10,%esp
  put_str("   mem_pool_init done\n");
c0003a16:	83 ec 0c             	sub    $0xc,%esp
c0003a19:	68 3e c8 00 c0       	push   $0xc000c83e
c0003a1e:	e8 0d e0 ff ff       	call   c0001a30 <put_str>
c0003a23:	83 c4 10             	add    $0x10,%esp
}
c0003a26:	90                   	nop
c0003a27:	c9                   	leave  
c0003a28:	c3                   	ret    

c0003a29 <block_desc_init>:

// 初始化内存块描述符数组中的7个描述符，为malloc做准备
void block_desc_init(struct mem_block_desc *desc_array) {
c0003a29:	55                   	push   %ebp
c0003a2a:	89 e5                	mov    %esp,%ebp
c0003a2c:	83 ec 18             	sub    $0x18,%esp
  uint16_t desc_idx;
  uint16_t block_size = 16;
c0003a2f:	66 c7 45 f4 10 00    	movw   $0x10,-0xc(%ebp)

  for (desc_idx = 0; desc_idx < DESC_CNT; desc_idx++) {
c0003a35:	66 c7 45 f6 00 00    	movw   $0x0,-0xa(%ebp)
c0003a3b:	eb 76                	jmp    c0003ab3 <block_desc_init+0x8a>
    desc_array[desc_idx].block_size = block_size;
c0003a3d:	0f b7 55 f6          	movzwl -0xa(%ebp),%edx
c0003a41:	89 d0                	mov    %edx,%eax
c0003a43:	01 c0                	add    %eax,%eax
c0003a45:	01 d0                	add    %edx,%eax
c0003a47:	c1 e0 03             	shl    $0x3,%eax
c0003a4a:	89 c2                	mov    %eax,%edx
c0003a4c:	8b 45 08             	mov    0x8(%ebp),%eax
c0003a4f:	01 c2                	add    %eax,%edx
c0003a51:	0f b7 45 f4          	movzwl -0xc(%ebp),%eax
c0003a55:	89 02                	mov    %eax,(%edx)

    // 初始化arena中的内存块数量
    desc_array[desc_idx].block_per_arena =
        (PG_SIZE - sizeof(struct arena)) / block_size;
c0003a57:	b8 f4 0f 00 00       	mov    $0xff4,%eax
c0003a5c:	ba 00 00 00 00       	mov    $0x0,%edx
c0003a61:	66 f7 75 f4          	divw   -0xc(%ebp)
c0003a65:	89 c1                	mov    %eax,%ecx
    desc_array[desc_idx].block_per_arena =
c0003a67:	0f b7 55 f6          	movzwl -0xa(%ebp),%edx
c0003a6b:	89 d0                	mov    %edx,%eax
c0003a6d:	01 c0                	add    %eax,%eax
c0003a6f:	01 d0                	add    %edx,%eax
c0003a71:	c1 e0 03             	shl    $0x3,%eax
c0003a74:	89 c2                	mov    %eax,%edx
c0003a76:	8b 45 08             	mov    0x8(%ebp),%eax
c0003a79:	01 c2                	add    %eax,%edx
        (PG_SIZE - sizeof(struct arena)) / block_size;
c0003a7b:	0f b7 c1             	movzwl %cx,%eax
    desc_array[desc_idx].block_per_arena =
c0003a7e:	89 42 04             	mov    %eax,0x4(%edx)
    list_init(&desc_array[desc_idx].free_list);
c0003a81:	0f b7 55 f6          	movzwl -0xa(%ebp),%edx
c0003a85:	89 d0                	mov    %edx,%eax
c0003a87:	01 c0                	add    %eax,%eax
c0003a89:	01 d0                	add    %edx,%eax
c0003a8b:	c1 e0 03             	shl    $0x3,%eax
c0003a8e:	89 c2                	mov    %eax,%edx
c0003a90:	8b 45 08             	mov    0x8(%ebp),%eax
c0003a93:	01 d0                	add    %edx,%eax
c0003a95:	83 c0 08             	add    $0x8,%eax
c0003a98:	83 ec 0c             	sub    $0xc,%esp
c0003a9b:	50                   	push   %eax
c0003a9c:	e8 65 07 00 00       	call   c0004206 <list_init>
c0003aa1:	83 c4 10             	add    $0x10,%esp
    block_size *= 2; // 更新为下一个规格内存块
c0003aa4:	66 d1 65 f4          	shlw   -0xc(%ebp)
  for (desc_idx = 0; desc_idx < DESC_CNT; desc_idx++) {
c0003aa8:	0f b7 45 f6          	movzwl -0xa(%ebp),%eax
c0003aac:	83 c0 01             	add    $0x1,%eax
c0003aaf:	66 89 45 f6          	mov    %ax,-0xa(%ebp)
c0003ab3:	66 83 7d f6 06       	cmpw   $0x6,-0xa(%ebp)
c0003ab8:	76 83                	jbe    c0003a3d <block_desc_init+0x14>
    // 下标越低，内存块容量越小
  }
}
c0003aba:	90                   	nop
c0003abb:	90                   	nop
c0003abc:	c9                   	leave  
c0003abd:	c3                   	ret    

c0003abe <mem_init>:

// 内存管理部分初始化入口
void mem_init() {
c0003abe:	55                   	push   %ebp
c0003abf:	89 e5                	mov    %esp,%ebp
c0003ac1:	83 ec 18             	sub    $0x18,%esp
  put_str("mem_init start\n");
c0003ac4:	83 ec 0c             	sub    $0xc,%esp
c0003ac7:	68 55 c8 00 c0       	push   $0xc000c855
c0003acc:	e8 5f df ff ff       	call   c0001a30 <put_str>
c0003ad1:	83 c4 10             	add    $0x10,%esp
  uint32_t mem_bytes_total = (*(uint32_t *)(0xb00));
c0003ad4:	b8 00 0b 00 00       	mov    $0xb00,%eax
c0003ad9:	8b 00                	mov    (%eax),%eax
c0003adb:	89 45 f4             	mov    %eax,-0xc(%ebp)
  mem_pool_init(mem_bytes_total); // 初始化内存池
c0003ade:	83 ec 0c             	sub    $0xc,%esp
c0003ae1:	ff 75 f4             	push   -0xc(%ebp)
c0003ae4:	e8 41 fd ff ff       	call   c000382a <mem_pool_init>
c0003ae9:	83 c4 10             	add    $0x10,%esp
  block_desc_init(k_block_descs); // 初始化mem_block_deesc数组descs
c0003aec:	83 ec 0c             	sub    $0xc,%esp
c0003aef:	68 c0 19 01 c0       	push   $0xc00119c0
c0003af4:	e8 30 ff ff ff       	call   c0003a29 <block_desc_init>
c0003af9:	83 c4 10             	add    $0x10,%esp
  put_str("mem_init done\n");
c0003afc:	83 ec 0c             	sub    $0xc,%esp
c0003aff:	68 65 c8 00 c0       	push   $0xc000c865
c0003b04:	e8 27 df ff ff       	call   c0001a30 <put_str>
c0003b09:	83 c4 10             	add    $0x10,%esp
c0003b0c:	90                   	nop
c0003b0d:	c9                   	leave  
c0003b0e:	c3                   	ret    

c0003b0f <running_thread>:
// 保存cur线程的寄存器映像，将下个线程next的寄存器映像装载到处理器
extern void switch_to(struct task_struct *cur, struct task_struct *next);
extern void init(void);

// 获取当前线程的pcb指针
struct task_struct *running_thread() {
c0003b0f:	55                   	push   %ebp
c0003b10:	89 e5                	mov    %esp,%ebp
c0003b12:	83 ec 10             	sub    $0x10,%esp
  uint32_t esp;
  asm("mov %%esp, %0" : "=g"(esp));
c0003b15:	89 e0                	mov    %esp,%eax
c0003b17:	89 45 fc             	mov    %eax,-0x4(%ebp)
  return (struct task_struct *)(esp &
c0003b1a:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0003b1d:	25 00 f0 ff ff       	and    $0xfffff000,%eax
                                0xfffff000); // 取esp整数部分，即pcb起始地址
}
c0003b22:	c9                   	leave  
c0003b23:	c3                   	ret    

c0003b24 <idle>:

// 系统空闲时运行的线程
static void idle(void *arg UNUSED) {
c0003b24:	55                   	push   %ebp
c0003b25:	89 e5                	mov    %esp,%ebp
c0003b27:	83 ec 08             	sub    $0x8,%esp
  while (1) {
    thread_block(TASK_BLOCKED); // 阻塞自己
c0003b2a:	83 ec 0c             	sub    $0xc,%esp
c0003b2d:	6a 02                	push   $0x2
c0003b2f:	e8 da 04 00 00       	call   c000400e <thread_block>
c0003b34:	83 c4 10             	add    $0x10,%esp
    asm volatile("sti; hlt" ::: "memory");
c0003b37:	fb                   	sti    
c0003b38:	f4                   	hlt    
    thread_block(TASK_BLOCKED); // 阻塞自己
c0003b39:	eb ef                	jmp    c0003b2a <idle+0x6>

c0003b3b <allocate_pid>:
  }
}

// 分配pid
static pid_t allocate_pid(void) {
c0003b3b:	55                   	push   %ebp
c0003b3c:	89 e5                	mov    %esp,%ebp
c0003b3e:	83 ec 08             	sub    $0x8,%esp
  static pid_t next_pid = 0;
  lock_acquire(&pid_lock);
c0003b41:	83 ec 0c             	sub    $0xc,%esp
c0003b44:	68 1c 1b 01 c0       	push   $0xc0011b1c
c0003b49:	e8 cb 0a 00 00       	call   c0004619 <lock_acquire>
c0003b4e:	83 c4 10             	add    $0x10,%esp
  next_pid++;
c0003b51:	0f b7 05 40 1b 01 c0 	movzwl 0xc0011b40,%eax
c0003b58:	83 c0 01             	add    $0x1,%eax
c0003b5b:	66 a3 40 1b 01 c0    	mov    %ax,0xc0011b40
  lock_release(&pid_lock);
c0003b61:	83 ec 0c             	sub    $0xc,%esp
c0003b64:	68 1c 1b 01 c0       	push   $0xc0011b1c
c0003b69:	e8 20 0b 00 00       	call   c000468e <lock_release>
c0003b6e:	83 c4 10             	add    $0x10,%esp
  return next_pid;
c0003b71:	0f b7 05 40 1b 01 c0 	movzwl 0xc0011b40,%eax
}
c0003b78:	c9                   	leave  
c0003b79:	c3                   	ret    

c0003b7a <kernel_thread>:

// 由kernel_thread去执行func(func_arg)
static void kernel_thread(thread_func *func, void *func_arg) {
c0003b7a:	55                   	push   %ebp
c0003b7b:	89 e5                	mov    %esp,%ebp
c0003b7d:	83 ec 08             	sub    $0x8,%esp
  intr_enable(); // 开中断避免func独享处理器
c0003b80:	e8 8f dd ff ff       	call   c0001914 <intr_enable>
  func(func_arg);
c0003b85:	83 ec 0c             	sub    $0xc,%esp
c0003b88:	ff 75 0c             	push   0xc(%ebp)
c0003b8b:	8b 45 08             	mov    0x8(%ebp),%eax
c0003b8e:	ff d0                	call   *%eax
c0003b90:	83 c4 10             	add    $0x10,%esp
}
c0003b93:	90                   	nop
c0003b94:	c9                   	leave  
c0003b95:	c3                   	ret    

c0003b96 <thread_create>:

// 初始化线程栈，将待执行func和func_arg放到栈中相应位置
void thread_create(struct task_struct *pthread, thread_func func,
                   void *func_arg) {
c0003b96:	55                   	push   %ebp
c0003b97:	89 e5                	mov    %esp,%ebp
c0003b99:	83 ec 10             	sub    $0x10,%esp
  pthread->self_kstack -= sizeof(struct intr_stack); // 预留中断使用栈的空间
c0003b9c:	8b 45 08             	mov    0x8(%ebp),%eax
c0003b9f:	8b 00                	mov    (%eax),%eax
c0003ba1:	8d 90 d0 fe ff ff    	lea    -0x130(%eax),%edx
c0003ba7:	8b 45 08             	mov    0x8(%ebp),%eax
c0003baa:	89 10                	mov    %edx,(%eax)
  pthread->self_kstack -= sizeof(struct thread_stack); // 预留线程栈空间
c0003bac:	8b 45 08             	mov    0x8(%ebp),%eax
c0003baf:	8b 00                	mov    (%eax),%eax
c0003bb1:	8d 50 80             	lea    -0x80(%eax),%edx
c0003bb4:	8b 45 08             	mov    0x8(%ebp),%eax
c0003bb7:	89 10                	mov    %edx,(%eax)

  struct thread_stack *kthread_stack =
c0003bb9:	8b 45 08             	mov    0x8(%ebp),%eax
c0003bbc:	8b 00                	mov    (%eax),%eax
c0003bbe:	89 45 fc             	mov    %eax,-0x4(%ebp)
      (struct thread_stack *)pthread->self_kstack;

  // kernel_thread使用ret方式调用
  kthread_stack->eip = kernel_thread;
c0003bc1:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0003bc4:	c7 40 10 7a 3b 00 c0 	movl   $0xc0003b7a,0x10(%eax)
  kthread_stack->function = func;
c0003bcb:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0003bce:	8b 55 0c             	mov    0xc(%ebp),%edx
c0003bd1:	89 50 18             	mov    %edx,0x18(%eax)
  kthread_stack->func_arg = func_arg;
c0003bd4:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0003bd7:	8b 55 10             	mov    0x10(%ebp),%edx
c0003bda:	89 50 1c             	mov    %edx,0x1c(%eax)

  kthread_stack->ebp = kthread_stack->ebx = kthread_stack->esi =
      kthread_stack->edi = 0;
c0003bdd:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0003be0:	c7 40 08 00 00 00 00 	movl   $0x0,0x8(%eax)
c0003be7:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0003bea:	8b 50 08             	mov    0x8(%eax),%edx
  kthread_stack->ebp = kthread_stack->ebx = kthread_stack->esi =
c0003bed:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0003bf0:	89 50 0c             	mov    %edx,0xc(%eax)
c0003bf3:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0003bf6:	8b 50 0c             	mov    0xc(%eax),%edx
c0003bf9:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0003bfc:	89 50 04             	mov    %edx,0x4(%eax)
c0003bff:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0003c02:	8b 50 04             	mov    0x4(%eax),%edx
c0003c05:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0003c08:	89 10                	mov    %edx,(%eax)
}
c0003c0a:	90                   	nop
c0003c0b:	c9                   	leave  
c0003c0c:	c3                   	ret    

c0003c0d <init_thread>:

// 初始化线程基本信息
void init_thread(struct task_struct *pthread, char *name, int prio) {
c0003c0d:	55                   	push   %ebp
c0003c0e:	89 e5                	mov    %esp,%ebp
c0003c10:	83 ec 18             	sub    $0x18,%esp
  memset(pthread, 0, sizeof(*pthread)); // PCB一页清0
c0003c13:	83 ec 04             	sub    $0x4,%esp
c0003c16:	68 18 01 00 00       	push   $0x118
c0003c1b:	6a 00                	push   $0x0
c0003c1d:	ff 75 08             	push   0x8(%ebp)
c0003c20:	e8 89 e7 ff ff       	call   c00023ae <memset>
c0003c25:	83 c4 10             	add    $0x10,%esp
  pthread->pid = allocate_pid();
c0003c28:	e8 0e ff ff ff       	call   c0003b3b <allocate_pid>
c0003c2d:	8b 55 08             	mov    0x8(%ebp),%edx
c0003c30:	66 89 42 04          	mov    %ax,0x4(%edx)
  strcpy(pthread->name, name);
c0003c34:	8b 45 08             	mov    0x8(%ebp),%eax
c0003c37:	83 c0 0c             	add    $0xc,%eax
c0003c3a:	83 ec 08             	sub    $0x8,%esp
c0003c3d:	ff 75 0c             	push   0xc(%ebp)
c0003c40:	50                   	push   %eax
c0003c41:	e8 9f e8 ff ff       	call   c00024e5 <strcpy>
c0003c46:	83 c4 10             	add    $0x10,%esp

  if (pthread == main_thread) {
c0003c49:	a1 f8 1a 01 c0       	mov    0xc0011af8,%eax
c0003c4e:	39 45 08             	cmp    %eax,0x8(%ebp)
c0003c51:	75 0c                	jne    c0003c5f <init_thread+0x52>
    pthread->status = TASK_RUNNING;
c0003c53:	8b 45 08             	mov    0x8(%ebp),%eax
c0003c56:	c7 40 08 00 00 00 00 	movl   $0x0,0x8(%eax)
c0003c5d:	eb 0a                	jmp    c0003c69 <init_thread+0x5c>
  } else {
    pthread->status = TASK_READY;
c0003c5f:	8b 45 08             	mov    0x8(%ebp),%eax
c0003c62:	c7 40 08 01 00 00 00 	movl   $0x1,0x8(%eax)
  }

  pthread->self_kstack =
      (uint32_t *)((uint32_t)pthread + PG_SIZE); // 线程的内核栈顶地址
c0003c69:	8b 45 08             	mov    0x8(%ebp),%eax
c0003c6c:	05 00 10 00 00       	add    $0x1000,%eax
c0003c71:	89 c2                	mov    %eax,%edx
  pthread->self_kstack =
c0003c73:	8b 45 08             	mov    0x8(%ebp),%eax
c0003c76:	89 10                	mov    %edx,(%eax)
  pthread->priority = prio;
c0003c78:	8b 45 10             	mov    0x10(%ebp),%eax
c0003c7b:	89 c2                	mov    %eax,%edx
c0003c7d:	8b 45 08             	mov    0x8(%ebp),%eax
c0003c80:	88 50 1c             	mov    %dl,0x1c(%eax)
  pthread->ticks = prio;
c0003c83:	8b 45 10             	mov    0x10(%ebp),%eax
c0003c86:	89 c2                	mov    %eax,%edx
c0003c88:	8b 45 08             	mov    0x8(%ebp),%eax
c0003c8b:	88 50 1d             	mov    %dl,0x1d(%eax)
  pthread->elapsed_ticks = 0;
c0003c8e:	8b 45 08             	mov    0x8(%ebp),%eax
c0003c91:	c7 40 20 00 00 00 00 	movl   $0x0,0x20(%eax)
  pthread->pgdir = NULL;
c0003c98:	8b 45 08             	mov    0x8(%ebp),%eax
c0003c9b:	c7 40 34 00 00 00 00 	movl   $0x0,0x34(%eax)
  pthread->fd_table[0] = 0; // 标准输入
c0003ca2:	8b 45 08             	mov    0x8(%ebp),%eax
c0003ca5:	c7 80 ec 00 00 00 00 	movl   $0x0,0xec(%eax)
c0003cac:	00 00 00 
  pthread->fd_table[1] = 1; // 标准输出
c0003caf:	8b 45 08             	mov    0x8(%ebp),%eax
c0003cb2:	c7 80 f0 00 00 00 01 	movl   $0x1,0xf0(%eax)
c0003cb9:	00 00 00 
  pthread->fd_table[2] = 2; // 标准错误
c0003cbc:	8b 45 08             	mov    0x8(%ebp),%eax
c0003cbf:	c7 80 f4 00 00 00 02 	movl   $0x2,0xf4(%eax)
c0003cc6:	00 00 00 
  uint8_t fd_idx = 3;
c0003cc9:	c6 45 f7 03          	movb   $0x3,-0x9(%ebp)
  while (fd_idx < MAX_FILES_OPEN_PER_PROC) { // 其余全部置-1
c0003ccd:	eb 1c                	jmp    c0003ceb <init_thread+0xde>
    pthread->fd_table[fd_idx] = -1;
c0003ccf:	0f b6 55 f7          	movzbl -0x9(%ebp),%edx
c0003cd3:	8b 45 08             	mov    0x8(%ebp),%eax
c0003cd6:	83 c2 38             	add    $0x38,%edx
c0003cd9:	c7 44 90 0c ff ff ff 	movl   $0xffffffff,0xc(%eax,%edx,4)
c0003ce0:	ff 
    fd_idx++;
c0003ce1:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0003ce5:	83 c0 01             	add    $0x1,%eax
c0003ce8:	88 45 f7             	mov    %al,-0x9(%ebp)
  while (fd_idx < MAX_FILES_OPEN_PER_PROC) { // 其余全部置-1
c0003ceb:	80 7d f7 07          	cmpb   $0x7,-0x9(%ebp)
c0003cef:	76 de                	jbe    c0003ccf <init_thread+0xc2>
  }
  pthread->cwd_inode_nr = 0;         // 以根目录为默认工作路径
c0003cf1:	8b 45 08             	mov    0x8(%ebp),%eax
c0003cf4:	c7 80 0c 01 00 00 00 	movl   $0x0,0x10c(%eax)
c0003cfb:	00 00 00 
  pthread->stack_magic = 0x20021112; // 自定义魔数
c0003cfe:	8b 45 08             	mov    0x8(%ebp),%eax
c0003d01:	c7 80 14 01 00 00 12 	movl   $0x20021112,0x114(%eax)
c0003d08:	11 02 20 
  pthread->parent_pid = -1;
c0003d0b:	8b 45 08             	mov    0x8(%ebp),%eax
c0003d0e:	66 c7 80 10 01 00 00 	movw   $0xffff,0x110(%eax)
c0003d15:	ff ff 
}
c0003d17:	90                   	nop
c0003d18:	c9                   	leave  
c0003d19:	c3                   	ret    

c0003d1a <thread_start>:

// 创建线程，线程执行函数是function(func_arg)
struct task_struct *thread_start(char *name, int prio, thread_func func,
                                 void *func_arg) {
c0003d1a:	55                   	push   %ebp
c0003d1b:	89 e5                	mov    %esp,%ebp
c0003d1d:	83 ec 18             	sub    $0x18,%esp
  struct task_struct *thread = get_kernel_pages(1); // PCB指针->最低地址
c0003d20:	83 ec 0c             	sub    $0xc,%esp
c0003d23:	6a 01                	push   $0x1
c0003d25:	e8 7f f0 ff ff       	call   c0002da9 <get_kernel_pages>
c0003d2a:	83 c4 10             	add    $0x10,%esp
c0003d2d:	89 45 f4             	mov    %eax,-0xc(%ebp)
  init_thread(thread, name, prio);
c0003d30:	83 ec 04             	sub    $0x4,%esp
c0003d33:	ff 75 0c             	push   0xc(%ebp)
c0003d36:	ff 75 08             	push   0x8(%ebp)
c0003d39:	ff 75 f4             	push   -0xc(%ebp)
c0003d3c:	e8 cc fe ff ff       	call   c0003c0d <init_thread>
c0003d41:	83 c4 10             	add    $0x10,%esp
  thread_create(thread, func, func_arg);
c0003d44:	83 ec 04             	sub    $0x4,%esp
c0003d47:	ff 75 14             	push   0x14(%ebp)
c0003d4a:	ff 75 10             	push   0x10(%ebp)
c0003d4d:	ff 75 f4             	push   -0xc(%ebp)
c0003d50:	e8 41 fe ff ff       	call   c0003b96 <thread_create>
c0003d55:	83 c4 10             	add    $0x10,%esp

  ASSERT(!elem_find(&thread_ready_list, &thread->general_tag));
c0003d58:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003d5b:	83 c0 24             	add    $0x24,%eax
c0003d5e:	83 ec 08             	sub    $0x8,%esp
c0003d61:	50                   	push   %eax
c0003d62:	68 fc 1a 01 c0       	push   $0xc0011afc
c0003d67:	e8 a5 05 00 00       	call   c0004311 <elem_find>
c0003d6c:	83 c4 10             	add    $0x10,%esp
c0003d6f:	85 c0                	test   %eax,%eax
c0003d71:	74 19                	je     c0003d8c <thread_start+0x72>
c0003d73:	68 cc c8 00 c0       	push   $0xc000c8cc
c0003d78:	68 34 cb 00 c0       	push   $0xc000cb34
c0003d7d:	6a 72                	push   $0x72
c0003d7f:	68 01 c9 00 c0       	push   $0xc000c901
c0003d84:	e8 4f e5 ff ff       	call   c00022d8 <panic_spin>
c0003d89:	83 c4 10             	add    $0x10,%esp
  list_append(&thread_ready_list, &thread->general_tag); // 加入就绪线程队列
c0003d8c:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003d8f:	83 c0 24             	add    $0x24,%eax
c0003d92:	83 ec 08             	sub    $0x8,%esp
c0003d95:	50                   	push   %eax
c0003d96:	68 fc 1a 01 c0       	push   $0xc0011afc
c0003d9b:	e8 f7 04 00 00       	call   c0004297 <list_append>
c0003da0:	83 c4 10             	add    $0x10,%esp
  ASSERT(!elem_find(&thread_all_list, &thread->all_list_tag));
c0003da3:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003da6:	83 c0 2c             	add    $0x2c,%eax
c0003da9:	83 ec 08             	sub    $0x8,%esp
c0003dac:	50                   	push   %eax
c0003dad:	68 0c 1b 01 c0       	push   $0xc0011b0c
c0003db2:	e8 5a 05 00 00       	call   c0004311 <elem_find>
c0003db7:	83 c4 10             	add    $0x10,%esp
c0003dba:	85 c0                	test   %eax,%eax
c0003dbc:	74 19                	je     c0003dd7 <thread_start+0xbd>
c0003dbe:	68 14 c9 00 c0       	push   $0xc000c914
c0003dc3:	68 34 cb 00 c0       	push   $0xc000cb34
c0003dc8:	6a 74                	push   $0x74
c0003dca:	68 01 c9 00 c0       	push   $0xc000c901
c0003dcf:	e8 04 e5 ff ff       	call   c00022d8 <panic_spin>
c0003dd4:	83 c4 10             	add    $0x10,%esp
  list_append(&thread_all_list, &thread->all_list_tag); // 加入全部线程队列
c0003dd7:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003dda:	83 c0 2c             	add    $0x2c,%eax
c0003ddd:	83 ec 08             	sub    $0x8,%esp
c0003de0:	50                   	push   %eax
c0003de1:	68 0c 1b 01 c0       	push   $0xc0011b0c
c0003de6:	e8 ac 04 00 00       	call   c0004297 <list_append>
c0003deb:	83 c4 10             	add    $0x10,%esp

  return thread;
c0003dee:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0003df1:	c9                   	leave  
c0003df2:	c3                   	ret    

c0003df3 <make_main_thread>:

// 将kernel中的main函数完善为主线程
static void make_main_thread(void) {
c0003df3:	55                   	push   %ebp
c0003df4:	89 e5                	mov    %esp,%ebp
c0003df6:	83 ec 08             	sub    $0x8,%esp
  main_thread = running_thread();
c0003df9:	e8 11 fd ff ff       	call   c0003b0f <running_thread>
c0003dfe:	a3 f8 1a 01 c0       	mov    %eax,0xc0011af8
  init_thread(main_thread, "main", 31);
c0003e03:	a1 f8 1a 01 c0       	mov    0xc0011af8,%eax
c0003e08:	83 ec 04             	sub    $0x4,%esp
c0003e0b:	6a 1f                	push   $0x1f
c0003e0d:	68 48 c9 00 c0       	push   $0xc000c948
c0003e12:	50                   	push   %eax
c0003e13:	e8 f5 fd ff ff       	call   c0003c0d <init_thread>
c0003e18:	83 c4 10             	add    $0x10,%esp

  ASSERT(!elem_find(&thread_all_list, &main_thread->all_list_tag));
c0003e1b:	a1 f8 1a 01 c0       	mov    0xc0011af8,%eax
c0003e20:	83 c0 2c             	add    $0x2c,%eax
c0003e23:	83 ec 08             	sub    $0x8,%esp
c0003e26:	50                   	push   %eax
c0003e27:	68 0c 1b 01 c0       	push   $0xc0011b0c
c0003e2c:	e8 e0 04 00 00       	call   c0004311 <elem_find>
c0003e31:	83 c4 10             	add    $0x10,%esp
c0003e34:	85 c0                	test   %eax,%eax
c0003e36:	74 19                	je     c0003e51 <make_main_thread+0x5e>
c0003e38:	68 50 c9 00 c0       	push   $0xc000c950
c0003e3d:	68 44 cb 00 c0       	push   $0xc000cb44
c0003e42:	6a 7f                	push   $0x7f
c0003e44:	68 01 c9 00 c0       	push   $0xc000c901
c0003e49:	e8 8a e4 ff ff       	call   c00022d8 <panic_spin>
c0003e4e:	83 c4 10             	add    $0x10,%esp
  list_append(&thread_all_list, &main_thread->all_list_tag);
c0003e51:	a1 f8 1a 01 c0       	mov    0xc0011af8,%eax
c0003e56:	83 c0 2c             	add    $0x2c,%eax
c0003e59:	83 ec 08             	sub    $0x8,%esp
c0003e5c:	50                   	push   %eax
c0003e5d:	68 0c 1b 01 c0       	push   $0xc0011b0c
c0003e62:	e8 30 04 00 00       	call   c0004297 <list_append>
c0003e67:	83 c4 10             	add    $0x10,%esp
}
c0003e6a:	90                   	nop
c0003e6b:	c9                   	leave  
c0003e6c:	c3                   	ret    

c0003e6d <schedule>:

// 调度函数
void schedule() {
c0003e6d:	55                   	push   %ebp
c0003e6e:	89 e5                	mov    %esp,%ebp
c0003e70:	83 ec 18             	sub    $0x18,%esp
  ASSERT(intr_get_status() == INTR_OFF); // 关中断状态
c0003e73:	e8 29 db ff ff       	call   c00019a1 <intr_get_status>
c0003e78:	85 c0                	test   %eax,%eax
c0003e7a:	74 1c                	je     c0003e98 <schedule+0x2b>
c0003e7c:	68 89 c9 00 c0       	push   $0xc000c989
c0003e81:	68 58 cb 00 c0       	push   $0xc000cb58
c0003e86:	68 85 00 00 00       	push   $0x85
c0003e8b:	68 01 c9 00 c0       	push   $0xc000c901
c0003e90:	e8 43 e4 ff ff       	call   c00022d8 <panic_spin>
c0003e95:	83 c4 10             	add    $0x10,%esp

  struct task_struct *cur = running_thread();
c0003e98:	e8 72 fc ff ff       	call   c0003b0f <running_thread>
c0003e9d:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (cur->status == TASK_RUNNING) { // 时间片到了-> 加入就绪队列队尾
c0003ea0:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003ea3:	8b 40 08             	mov    0x8(%eax),%eax
c0003ea6:	85 c0                	test   %eax,%eax
c0003ea8:	75 65                	jne    c0003f0f <schedule+0xa2>
    ASSERT(!elem_find(&thread_ready_list, &cur->general_tag));
c0003eaa:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003ead:	83 c0 24             	add    $0x24,%eax
c0003eb0:	83 ec 08             	sub    $0x8,%esp
c0003eb3:	50                   	push   %eax
c0003eb4:	68 fc 1a 01 c0       	push   $0xc0011afc
c0003eb9:	e8 53 04 00 00       	call   c0004311 <elem_find>
c0003ebe:	83 c4 10             	add    $0x10,%esp
c0003ec1:	85 c0                	test   %eax,%eax
c0003ec3:	74 1c                	je     c0003ee1 <schedule+0x74>
c0003ec5:	68 a8 c9 00 c0       	push   $0xc000c9a8
c0003eca:	68 58 cb 00 c0       	push   $0xc000cb58
c0003ecf:	68 89 00 00 00       	push   $0x89
c0003ed4:	68 01 c9 00 c0       	push   $0xc000c901
c0003ed9:	e8 fa e3 ff ff       	call   c00022d8 <panic_spin>
c0003ede:	83 c4 10             	add    $0x10,%esp
    list_append(&thread_ready_list, &cur->general_tag);
c0003ee1:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003ee4:	83 c0 24             	add    $0x24,%eax
c0003ee7:	83 ec 08             	sub    $0x8,%esp
c0003eea:	50                   	push   %eax
c0003eeb:	68 fc 1a 01 c0       	push   $0xc0011afc
c0003ef0:	e8 a2 03 00 00       	call   c0004297 <list_append>
c0003ef5:	83 c4 10             	add    $0x10,%esp
    cur->ticks = cur->priority;
c0003ef8:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003efb:	0f b6 50 1c          	movzbl 0x1c(%eax),%edx
c0003eff:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003f02:	88 50 1d             	mov    %dl,0x1d(%eax)
    cur->status = TASK_READY;
c0003f05:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003f08:	c7 40 08 01 00 00 00 	movl   $0x1,0x8(%eax)
  } else {
  }

  // 就绪队列中没有可运行任务-> 唤醒idle
  if (list_empty(&thread_ready_list)) {
c0003f0f:	83 ec 0c             	sub    $0xc,%esp
c0003f12:	68 fc 1a 01 c0       	push   $0xc0011afc
c0003f17:	e8 c2 04 00 00       	call   c00043de <list_empty>
c0003f1c:	83 c4 10             	add    $0x10,%esp
c0003f1f:	85 c0                	test   %eax,%eax
c0003f21:	74 11                	je     c0003f34 <schedule+0xc7>
    thread_unblock(idle_thread);
c0003f23:	a1 38 1b 01 c0       	mov    0xc0011b38,%eax
c0003f28:	83 ec 0c             	sub    $0xc,%esp
c0003f2b:	50                   	push   %eax
c0003f2c:	e8 40 01 00 00       	call   c0004071 <thread_unblock>
c0003f31:	83 c4 10             	add    $0x10,%esp
  }
  thread_tag = NULL;
c0003f34:	c7 05 3c 1b 01 c0 00 	movl   $0x0,0xc0011b3c
c0003f3b:	00 00 00 
  thread_tag =
      list_pop(&thread_ready_list); // 弹出就绪队列中的下一个处理线程结点（tag）
c0003f3e:	83 ec 0c             	sub    $0xc,%esp
c0003f41:	68 fc 1a 01 c0       	push   $0xc0011afc
c0003f46:	e8 a4 03 00 00       	call   c00042ef <list_pop>
c0003f4b:	83 c4 10             	add    $0x10,%esp
  thread_tag =
c0003f4e:	a3 3c 1b 01 c0       	mov    %eax,0xc0011b3c
  struct task_struct *next =
      elem2entry(struct task_struct, general_tag, thread_tag);
c0003f53:	a1 3c 1b 01 c0       	mov    0xc0011b3c,%eax
c0003f58:	83 e8 24             	sub    $0x24,%eax
  struct task_struct *next =
c0003f5b:	89 45 f0             	mov    %eax,-0x10(%ebp)
  next->status = TASK_RUNNING;
c0003f5e:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0003f61:	c7 40 08 00 00 00 00 	movl   $0x0,0x8(%eax)

  /* 激活页表，并根据任务是否为进程来修改tss.esp0 */
  process_active(next);
c0003f68:	83 ec 0c             	sub    $0xc,%esp
c0003f6b:	ff 75 f0             	push   -0x10(%ebp)
c0003f6e:	e8 ff 10 00 00       	call   c0005072 <process_active>
c0003f73:	83 c4 10             	add    $0x10,%esp
  // 从此之后进程/线程一律作为内核线程去处理（0特权级、使用内核页表）

  switch_to(cur, next); // 任务切换
c0003f76:	83 ec 08             	sub    $0x8,%esp
c0003f79:	ff 75 f0             	push   -0x10(%ebp)
c0003f7c:	ff 75 f4             	push   -0xc(%ebp)
c0003f7f:	e8 7c 04 00 00       	call   c0004400 <switch_to>
c0003f84:	83 c4 10             	add    $0x10,%esp
}
c0003f87:	90                   	nop
c0003f88:	c9                   	leave  
c0003f89:	c3                   	ret    

c0003f8a <thread_yield>:

// 主动让出cpu，换其他线程运行
void thread_yield(void) {
c0003f8a:	55                   	push   %ebp
c0003f8b:	89 e5                	mov    %esp,%ebp
c0003f8d:	83 ec 18             	sub    $0x18,%esp
  struct task_struct *cur = running_thread();
c0003f90:	e8 7a fb ff ff       	call   c0003b0f <running_thread>
c0003f95:	89 45 f4             	mov    %eax,-0xc(%ebp)
  enum intr_status old_status = intr_disable();
c0003f98:	e8 a0 d9 ff ff       	call   c000193d <intr_disable>
c0003f9d:	89 45 f0             	mov    %eax,-0x10(%ebp)
  ASSERT(!elem_find(&thread_ready_list, &cur->general_tag));
c0003fa0:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003fa3:	83 c0 24             	add    $0x24,%eax
c0003fa6:	83 ec 08             	sub    $0x8,%esp
c0003fa9:	50                   	push   %eax
c0003faa:	68 fc 1a 01 c0       	push   $0xc0011afc
c0003faf:	e8 5d 03 00 00       	call   c0004311 <elem_find>
c0003fb4:	83 c4 10             	add    $0x10,%esp
c0003fb7:	85 c0                	test   %eax,%eax
c0003fb9:	74 1c                	je     c0003fd7 <thread_yield+0x4d>
c0003fbb:	68 a8 c9 00 c0       	push   $0xc000c9a8
c0003fc0:	68 64 cb 00 c0       	push   $0xc000cb64
c0003fc5:	68 a6 00 00 00       	push   $0xa6
c0003fca:	68 01 c9 00 c0       	push   $0xc000c901
c0003fcf:	e8 04 e3 ff ff       	call   c00022d8 <panic_spin>
c0003fd4:	83 c4 10             	add    $0x10,%esp
  list_append(&thread_ready_list, &cur->general_tag);
c0003fd7:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003fda:	83 c0 24             	add    $0x24,%eax
c0003fdd:	83 ec 08             	sub    $0x8,%esp
c0003fe0:	50                   	push   %eax
c0003fe1:	68 fc 1a 01 c0       	push   $0xc0011afc
c0003fe6:	e8 ac 02 00 00       	call   c0004297 <list_append>
c0003feb:	83 c4 10             	add    $0x10,%esp
  cur->status = TASK_READY; // 与thread_block区别
c0003fee:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003ff1:	c7 40 08 01 00 00 00 	movl   $0x1,0x8(%eax)
  schedule();
c0003ff8:	e8 70 fe ff ff       	call   c0003e6d <schedule>
  intr_set_status(old_status);
c0003ffd:	83 ec 0c             	sub    $0xc,%esp
c0004000:	ff 75 f0             	push   -0x10(%ebp)
c0004003:	e8 7b d9 ff ff       	call   c0001983 <intr_set_status>
c0004008:	83 c4 10             	add    $0x10,%esp
}
c000400b:	90                   	nop
c000400c:	c9                   	leave  
c000400d:	c3                   	ret    

c000400e <thread_block>:

// 线程自愿阻塞，标志状态为stat
void thread_block(enum task_status stat) {
c000400e:	55                   	push   %ebp
c000400f:	89 e5                	mov    %esp,%ebp
c0004011:	83 ec 18             	sub    $0x18,%esp
  // TASK_BLOCKED、TASK_WAITING、TASK_HANGING三种状态不会被调度
  ASSERT(((stat == TASK_BLOCKED) || (stat == TASK_WAITING) ||
c0004014:	83 7d 08 02          	cmpl   $0x2,0x8(%ebp)
c0004018:	74 28                	je     c0004042 <thread_block+0x34>
c000401a:	83 7d 08 03          	cmpl   $0x3,0x8(%ebp)
c000401e:	74 22                	je     c0004042 <thread_block+0x34>
c0004020:	83 7d 08 04          	cmpl   $0x4,0x8(%ebp)
c0004024:	74 1c                	je     c0004042 <thread_block+0x34>
c0004026:	68 dc c9 00 c0       	push   $0xc000c9dc
c000402b:	68 74 cb 00 c0       	push   $0xc000cb74
c0004030:	68 b0 00 00 00       	push   $0xb0
c0004035:	68 01 c9 00 c0       	push   $0xc000c901
c000403a:	e8 99 e2 ff ff       	call   c00022d8 <panic_spin>
c000403f:	83 c4 10             	add    $0x10,%esp
          (stat == TASK_HANGING)));
  enum intr_status old_status = intr_disable();
c0004042:	e8 f6 d8 ff ff       	call   c000193d <intr_disable>
c0004047:	89 45 f4             	mov    %eax,-0xc(%ebp)
  struct task_struct *cur_thread = running_thread();
c000404a:	e8 c0 fa ff ff       	call   c0003b0f <running_thread>
c000404f:	89 45 f0             	mov    %eax,-0x10(%ebp)
  cur_thread->status = stat; // 修改状态为非RUNNING，不让其回到ready_list中
c0004052:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0004055:	8b 55 08             	mov    0x8(%ebp),%edx
c0004058:	89 50 08             	mov    %edx,0x8(%eax)
  schedule();                // 将当前线程换下处理器
c000405b:	e8 0d fe ff ff       	call   c0003e6d <schedule>
  intr_set_status(old_status); // 待当前线程被解除阻塞后才继续运行
c0004060:	83 ec 0c             	sub    $0xc,%esp
c0004063:	ff 75 f4             	push   -0xc(%ebp)
c0004066:	e8 18 d9 ff ff       	call   c0001983 <intr_set_status>
c000406b:	83 c4 10             	add    $0x10,%esp
}
c000406e:	90                   	nop
c000406f:	c9                   	leave  
c0004070:	c3                   	ret    

c0004071 <thread_unblock>:

// 线程唤醒
void thread_unblock(struct task_struct *pthread) {
c0004071:	55                   	push   %ebp
c0004072:	89 e5                	mov    %esp,%ebp
c0004074:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status = intr_disable();
c0004077:	e8 c1 d8 ff ff       	call   c000193d <intr_disable>
c000407c:	89 45 f4             	mov    %eax,-0xc(%ebp)
  ASSERT(((pthread->status == TASK_BLOCKED) ||
c000407f:	8b 45 08             	mov    0x8(%ebp),%eax
c0004082:	8b 40 08             	mov    0x8(%eax),%eax
c0004085:	83 f8 02             	cmp    $0x2,%eax
c0004088:	74 32                	je     c00040bc <thread_unblock+0x4b>
c000408a:	8b 45 08             	mov    0x8(%ebp),%eax
c000408d:	8b 40 08             	mov    0x8(%eax),%eax
c0004090:	83 f8 03             	cmp    $0x3,%eax
c0004093:	74 27                	je     c00040bc <thread_unblock+0x4b>
c0004095:	8b 45 08             	mov    0x8(%ebp),%eax
c0004098:	8b 40 08             	mov    0x8(%eax),%eax
c000409b:	83 f8 04             	cmp    $0x4,%eax
c000409e:	74 1c                	je     c00040bc <thread_unblock+0x4b>
c00040a0:	68 2c ca 00 c0       	push   $0xc000ca2c
c00040a5:	68 84 cb 00 c0       	push   $0xc000cb84
c00040aa:	68 bc 00 00 00       	push   $0xbc
c00040af:	68 01 c9 00 c0       	push   $0xc000c901
c00040b4:	e8 1f e2 ff ff       	call   c00022d8 <panic_spin>
c00040b9:	83 c4 10             	add    $0x10,%esp
          (pthread->status == TASK_WAITING) ||
          (pthread->status == TASK_HANGING)));
  if (pthread->status != TASK_READY) {
c00040bc:	8b 45 08             	mov    0x8(%ebp),%eax
c00040bf:	8b 40 08             	mov    0x8(%eax),%eax
c00040c2:	83 f8 01             	cmp    $0x1,%eax
c00040c5:	0f 84 8f 00 00 00    	je     c000415a <thread_unblock+0xe9>
    ASSERT(!elem_find(&thread_ready_list, &pthread->general_tag));
c00040cb:	8b 45 08             	mov    0x8(%ebp),%eax
c00040ce:	83 c0 24             	add    $0x24,%eax
c00040d1:	83 ec 08             	sub    $0x8,%esp
c00040d4:	50                   	push   %eax
c00040d5:	68 fc 1a 01 c0       	push   $0xc0011afc
c00040da:	e8 32 02 00 00       	call   c0004311 <elem_find>
c00040df:	83 c4 10             	add    $0x10,%esp
c00040e2:	85 c0                	test   %eax,%eax
c00040e4:	74 1c                	je     c0004102 <thread_unblock+0x91>
c00040e6:	68 9c ca 00 c0       	push   $0xc000ca9c
c00040eb:	68 84 cb 00 c0       	push   $0xc000cb84
c00040f0:	68 c0 00 00 00       	push   $0xc0
c00040f5:	68 01 c9 00 c0       	push   $0xc000c901
c00040fa:	e8 d9 e1 ff ff       	call   c00022d8 <panic_spin>
c00040ff:	83 c4 10             	add    $0x10,%esp
    if (elem_find(&thread_ready_list, &pthread->general_tag)) {
c0004102:	8b 45 08             	mov    0x8(%ebp),%eax
c0004105:	83 c0 24             	add    $0x24,%eax
c0004108:	83 ec 08             	sub    $0x8,%esp
c000410b:	50                   	push   %eax
c000410c:	68 fc 1a 01 c0       	push   $0xc0011afc
c0004111:	e8 fb 01 00 00       	call   c0004311 <elem_find>
c0004116:	83 c4 10             	add    $0x10,%esp
c0004119:	85 c0                	test   %eax,%eax
c000411b:	74 1c                	je     c0004139 <thread_unblock+0xc8>
      PANIC("thread_unblock: blocked thread in ready_list\n");
c000411d:	68 d4 ca 00 c0       	push   $0xc000cad4
c0004122:	68 84 cb 00 c0       	push   $0xc000cb84
c0004127:	68 c2 00 00 00       	push   $0xc2
c000412c:	68 01 c9 00 c0       	push   $0xc000c901
c0004131:	e8 a2 e1 ff ff       	call   c00022d8 <panic_spin>
c0004136:	83 c4 10             	add    $0x10,%esp
    }
    list_push(&thread_ready_list,
c0004139:	8b 45 08             	mov    0x8(%ebp),%eax
c000413c:	83 c0 24             	add    $0x24,%eax
c000413f:	83 ec 08             	sub    $0x8,%esp
c0004142:	50                   	push   %eax
c0004143:	68 fc 1a 01 c0       	push   $0xc0011afc
c0004148:	e8 2c 01 00 00       	call   c0004279 <list_push>
c000414d:	83 c4 10             	add    $0x10,%esp
              &pthread->general_tag); // 放在就绪队列最前面(尽快调度
    pthread->status = TASK_READY;
c0004150:	8b 45 08             	mov    0x8(%ebp),%eax
c0004153:	c7 40 08 01 00 00 00 	movl   $0x1,0x8(%eax)
  }
  intr_set_status(old_status);
c000415a:	83 ec 0c             	sub    $0xc,%esp
c000415d:	ff 75 f4             	push   -0xc(%ebp)
c0004160:	e8 1e d8 ff ff       	call   c0001983 <intr_set_status>
c0004165:	83 c4 10             	add    $0x10,%esp
}
c0004168:	90                   	nop
c0004169:	c9                   	leave  
c000416a:	c3                   	ret    

c000416b <fork_pid>:

// 为fork分配一个pid
pid_t fork_pid(void) { return allocate_pid(); }
c000416b:	55                   	push   %ebp
c000416c:	89 e5                	mov    %esp,%ebp
c000416e:	83 ec 08             	sub    $0x8,%esp
c0004171:	e8 c5 f9 ff ff       	call   c0003b3b <allocate_pid>
c0004176:	c9                   	leave  
c0004177:	c3                   	ret    

c0004178 <thread_init>:

// 初始化线程环境
void thread_init(void) {
c0004178:	55                   	push   %ebp
c0004179:	89 e5                	mov    %esp,%ebp
c000417b:	83 ec 08             	sub    $0x8,%esp
  put_str("thread_init start\n");
c000417e:	83 ec 0c             	sub    $0xc,%esp
c0004181:	68 02 cb 00 c0       	push   $0xc000cb02
c0004186:	e8 a5 d8 ff ff       	call   c0001a30 <put_str>
c000418b:	83 c4 10             	add    $0x10,%esp

  list_init(&thread_ready_list);
c000418e:	83 ec 0c             	sub    $0xc,%esp
c0004191:	68 fc 1a 01 c0       	push   $0xc0011afc
c0004196:	e8 6b 00 00 00       	call   c0004206 <list_init>
c000419b:	83 c4 10             	add    $0x10,%esp
  list_init(&thread_all_list);
c000419e:	83 ec 0c             	sub    $0xc,%esp
c00041a1:	68 0c 1b 01 c0       	push   $0xc0011b0c
c00041a6:	e8 5b 00 00 00       	call   c0004206 <list_init>
c00041ab:	83 c4 10             	add    $0x10,%esp
  lock_init(&pid_lock);
c00041ae:	83 ec 0c             	sub    $0xc,%esp
c00041b1:	68 1c 1b 01 c0       	push   $0xc0011b1c
c00041b6:	e8 84 02 00 00       	call   c000443f <lock_init>
c00041bb:	83 c4 10             	add    $0x10,%esp

  process_execute(init, "init"); // 第一个初始化，这是第一个进程，init进程pid为1
c00041be:	83 ec 08             	sub    $0x8,%esp
c00041c1:	68 15 cb 00 c0       	push   $0xc000cb15
c00041c6:	68 3d 15 00 c0       	push   $0xc000153d
c00041cb:	e8 b2 0f 00 00       	call   c0005182 <process_execute>
c00041d0:	83 c4 10             	add    $0x10,%esp
  make_main_thread(); // 为当前main函数创建线程，在其pcb中写入线程信息
c00041d3:	e8 1b fc ff ff       	call   c0003df3 <make_main_thread>
  idle_thread = thread_start("idle", 10, idle, NULL); // 创建idle线程
c00041d8:	6a 00                	push   $0x0
c00041da:	68 24 3b 00 c0       	push   $0xc0003b24
c00041df:	6a 0a                	push   $0xa
c00041e1:	68 1a cb 00 c0       	push   $0xc000cb1a
c00041e6:	e8 2f fb ff ff       	call   c0003d1a <thread_start>
c00041eb:	83 c4 10             	add    $0x10,%esp
c00041ee:	a3 38 1b 01 c0       	mov    %eax,0xc0011b38
  put_str("thread_init done\n");
c00041f3:	83 ec 0c             	sub    $0xc,%esp
c00041f6:	68 1f cb 00 c0       	push   $0xc000cb1f
c00041fb:	e8 30 d8 ff ff       	call   c0001a30 <put_str>
c0004200:	83 c4 10             	add    $0x10,%esp
c0004203:	90                   	nop
c0004204:	c9                   	leave  
c0004205:	c3                   	ret    

c0004206 <list_init>:
#include "global.h"
#include "interrupt.h"
#include "stdint.h"
#include "stdio_kernel.h"

void list_init(struct list *list) {
c0004206:	55                   	push   %ebp
c0004207:	89 e5                	mov    %esp,%ebp
  list->head.prev = NULL;
c0004209:	8b 45 08             	mov    0x8(%ebp),%eax
c000420c:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
  list->head.next = &list->tail;
c0004212:	8b 45 08             	mov    0x8(%ebp),%eax
c0004215:	8d 50 08             	lea    0x8(%eax),%edx
c0004218:	8b 45 08             	mov    0x8(%ebp),%eax
c000421b:	89 50 04             	mov    %edx,0x4(%eax)
  list->tail.prev = &list->head;
c000421e:	8b 55 08             	mov    0x8(%ebp),%edx
c0004221:	8b 45 08             	mov    0x8(%ebp),%eax
c0004224:	89 50 08             	mov    %edx,0x8(%eax)
  list->tail.next = NULL;
c0004227:	8b 45 08             	mov    0x8(%ebp),%eax
c000422a:	c7 40 0c 00 00 00 00 	movl   $0x0,0xc(%eax)
}
c0004231:	90                   	nop
c0004232:	5d                   	pop    %ebp
c0004233:	c3                   	ret    

c0004234 <list_insert_before>:

// 把elem插入在元素before之前
void list_insert_before(struct list_elem *before, struct list_elem *elem) {
c0004234:	55                   	push   %ebp
c0004235:	89 e5                	mov    %esp,%ebp
c0004237:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status = intr_disable(); // 关中断保证原子性
c000423a:	e8 fe d6 ff ff       	call   c000193d <intr_disable>
c000423f:	89 45 f4             	mov    %eax,-0xc(%ebp)
  before->prev->next = elem;
c0004242:	8b 45 08             	mov    0x8(%ebp),%eax
c0004245:	8b 00                	mov    (%eax),%eax
c0004247:	8b 55 0c             	mov    0xc(%ebp),%edx
c000424a:	89 50 04             	mov    %edx,0x4(%eax)
  elem->prev = before->prev;
c000424d:	8b 45 08             	mov    0x8(%ebp),%eax
c0004250:	8b 10                	mov    (%eax),%edx
c0004252:	8b 45 0c             	mov    0xc(%ebp),%eax
c0004255:	89 10                	mov    %edx,(%eax)
  elem->next = before;
c0004257:	8b 45 0c             	mov    0xc(%ebp),%eax
c000425a:	8b 55 08             	mov    0x8(%ebp),%edx
c000425d:	89 50 04             	mov    %edx,0x4(%eax)
  before->prev = elem;
c0004260:	8b 45 08             	mov    0x8(%ebp),%eax
c0004263:	8b 55 0c             	mov    0xc(%ebp),%edx
c0004266:	89 10                	mov    %edx,(%eax)
  intr_set_status(old_status);
c0004268:	83 ec 0c             	sub    $0xc,%esp
c000426b:	ff 75 f4             	push   -0xc(%ebp)
c000426e:	e8 10 d7 ff ff       	call   c0001983 <intr_set_status>
c0004273:	83 c4 10             	add    $0x10,%esp
}
c0004276:	90                   	nop
c0004277:	c9                   	leave  
c0004278:	c3                   	ret    

c0004279 <list_push>:

// 添加元素到列表队首
void list_push(struct list *plist, struct list_elem *elem) {
c0004279:	55                   	push   %ebp
c000427a:	89 e5                	mov    %esp,%ebp
c000427c:	83 ec 08             	sub    $0x8,%esp
  list_insert_before(plist->head.next, elem);
c000427f:	8b 45 08             	mov    0x8(%ebp),%eax
c0004282:	8b 40 04             	mov    0x4(%eax),%eax
c0004285:	83 ec 08             	sub    $0x8,%esp
c0004288:	ff 75 0c             	push   0xc(%ebp)
c000428b:	50                   	push   %eax
c000428c:	e8 a3 ff ff ff       	call   c0004234 <list_insert_before>
c0004291:	83 c4 10             	add    $0x10,%esp
}
c0004294:	90                   	nop
c0004295:	c9                   	leave  
c0004296:	c3                   	ret    

c0004297 <list_append>:

// 追加元素到链表队尾
void list_append(struct list *plist, struct list_elem *elem) {
c0004297:	55                   	push   %ebp
c0004298:	89 e5                	mov    %esp,%ebp
c000429a:	83 ec 08             	sub    $0x8,%esp
  list_insert_before(&plist->tail, elem);
c000429d:	8b 45 08             	mov    0x8(%ebp),%eax
c00042a0:	83 c0 08             	add    $0x8,%eax
c00042a3:	83 ec 08             	sub    $0x8,%esp
c00042a6:	ff 75 0c             	push   0xc(%ebp)
c00042a9:	50                   	push   %eax
c00042aa:	e8 85 ff ff ff       	call   c0004234 <list_insert_before>
c00042af:	83 c4 10             	add    $0x10,%esp
}
c00042b2:	90                   	nop
c00042b3:	c9                   	leave  
c00042b4:	c3                   	ret    

c00042b5 <list_remove>:

void list_remove(struct list_elem *pelem) {
c00042b5:	55                   	push   %ebp
c00042b6:	89 e5                	mov    %esp,%ebp
c00042b8:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status = intr_disable();
c00042bb:	e8 7d d6 ff ff       	call   c000193d <intr_disable>
c00042c0:	89 45 f4             	mov    %eax,-0xc(%ebp)
  pelem->prev->next = pelem->next;
c00042c3:	8b 45 08             	mov    0x8(%ebp),%eax
c00042c6:	8b 00                	mov    (%eax),%eax
c00042c8:	8b 55 08             	mov    0x8(%ebp),%edx
c00042cb:	8b 52 04             	mov    0x4(%edx),%edx
c00042ce:	89 50 04             	mov    %edx,0x4(%eax)
  pelem->next->prev = pelem->prev;
c00042d1:	8b 45 08             	mov    0x8(%ebp),%eax
c00042d4:	8b 40 04             	mov    0x4(%eax),%eax
c00042d7:	8b 55 08             	mov    0x8(%ebp),%edx
c00042da:	8b 12                	mov    (%edx),%edx
c00042dc:	89 10                	mov    %edx,(%eax)
  intr_set_status(old_status);
c00042de:	83 ec 0c             	sub    $0xc,%esp
c00042e1:	ff 75 f4             	push   -0xc(%ebp)
c00042e4:	e8 9a d6 ff ff       	call   c0001983 <intr_set_status>
c00042e9:	83 c4 10             	add    $0x10,%esp
}
c00042ec:	90                   	nop
c00042ed:	c9                   	leave  
c00042ee:	c3                   	ret    

c00042ef <list_pop>:

// 将链表第1个元素弹出并返回
struct list_elem *list_pop(struct list *plist) {
c00042ef:	55                   	push   %ebp
c00042f0:	89 e5                	mov    %esp,%ebp
c00042f2:	83 ec 18             	sub    $0x18,%esp
  struct list_elem *elem = plist->head.next;
c00042f5:	8b 45 08             	mov    0x8(%ebp),%eax
c00042f8:	8b 40 04             	mov    0x4(%eax),%eax
c00042fb:	89 45 f4             	mov    %eax,-0xc(%ebp)
  list_remove(elem);
c00042fe:	83 ec 0c             	sub    $0xc,%esp
c0004301:	ff 75 f4             	push   -0xc(%ebp)
c0004304:	e8 ac ff ff ff       	call   c00042b5 <list_remove>
c0004309:	83 c4 10             	add    $0x10,%esp
  return elem;
c000430c:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c000430f:	c9                   	leave  
c0004310:	c3                   	ret    

c0004311 <elem_find>:

bool elem_find(struct list *plist, struct list_elem *obj_elem) {
c0004311:	55                   	push   %ebp
c0004312:	89 e5                	mov    %esp,%ebp
c0004314:	83 ec 10             	sub    $0x10,%esp
  struct list_elem *elem = plist->head.next;
c0004317:	8b 45 08             	mov    0x8(%ebp),%eax
c000431a:	8b 40 04             	mov    0x4(%eax),%eax
c000431d:	89 45 fc             	mov    %eax,-0x4(%ebp)
  while (elem != &plist->tail) {
c0004320:	eb 18                	jmp    c000433a <elem_find+0x29>
    if (elem == obj_elem) {
c0004322:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0004325:	3b 45 0c             	cmp    0xc(%ebp),%eax
c0004328:	75 07                	jne    c0004331 <elem_find+0x20>
      return true;
c000432a:	b8 01 00 00 00       	mov    $0x1,%eax
c000432f:	eb 19                	jmp    c000434a <elem_find+0x39>
    }
    elem = elem->next;
c0004331:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0004334:	8b 40 04             	mov    0x4(%eax),%eax
c0004337:	89 45 fc             	mov    %eax,-0x4(%ebp)
  while (elem != &plist->tail) {
c000433a:	8b 45 08             	mov    0x8(%ebp),%eax
c000433d:	83 c0 08             	add    $0x8,%eax
c0004340:	39 45 fc             	cmp    %eax,-0x4(%ebp)
c0004343:	75 dd                	jne    c0004322 <elem_find+0x11>
  }
  return false;
c0004345:	b8 00 00 00 00       	mov    $0x0,%eax
}
c000434a:	c9                   	leave  
c000434b:	c3                   	ret    

c000434c <list_traversal>:

// 遍历逐个判断是否有符合条件(回调函数f)的元素
struct list_elem *list_traversal(struct list *plist, func f, int arg) {
c000434c:	55                   	push   %ebp
c000434d:	89 e5                	mov    %esp,%ebp
c000434f:	83 ec 18             	sub    $0x18,%esp
  struct list_elem *elem = plist->head.next;
c0004352:	8b 45 08             	mov    0x8(%ebp),%eax
c0004355:	8b 40 04             	mov    0x4(%eax),%eax
c0004358:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (list_empty(plist)) {
c000435b:	83 ec 0c             	sub    $0xc,%esp
c000435e:	ff 75 08             	push   0x8(%ebp)
c0004361:	e8 78 00 00 00       	call   c00043de <list_empty>
c0004366:	83 c4 10             	add    $0x10,%esp
c0004369:	85 c0                	test   %eax,%eax
c000436b:	74 2a                	je     c0004397 <list_traversal+0x4b>
    return NULL;
c000436d:	b8 00 00 00 00       	mov    $0x0,%eax
c0004372:	eb 33                	jmp    c00043a7 <list_traversal+0x5b>
  }
  while (elem != &plist->tail) {
    //printk("%x \n", elem);
    if (f(elem, arg)) {
c0004374:	83 ec 08             	sub    $0x8,%esp
c0004377:	ff 75 10             	push   0x10(%ebp)
c000437a:	ff 75 f4             	push   -0xc(%ebp)
c000437d:	8b 45 0c             	mov    0xc(%ebp),%eax
c0004380:	ff d0                	call   *%eax
c0004382:	83 c4 10             	add    $0x10,%esp
c0004385:	85 c0                	test   %eax,%eax
c0004387:	74 05                	je     c000438e <list_traversal+0x42>
      return elem;
c0004389:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000438c:	eb 19                	jmp    c00043a7 <list_traversal+0x5b>
    }
    elem = elem->next;
c000438e:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0004391:	8b 40 04             	mov    0x4(%eax),%eax
c0004394:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while (elem != &plist->tail) {
c0004397:	8b 45 08             	mov    0x8(%ebp),%eax
c000439a:	83 c0 08             	add    $0x8,%eax
c000439d:	39 45 f4             	cmp    %eax,-0xc(%ebp)
c00043a0:	75 d2                	jne    c0004374 <list_traversal+0x28>
  }
  return NULL;
c00043a2:	b8 00 00 00 00       	mov    $0x0,%eax
}
c00043a7:	c9                   	leave  
c00043a8:	c3                   	ret    

c00043a9 <list_len>:

uint32_t list_len(struct list *plist) {
c00043a9:	55                   	push   %ebp
c00043aa:	89 e5                	mov    %esp,%ebp
c00043ac:	83 ec 10             	sub    $0x10,%esp
  struct list_elem *elem = plist->head.next;
c00043af:	8b 45 08             	mov    0x8(%ebp),%eax
c00043b2:	8b 40 04             	mov    0x4(%eax),%eax
c00043b5:	89 45 fc             	mov    %eax,-0x4(%ebp)
  uint32_t len = 0;
c00043b8:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%ebp)
  while (elem != &plist->tail) {
c00043bf:	eb 0d                	jmp    c00043ce <list_len+0x25>
    len++;
c00043c1:	83 45 f8 01          	addl   $0x1,-0x8(%ebp)
    elem = elem->next;
c00043c5:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00043c8:	8b 40 04             	mov    0x4(%eax),%eax
c00043cb:	89 45 fc             	mov    %eax,-0x4(%ebp)
  while (elem != &plist->tail) {
c00043ce:	8b 45 08             	mov    0x8(%ebp),%eax
c00043d1:	83 c0 08             	add    $0x8,%eax
c00043d4:	39 45 fc             	cmp    %eax,-0x4(%ebp)
c00043d7:	75 e8                	jne    c00043c1 <list_len+0x18>
  }
  return len;
c00043d9:	8b 45 f8             	mov    -0x8(%ebp),%eax
}
c00043dc:	c9                   	leave  
c00043dd:	c3                   	ret    

c00043de <list_empty>:

bool list_empty(struct list *plist) {
c00043de:	55                   	push   %ebp
c00043df:	89 e5                	mov    %esp,%ebp
  return (plist->head.next == &plist->tail ? true : false);
c00043e1:	8b 45 08             	mov    0x8(%ebp),%eax
c00043e4:	8b 40 04             	mov    0x4(%eax),%eax
c00043e7:	8b 55 08             	mov    0x8(%ebp),%edx
c00043ea:	83 c2 08             	add    $0x8,%edx
c00043ed:	39 d0                	cmp    %edx,%eax
c00043ef:	0f 94 c0             	sete   %al
c00043f2:	0f b6 c0             	movzbl %al,%eax
c00043f5:	5d                   	pop    %ebp
c00043f6:	c3                   	ret    
c00043f7:	66 90                	xchg   %ax,%ax
c00043f9:	66 90                	xchg   %ax,%ax
c00043fb:	66 90                	xchg   %ax,%ax
c00043fd:	66 90                	xchg   %ax,%ax
c00043ff:	90                   	nop

c0004400 <switch_to>:
c0004400:	56                   	push   %esi
c0004401:	57                   	push   %edi
c0004402:	53                   	push   %ebx
c0004403:	55                   	push   %ebp
c0004404:	8b 44 24 14          	mov    0x14(%esp),%eax
c0004408:	89 20                	mov    %esp,(%eax)
c000440a:	8b 44 24 18          	mov    0x18(%esp),%eax
c000440e:	8b 20                	mov    (%eax),%esp
c0004410:	5d                   	pop    %ebp
c0004411:	5b                   	pop    %ebx
c0004412:	5f                   	pop    %edi
c0004413:	5e                   	pop    %esi
c0004414:	c3                   	ret    

c0004415 <sema_init>:
#include "interrupt.h"
#include "list.h"
#include "stdint.h"
#include "thread.h"

void sema_init(struct semaphore *psema, uint8_t value) {
c0004415:	55                   	push   %ebp
c0004416:	89 e5                	mov    %esp,%ebp
c0004418:	83 ec 18             	sub    $0x18,%esp
c000441b:	8b 45 0c             	mov    0xc(%ebp),%eax
c000441e:	88 45 f4             	mov    %al,-0xc(%ebp)
  psema->value = value;
c0004421:	8b 45 08             	mov    0x8(%ebp),%eax
c0004424:	0f b6 55 f4          	movzbl -0xc(%ebp),%edx
c0004428:	88 10                	mov    %dl,(%eax)
  list_init(&psema->waiters);
c000442a:	8b 45 08             	mov    0x8(%ebp),%eax
c000442d:	83 c0 04             	add    $0x4,%eax
c0004430:	83 ec 0c             	sub    $0xc,%esp
c0004433:	50                   	push   %eax
c0004434:	e8 cd fd ff ff       	call   c0004206 <list_init>
c0004439:	83 c4 10             	add    $0x10,%esp
}
c000443c:	90                   	nop
c000443d:	c9                   	leave  
c000443e:	c3                   	ret    

c000443f <lock_init>:

void lock_init(struct lock *plock) {
c000443f:	55                   	push   %ebp
c0004440:	89 e5                	mov    %esp,%ebp
c0004442:	83 ec 08             	sub    $0x8,%esp
  plock->holder = NULL;
c0004445:	8b 45 08             	mov    0x8(%ebp),%eax
c0004448:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
  plock->holder_repeat_nr = 0;
c000444e:	8b 45 08             	mov    0x8(%ebp),%eax
c0004451:	c7 40 18 00 00 00 00 	movl   $0x0,0x18(%eax)
  sema_init(&plock->semaphore, 1);
c0004458:	8b 45 08             	mov    0x8(%ebp),%eax
c000445b:	83 c0 04             	add    $0x4,%eax
c000445e:	83 ec 08             	sub    $0x8,%esp
c0004461:	6a 01                	push   $0x1
c0004463:	50                   	push   %eax
c0004464:	e8 ac ff ff ff       	call   c0004415 <sema_init>
c0004469:	83 c4 10             	add    $0x10,%esp
}
c000446c:	90                   	nop
c000446d:	c9                   	leave  
c000446e:	c3                   	ret    

c000446f <sema_down>:

void sema_down(struct semaphore *psema) {
c000446f:	55                   	push   %ebp
c0004470:	89 e5                	mov    %esp,%ebp
c0004472:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status = intr_disable();
c0004475:	e8 c3 d4 ff ff       	call   c000193d <intr_disable>
c000447a:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while (psema->value == 0) { // 已经被别人持有
c000447d:	e9 98 00 00 00       	jmp    c000451a <sema_down+0xab>
    ASSERT(!elem_find(&psema->waiters, &running_thread()->general_tag));
c0004482:	e8 88 f6 ff ff       	call   c0003b0f <running_thread>
c0004487:	8d 50 24             	lea    0x24(%eax),%edx
c000448a:	8b 45 08             	mov    0x8(%ebp),%eax
c000448d:	83 c0 04             	add    $0x4,%eax
c0004490:	83 ec 08             	sub    $0x8,%esp
c0004493:	52                   	push   %edx
c0004494:	50                   	push   %eax
c0004495:	e8 77 fe ff ff       	call   c0004311 <elem_find>
c000449a:	83 c4 10             	add    $0x10,%esp
c000449d:	85 c0                	test   %eax,%eax
c000449f:	74 19                	je     c00044ba <sema_down+0x4b>
c00044a1:	68 94 cb 00 c0       	push   $0xc000cb94
c00044a6:	68 98 cc 00 c0       	push   $0xc000cc98
c00044ab:	6a 16                	push   $0x16
c00044ad:	68 d0 cb 00 c0       	push   $0xc000cbd0
c00044b2:	e8 21 de ff ff       	call   c00022d8 <panic_spin>
c00044b7:	83 c4 10             	add    $0x10,%esp
    if (elem_find(&psema->waiters, &running_thread()->general_tag)) {
c00044ba:	e8 50 f6 ff ff       	call   c0003b0f <running_thread>
c00044bf:	8d 50 24             	lea    0x24(%eax),%edx
c00044c2:	8b 45 08             	mov    0x8(%ebp),%eax
c00044c5:	83 c0 04             	add    $0x4,%eax
c00044c8:	83 ec 08             	sub    $0x8,%esp
c00044cb:	52                   	push   %edx
c00044cc:	50                   	push   %eax
c00044cd:	e8 3f fe ff ff       	call   c0004311 <elem_find>
c00044d2:	83 c4 10             	add    $0x10,%esp
c00044d5:	85 c0                	test   %eax,%eax
c00044d7:	74 19                	je     c00044f2 <sema_down+0x83>
      PANIC("sema_down: thread blocked has been in waiters_list\n");
c00044d9:	68 e0 cb 00 c0       	push   $0xc000cbe0
c00044de:	68 98 cc 00 c0       	push   $0xc000cc98
c00044e3:	6a 18                	push   $0x18
c00044e5:	68 d0 cb 00 c0       	push   $0xc000cbd0
c00044ea:	e8 e9 dd ff ff       	call   c00022d8 <panic_spin>
c00044ef:	83 c4 10             	add    $0x10,%esp
    }
    // 当前线程把自己加入该锁的等待队列，然后阻塞自己
    list_append(&psema->waiters, &running_thread()->general_tag);
c00044f2:	e8 18 f6 ff ff       	call   c0003b0f <running_thread>
c00044f7:	8d 50 24             	lea    0x24(%eax),%edx
c00044fa:	8b 45 08             	mov    0x8(%ebp),%eax
c00044fd:	83 c0 04             	add    $0x4,%eax
c0004500:	83 ec 08             	sub    $0x8,%esp
c0004503:	52                   	push   %edx
c0004504:	50                   	push   %eax
c0004505:	e8 8d fd ff ff       	call   c0004297 <list_append>
c000450a:	83 c4 10             	add    $0x10,%esp
    thread_block(TASK_BLOCKED);
c000450d:	83 ec 0c             	sub    $0xc,%esp
c0004510:	6a 02                	push   $0x2
c0004512:	e8 f7 fa ff ff       	call   c000400e <thread_block>
c0004517:	83 c4 10             	add    $0x10,%esp
  while (psema->value == 0) { // 已经被别人持有
c000451a:	8b 45 08             	mov    0x8(%ebp),%eax
c000451d:	0f b6 00             	movzbl (%eax),%eax
c0004520:	84 c0                	test   %al,%al
c0004522:	0f 84 5a ff ff ff    	je     c0004482 <sema_down+0x13>
  }
  // value=1或被唤醒后-> 获得锁
  psema->value--;
c0004528:	8b 45 08             	mov    0x8(%ebp),%eax
c000452b:	0f b6 00             	movzbl (%eax),%eax
c000452e:	8d 50 ff             	lea    -0x1(%eax),%edx
c0004531:	8b 45 08             	mov    0x8(%ebp),%eax
c0004534:	88 10                	mov    %dl,(%eax)
  ASSERT(psema->value == 0);
c0004536:	8b 45 08             	mov    0x8(%ebp),%eax
c0004539:	0f b6 00             	movzbl (%eax),%eax
c000453c:	84 c0                	test   %al,%al
c000453e:	74 19                	je     c0004559 <sema_down+0xea>
c0004540:	68 14 cc 00 c0       	push   $0xc000cc14
c0004545:	68 98 cc 00 c0       	push   $0xc000cc98
c000454a:	6a 20                	push   $0x20
c000454c:	68 d0 cb 00 c0       	push   $0xc000cbd0
c0004551:	e8 82 dd ff ff       	call   c00022d8 <panic_spin>
c0004556:	83 c4 10             	add    $0x10,%esp
  intr_set_status(old_status);
c0004559:	83 ec 0c             	sub    $0xc,%esp
c000455c:	ff 75 f4             	push   -0xc(%ebp)
c000455f:	e8 1f d4 ff ff       	call   c0001983 <intr_set_status>
c0004564:	83 c4 10             	add    $0x10,%esp
}
c0004567:	90                   	nop
c0004568:	c9                   	leave  
c0004569:	c3                   	ret    

c000456a <sema_up>:

void sema_up(struct semaphore *psema) {
c000456a:	55                   	push   %ebp
c000456b:	89 e5                	mov    %esp,%ebp
c000456d:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status = intr_disable();
c0004570:	e8 c8 d3 ff ff       	call   c000193d <intr_disable>
c0004575:	89 45 f4             	mov    %eax,-0xc(%ebp)
  ASSERT(psema->value == 0);
c0004578:	8b 45 08             	mov    0x8(%ebp),%eax
c000457b:	0f b6 00             	movzbl (%eax),%eax
c000457e:	84 c0                	test   %al,%al
c0004580:	74 19                	je     c000459b <sema_up+0x31>
c0004582:	68 14 cc 00 c0       	push   $0xc000cc14
c0004587:	68 a4 cc 00 c0       	push   $0xc000cca4
c000458c:	6a 26                	push   $0x26
c000458e:	68 d0 cb 00 c0       	push   $0xc000cbd0
c0004593:	e8 40 dd ff ff       	call   c00022d8 <panic_spin>
c0004598:	83 c4 10             	add    $0x10,%esp
  if (!list_empty(&psema->waiters)) {
c000459b:	8b 45 08             	mov    0x8(%ebp),%eax
c000459e:	83 c0 04             	add    $0x4,%eax
c00045a1:	83 ec 0c             	sub    $0xc,%esp
c00045a4:	50                   	push   %eax
c00045a5:	e8 34 fe ff ff       	call   c00043de <list_empty>
c00045aa:	83 c4 10             	add    $0x10,%esp
c00045ad:	85 c0                	test   %eax,%eax
c00045af:	75 26                	jne    c00045d7 <sema_up+0x6d>
    struct task_struct *thread_blocked =
        elem2entry(struct task_struct, general_tag, list_pop(&psema->waiters));
c00045b1:	8b 45 08             	mov    0x8(%ebp),%eax
c00045b4:	83 c0 04             	add    $0x4,%eax
c00045b7:	83 ec 0c             	sub    $0xc,%esp
c00045ba:	50                   	push   %eax
c00045bb:	e8 2f fd ff ff       	call   c00042ef <list_pop>
c00045c0:	83 c4 10             	add    $0x10,%esp
c00045c3:	83 e8 24             	sub    $0x24,%eax
    struct task_struct *thread_blocked =
c00045c6:	89 45 f0             	mov    %eax,-0x10(%ebp)
    thread_unblock(thread_blocked);
c00045c9:	83 ec 0c             	sub    $0xc,%esp
c00045cc:	ff 75 f0             	push   -0x10(%ebp)
c00045cf:	e8 9d fa ff ff       	call   c0004071 <thread_unblock>
c00045d4:	83 c4 10             	add    $0x10,%esp
  }
  psema->value++;
c00045d7:	8b 45 08             	mov    0x8(%ebp),%eax
c00045da:	0f b6 00             	movzbl (%eax),%eax
c00045dd:	8d 50 01             	lea    0x1(%eax),%edx
c00045e0:	8b 45 08             	mov    0x8(%ebp),%eax
c00045e3:	88 10                	mov    %dl,(%eax)
  ASSERT(psema->value == 1);
c00045e5:	8b 45 08             	mov    0x8(%ebp),%eax
c00045e8:	0f b6 00             	movzbl (%eax),%eax
c00045eb:	3c 01                	cmp    $0x1,%al
c00045ed:	74 19                	je     c0004608 <sema_up+0x9e>
c00045ef:	68 26 cc 00 c0       	push   $0xc000cc26
c00045f4:	68 a4 cc 00 c0       	push   $0xc000cca4
c00045f9:	6a 2d                	push   $0x2d
c00045fb:	68 d0 cb 00 c0       	push   $0xc000cbd0
c0004600:	e8 d3 dc ff ff       	call   c00022d8 <panic_spin>
c0004605:	83 c4 10             	add    $0x10,%esp
  intr_set_status(old_status);
c0004608:	83 ec 0c             	sub    $0xc,%esp
c000460b:	ff 75 f4             	push   -0xc(%ebp)
c000460e:	e8 70 d3 ff ff       	call   c0001983 <intr_set_status>
c0004613:	83 c4 10             	add    $0x10,%esp
}
c0004616:	90                   	nop
c0004617:	c9                   	leave  
c0004618:	c3                   	ret    

c0004619 <lock_acquire>:

// 获取锁plock
void lock_acquire(struct lock *plock) {
c0004619:	55                   	push   %ebp
c000461a:	89 e5                	mov    %esp,%ebp
c000461c:	53                   	push   %ebx
c000461d:	83 ec 04             	sub    $0x4,%esp
  if (plock->holder != running_thread()) { // 判断是否已持有该锁
c0004620:	8b 45 08             	mov    0x8(%ebp),%eax
c0004623:	8b 18                	mov    (%eax),%ebx
c0004625:	e8 e5 f4 ff ff       	call   c0003b0f <running_thread>
c000462a:	39 c3                	cmp    %eax,%ebx
c000462c:	74 4b                	je     c0004679 <lock_acquire+0x60>
    sema_down(&plock->semaphore);          // 信号量P操作(原子
c000462e:	8b 45 08             	mov    0x8(%ebp),%eax
c0004631:	83 c0 04             	add    $0x4,%eax
c0004634:	83 ec 0c             	sub    $0xc,%esp
c0004637:	50                   	push   %eax
c0004638:	e8 32 fe ff ff       	call   c000446f <sema_down>
c000463d:	83 c4 10             	add    $0x10,%esp
    plock->holder = running_thread();
c0004640:	e8 ca f4 ff ff       	call   c0003b0f <running_thread>
c0004645:	8b 55 08             	mov    0x8(%ebp),%edx
c0004648:	89 02                	mov    %eax,(%edx)
    ASSERT(plock->holder_repeat_nr == 0);
c000464a:	8b 45 08             	mov    0x8(%ebp),%eax
c000464d:	8b 40 18             	mov    0x18(%eax),%eax
c0004650:	85 c0                	test   %eax,%eax
c0004652:	74 19                	je     c000466d <lock_acquire+0x54>
c0004654:	68 38 cc 00 c0       	push   $0xc000cc38
c0004659:	68 ac cc 00 c0       	push   $0xc000ccac
c000465e:	6a 36                	push   $0x36
c0004660:	68 d0 cb 00 c0       	push   $0xc000cbd0
c0004665:	e8 6e dc ff ff       	call   c00022d8 <panic_spin>
c000466a:	83 c4 10             	add    $0x10,%esp
    plock->holder_repeat_nr = 1;
c000466d:	8b 45 08             	mov    0x8(%ebp),%eax
c0004670:	c7 40 18 01 00 00 00 	movl   $0x1,0x18(%eax)
  } else {
    plock->holder_repeat_nr++;
  }
}
c0004677:	eb 0f                	jmp    c0004688 <lock_acquire+0x6f>
    plock->holder_repeat_nr++;
c0004679:	8b 45 08             	mov    0x8(%ebp),%eax
c000467c:	8b 40 18             	mov    0x18(%eax),%eax
c000467f:	8d 50 01             	lea    0x1(%eax),%edx
c0004682:	8b 45 08             	mov    0x8(%ebp),%eax
c0004685:	89 50 18             	mov    %edx,0x18(%eax)
}
c0004688:	90                   	nop
c0004689:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c000468c:	c9                   	leave  
c000468d:	c3                   	ret    

c000468e <lock_release>:

// 释放锁plock
void lock_release(struct lock *plock) {
c000468e:	55                   	push   %ebp
c000468f:	89 e5                	mov    %esp,%ebp
c0004691:	53                   	push   %ebx
c0004692:	83 ec 04             	sub    $0x4,%esp
  ASSERT(plock->holder == running_thread());
c0004695:	8b 45 08             	mov    0x8(%ebp),%eax
c0004698:	8b 18                	mov    (%eax),%ebx
c000469a:	e8 70 f4 ff ff       	call   c0003b0f <running_thread>
c000469f:	39 c3                	cmp    %eax,%ebx
c00046a1:	74 19                	je     c00046bc <lock_release+0x2e>
c00046a3:	68 58 cc 00 c0       	push   $0xc000cc58
c00046a8:	68 bc cc 00 c0       	push   $0xc000ccbc
c00046ad:	6a 3f                	push   $0x3f
c00046af:	68 d0 cb 00 c0       	push   $0xc000cbd0
c00046b4:	e8 1f dc ff ff       	call   c00022d8 <panic_spin>
c00046b9:	83 c4 10             	add    $0x10,%esp
  if (plock->holder_repeat_nr > 1) {
c00046bc:	8b 45 08             	mov    0x8(%ebp),%eax
c00046bf:	8b 40 18             	mov    0x18(%eax),%eax
c00046c2:	83 f8 01             	cmp    $0x1,%eax
c00046c5:	76 11                	jbe    c00046d8 <lock_release+0x4a>
    // 此时还不能释放锁
    plock->holder_repeat_nr--;
c00046c7:	8b 45 08             	mov    0x8(%ebp),%eax
c00046ca:	8b 40 18             	mov    0x18(%eax),%eax
c00046cd:	8d 50 ff             	lea    -0x1(%eax),%edx
c00046d0:	8b 45 08             	mov    0x8(%ebp),%eax
c00046d3:	89 50 18             	mov    %edx,0x18(%eax)
    return;
c00046d6:	eb 49                	jmp    c0004721 <lock_release+0x93>
  }
  ASSERT(plock->holder_repeat_nr == 1);
c00046d8:	8b 45 08             	mov    0x8(%ebp),%eax
c00046db:	8b 40 18             	mov    0x18(%eax),%eax
c00046de:	83 f8 01             	cmp    $0x1,%eax
c00046e1:	74 19                	je     c00046fc <lock_release+0x6e>
c00046e3:	68 7a cc 00 c0       	push   $0xc000cc7a
c00046e8:	68 bc cc 00 c0       	push   $0xc000ccbc
c00046ed:	6a 45                	push   $0x45
c00046ef:	68 d0 cb 00 c0       	push   $0xc000cbd0
c00046f4:	e8 df db ff ff       	call   c00022d8 <panic_spin>
c00046f9:	83 c4 10             	add    $0x10,%esp

  plock->holder = NULL; // 把锁的持有者置空放在V操作前
c00046fc:	8b 45 08             	mov    0x8(%ebp),%eax
c00046ff:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
  plock->holder_repeat_nr = 0;
c0004705:	8b 45 08             	mov    0x8(%ebp),%eax
c0004708:	c7 40 18 00 00 00 00 	movl   $0x0,0x18(%eax)
  sema_up(&plock->semaphore); // 信号量V操作(原子
c000470f:	8b 45 08             	mov    0x8(%ebp),%eax
c0004712:	83 c0 04             	add    $0x4,%eax
c0004715:	83 ec 0c             	sub    $0xc,%esp
c0004718:	50                   	push   %eax
c0004719:	e8 4c fe ff ff       	call   c000456a <sema_up>
c000471e:	83 c4 10             	add    $0x10,%esp
c0004721:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c0004724:	c9                   	leave  
c0004725:	c3                   	ret    

c0004726 <console_init>:
#include "print.h"
#include "sync.h"

static struct lock console_lock; // 终端锁

void console_init() { lock_init(&console_lock); }
c0004726:	55                   	push   %ebp
c0004727:	89 e5                	mov    %esp,%ebp
c0004729:	83 ec 08             	sub    $0x8,%esp
c000472c:	83 ec 0c             	sub    $0xc,%esp
c000472f:	68 44 1b 01 c0       	push   $0xc0011b44
c0004734:	e8 06 fd ff ff       	call   c000443f <lock_init>
c0004739:	83 c4 10             	add    $0x10,%esp
c000473c:	90                   	nop
c000473d:	c9                   	leave  
c000473e:	c3                   	ret    

c000473f <console_acquire>:

// 获取终端
void console_acquire() { lock_acquire(&console_lock); }
c000473f:	55                   	push   %ebp
c0004740:	89 e5                	mov    %esp,%ebp
c0004742:	83 ec 08             	sub    $0x8,%esp
c0004745:	83 ec 0c             	sub    $0xc,%esp
c0004748:	68 44 1b 01 c0       	push   $0xc0011b44
c000474d:	e8 c7 fe ff ff       	call   c0004619 <lock_acquire>
c0004752:	83 c4 10             	add    $0x10,%esp
c0004755:	90                   	nop
c0004756:	c9                   	leave  
c0004757:	c3                   	ret    

c0004758 <console_release>:

// 释放终端
void console_release() { lock_release(&console_lock); }
c0004758:	55                   	push   %ebp
c0004759:	89 e5                	mov    %esp,%ebp
c000475b:	83 ec 08             	sub    $0x8,%esp
c000475e:	83 ec 0c             	sub    $0xc,%esp
c0004761:	68 44 1b 01 c0       	push   $0xc0011b44
c0004766:	e8 23 ff ff ff       	call   c000468e <lock_release>
c000476b:	83 c4 10             	add    $0x10,%esp
c000476e:	90                   	nop
c000476f:	c9                   	leave  
c0004770:	c3                   	ret    

c0004771 <console_put_str>:

// 终端中输出字符串
void console_put_str(char *str) {
c0004771:	55                   	push   %ebp
c0004772:	89 e5                	mov    %esp,%ebp
c0004774:	83 ec 08             	sub    $0x8,%esp
  console_acquire();
c0004777:	e8 c3 ff ff ff       	call   c000473f <console_acquire>
  put_str(str);
c000477c:	83 ec 0c             	sub    $0xc,%esp
c000477f:	ff 75 08             	push   0x8(%ebp)
c0004782:	e8 a9 d2 ff ff       	call   c0001a30 <put_str>
c0004787:	83 c4 10             	add    $0x10,%esp
  console_release();
c000478a:	e8 c9 ff ff ff       	call   c0004758 <console_release>
}
c000478f:	90                   	nop
c0004790:	c9                   	leave  
c0004791:	c3                   	ret    

c0004792 <console_put_char>:

// 终端中输出字符
void console_put_char(uint8_t char_asci) {
c0004792:	55                   	push   %ebp
c0004793:	89 e5                	mov    %esp,%ebp
c0004795:	83 ec 18             	sub    $0x18,%esp
c0004798:	8b 45 08             	mov    0x8(%ebp),%eax
c000479b:	88 45 f4             	mov    %al,-0xc(%ebp)
  console_acquire();
c000479e:	e8 9c ff ff ff       	call   c000473f <console_acquire>
  put_char(char_asci);
c00047a3:	0f b6 45 f4          	movzbl -0xc(%ebp),%eax
c00047a7:	83 ec 0c             	sub    $0xc,%esp
c00047aa:	50                   	push   %eax
c00047ab:	e8 9e d2 ff ff       	call   c0001a4e <put_char>
c00047b0:	83 c4 10             	add    $0x10,%esp
  console_release();
c00047b3:	e8 a0 ff ff ff       	call   c0004758 <console_release>
}
c00047b8:	90                   	nop
c00047b9:	c9                   	leave  
c00047ba:	c3                   	ret    

c00047bb <console_put_int>:

// 终端中输出十六进制整数
void console_put_int(uint32_t num) {
c00047bb:	55                   	push   %ebp
c00047bc:	89 e5                	mov    %esp,%ebp
c00047be:	83 ec 08             	sub    $0x8,%esp
  console_acquire();
c00047c1:	e8 79 ff ff ff       	call   c000473f <console_acquire>
  put_int(num);
c00047c6:	83 ec 0c             	sub    $0xc,%esp
c00047c9:	ff 75 08             	push   0x8(%ebp)
c00047cc:	e8 5c d3 ff ff       	call   c0001b2d <put_int>
c00047d1:	83 c4 10             	add    $0x10,%esp
  console_release();
c00047d4:	e8 7f ff ff ff       	call   c0004758 <console_release>
}
c00047d9:	90                   	nop
c00047da:	c9                   	leave  
c00047db:	c3                   	ret    

c00047dc <sys_putchar>:

c00047dc:	55                   	push   %ebp
c00047dd:	89 e5                	mov    %esp,%ebp
c00047df:	83 ec 18             	sub    $0x18,%esp
c00047e2:	8b 45 08             	mov    0x8(%ebp),%eax
c00047e5:	88 45 f4             	mov    %al,-0xc(%ebp)
c00047e8:	0f b6 45 f4          	movzbl -0xc(%ebp),%eax
c00047ec:	83 ec 0c             	sub    $0xc,%esp
c00047ef:	50                   	push   %eax
c00047f0:	e8 9d ff ff ff       	call   c0004792 <console_put_char>
c00047f5:	83 c4 10             	add    $0x10,%esp
c00047f8:	90                   	nop
c00047f9:	c9                   	leave  
c00047fa:	c3                   	ret    

c00047fb <inb>:
static inline void outsw(uint16_t port, const void *addr, uint32_t word_cnt) {
  asm volatile("cld; rep outsw" : "+S"(addr), "+c"(word_cnt) : "d"(port));
}

// 从端口读1字节
static inline uint8_t inb(uint16_t port) {
c00047fb:	55                   	push   %ebp
c00047fc:	89 e5                	mov    %esp,%ebp
c00047fe:	83 ec 14             	sub    $0x14,%esp
c0004801:	8b 45 08             	mov    0x8(%ebp),%eax
c0004804:	66 89 45 ec          	mov    %ax,-0x14(%ebp)
  uint8_t data;
  asm volatile("inb %w1, %b0" : "=a"(data) : "Nd"(port));
c0004808:	0f b7 45 ec          	movzwl -0x14(%ebp),%eax
c000480c:	89 c2                	mov    %eax,%edx
c000480e:	ec                   	in     (%dx),%al
c000480f:	88 45 ff             	mov    %al,-0x1(%ebp)
  return data;
c0004812:	0f b6 45 ff          	movzbl -0x1(%ebp),%eax
}
c0004816:	c9                   	leave  
c0004817:	c3                   	ret    

c0004818 <intr_keyboard_handler>:
    /* 0x3A */ {caps_lock_char, caps_lock_char}
    /*其他按键暂不处理*/
};

// 键盘中断处理程序
static void intr_keyboard_handler(void) {
c0004818:	55                   	push   %ebp
c0004819:	89 e5                	mov    %esp,%ebp
c000481b:	83 ec 28             	sub    $0x28,%esp
  //bool ctrl_down_last = ctrl_status; // 记录三个组合键是否被按下
  bool shift_down_last = shift_status;
c000481e:	a1 d0 1b 01 c0       	mov    0xc0011bd0,%eax
c0004823:	89 45 ec             	mov    %eax,-0x14(%ebp)
  bool caps_lock_last = caps_lock_status;
c0004826:	a1 d8 1b 01 c0       	mov    0xc0011bd8,%eax
c000482b:	89 45 e8             	mov    %eax,-0x18(%ebp)
  bool break_code;

  uint16_t scancode = inb(KBD_BUF_PORT); // 获取扫描码
c000482e:	6a 60                	push   $0x60
c0004830:	e8 c6 ff ff ff       	call   c00047fb <inb>
c0004835:	83 c4 04             	add    $0x4,%esp
c0004838:	0f b6 c0             	movzbl %al,%eax
c000483b:	66 89 45 f6          	mov    %ax,-0xa(%ebp)

  // scancode是e0开头-> 有多个扫描码，所以马上结束此次函数等下个码进来
  if (scancode == 0xe0) {
c000483f:	66 81 7d f6 e0 00    	cmpw   $0xe0,-0xa(%ebp)
c0004845:	75 0f                	jne    c0004856 <intr_keyboard_handler+0x3e>
    ext_scancode = true; // 打开e0标记
c0004847:	c7 05 dc 1b 01 c0 01 	movl   $0x1,0xc0011bdc
c000484e:	00 00 00 
    return;
c0004851:	e9 40 02 00 00       	jmp    c0004a96 <intr_keyboard_handler+0x27e>
  }

  // 上次以0xe0开头-> 将扫描码合并
  if (ext_scancode) {
c0004856:	a1 dc 1b 01 c0       	mov    0xc0011bdc,%eax
c000485b:	85 c0                	test   %eax,%eax
c000485d:	74 10                	je     c000486f <intr_keyboard_handler+0x57>
    scancode = ((0xe000) | scancode);
c000485f:	66 81 4d f6 00 e0    	orw    $0xe000,-0xa(%ebp)
    ext_scancode = false; // 关闭e0标记
c0004865:	c7 05 dc 1b 01 c0 00 	movl   $0x0,0xc0011bdc
c000486c:	00 00 00 
  }

  break_code = ((scancode & 0x0080) != 0); // 获取break_code
c000486f:	0f b7 45 f6          	movzwl -0xa(%ebp),%eax
c0004873:	25 80 00 00 00       	and    $0x80,%eax
c0004878:	85 c0                	test   %eax,%eax
c000487a:	0f 95 c0             	setne  %al
c000487d:	0f b6 c0             	movzbl %al,%eax
c0004880:	89 45 e4             	mov    %eax,-0x1c(%ebp)

  if (break_code) {                            // 断码处理
c0004883:	83 7d e4 00          	cmpl   $0x0,-0x1c(%ebp)
c0004887:	74 6a                	je     c00048f3 <intr_keyboard_handler+0xdb>
    uint16_t make_code = (scancode &= 0xff7f); // 通过将第8位置0来获得其通码
c0004889:	66 81 65 f6 7f ff    	andw   $0xff7f,-0xa(%ebp)
c000488f:	0f b7 45 f6          	movzwl -0xa(%ebp),%eax
c0004893:	66 89 45 e0          	mov    %ax,-0x20(%ebp)

    // 判断三个键是否弹起
    if (make_code == ctrl_l_make || make_code == ctrl_r_make) {
c0004897:	66 83 7d e0 1d       	cmpw   $0x1d,-0x20(%ebp)
c000489c:	74 08                	je     c00048a6 <intr_keyboard_handler+0x8e>
c000489e:	66 81 7d e0 1d e0    	cmpw   $0xe01d,-0x20(%ebp)
c00048a4:	75 0c                	jne    c00048b2 <intr_keyboard_handler+0x9a>
      ctrl_status = false;
c00048a6:	c7 05 cc 1b 01 c0 00 	movl   $0x0,0xc0011bcc
c00048ad:	00 00 00 
c00048b0:	eb 3c                	jmp    c00048ee <intr_keyboard_handler+0xd6>
    } else if (make_code == shift_l_make || make_code == shift_r_make) {
c00048b2:	66 83 7d e0 2a       	cmpw   $0x2a,-0x20(%ebp)
c00048b7:	74 07                	je     c00048c0 <intr_keyboard_handler+0xa8>
c00048b9:	66 83 7d e0 36       	cmpw   $0x36,-0x20(%ebp)
c00048be:	75 0c                	jne    c00048cc <intr_keyboard_handler+0xb4>
      shift_status = false;
c00048c0:	c7 05 d0 1b 01 c0 00 	movl   $0x0,0xc0011bd0
c00048c7:	00 00 00 
c00048ca:	eb 22                	jmp    c00048ee <intr_keyboard_handler+0xd6>
    } else if (make_code == alt_l_make || make_code == alt_r_make) {
c00048cc:	66 83 7d e0 38       	cmpw   $0x38,-0x20(%ebp)
c00048d1:	74 0c                	je     c00048df <intr_keyboard_handler+0xc7>
c00048d3:	66 81 7d e0 38 e0    	cmpw   $0xe038,-0x20(%ebp)
c00048d9:	0f 85 b0 01 00 00    	jne    c0004a8f <intr_keyboard_handler+0x277>
      alt_status = false;
c00048df:	c7 05 d4 1b 01 c0 00 	movl   $0x0,0xc0011bd4
c00048e6:	00 00 00 
    } // caps_lock不是弹起后关闭，需单独处理

    return;
c00048e9:	e9 a1 01 00 00       	jmp    c0004a8f <intr_keyboard_handler+0x277>
c00048ee:	e9 9c 01 00 00       	jmp    c0004a8f <intr_keyboard_handler+0x277>
  } else if ((scancode > 0x00 && scancode < 0x3b) || (scancode == alt_r_make) ||
c00048f3:	66 83 7d f6 00       	cmpw   $0x0,-0xa(%ebp)
c00048f8:	74 07                	je     c0004901 <intr_keyboard_handler+0xe9>
c00048fa:	66 83 7d f6 3a       	cmpw   $0x3a,-0xa(%ebp)
c00048ff:	76 14                	jbe    c0004915 <intr_keyboard_handler+0xfd>
c0004901:	66 81 7d f6 38 e0    	cmpw   $0xe038,-0xa(%ebp)
c0004907:	74 0c                	je     c0004915 <intr_keyboard_handler+0xfd>
c0004909:	66 81 7d f6 1d e0    	cmpw   $0xe01d,-0xa(%ebp)
c000490f:	0f 85 68 01 00 00    	jne    c0004a7d <intr_keyboard_handler+0x265>
             (scancode == ctrl_r_make)) { // 通码处理
    bool shift = false;                   // 判断是否与shift组合
c0004915:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
    if ((scancode < 0x0e) || (scancode == 0x29) || (scancode == 0x1a) ||
c000491c:	66 83 7d f6 0d       	cmpw   $0xd,-0xa(%ebp)
c0004921:	76 3f                	jbe    c0004962 <intr_keyboard_handler+0x14a>
c0004923:	66 83 7d f6 29       	cmpw   $0x29,-0xa(%ebp)
c0004928:	74 38                	je     c0004962 <intr_keyboard_handler+0x14a>
c000492a:	66 83 7d f6 1a       	cmpw   $0x1a,-0xa(%ebp)
c000492f:	74 31                	je     c0004962 <intr_keyboard_handler+0x14a>
c0004931:	66 83 7d f6 1b       	cmpw   $0x1b,-0xa(%ebp)
c0004936:	74 2a                	je     c0004962 <intr_keyboard_handler+0x14a>
        (scancode == 0x1b) || (scancode == 0x2b) || (scancode == 0x27) ||
c0004938:	66 83 7d f6 2b       	cmpw   $0x2b,-0xa(%ebp)
c000493d:	74 23                	je     c0004962 <intr_keyboard_handler+0x14a>
c000493f:	66 83 7d f6 27       	cmpw   $0x27,-0xa(%ebp)
c0004944:	74 1c                	je     c0004962 <intr_keyboard_handler+0x14a>
c0004946:	66 83 7d f6 28       	cmpw   $0x28,-0xa(%ebp)
c000494b:	74 15                	je     c0004962 <intr_keyboard_handler+0x14a>
        (scancode == 0x28) || (scancode == 0x33) || (scancode == 0x34) ||
c000494d:	66 83 7d f6 33       	cmpw   $0x33,-0xa(%ebp)
c0004952:	74 0e                	je     c0004962 <intr_keyboard_handler+0x14a>
c0004954:	66 83 7d f6 34       	cmpw   $0x34,-0xa(%ebp)
c0004959:	74 07                	je     c0004962 <intr_keyboard_handler+0x14a>
c000495b:	66 83 7d f6 35       	cmpw   $0x35,-0xa(%ebp)
c0004960:	75 0f                	jne    c0004971 <intr_keyboard_handler+0x159>
        (scancode == 0x35)) { // 双字符键
      if (shift_down_last) {
c0004962:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c0004966:	74 3a                	je     c00049a2 <intr_keyboard_handler+0x18a>
        shift = true;
c0004968:	c7 45 f0 01 00 00 00 	movl   $0x1,-0x10(%ebp)
      if (shift_down_last) {
c000496f:	eb 31                	jmp    c00049a2 <intr_keyboard_handler+0x18a>
      }
    } else { // 字母键
      if (shift_down_last && caps_lock_last) {
c0004971:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c0004975:	74 0f                	je     c0004986 <intr_keyboard_handler+0x16e>
c0004977:	83 7d e8 00          	cmpl   $0x0,-0x18(%ebp)
c000497b:	74 09                	je     c0004986 <intr_keyboard_handler+0x16e>
        shift = false;
c000497d:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
c0004984:	eb 1c                	jmp    c00049a2 <intr_keyboard_handler+0x18a>
      } else if (shift_down_last || caps_lock_last) {
c0004986:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c000498a:	75 06                	jne    c0004992 <intr_keyboard_handler+0x17a>
c000498c:	83 7d e8 00          	cmpl   $0x0,-0x18(%ebp)
c0004990:	74 09                	je     c000499b <intr_keyboard_handler+0x183>
        shift = true;
c0004992:	c7 45 f0 01 00 00 00 	movl   $0x1,-0x10(%ebp)
c0004999:	eb 07                	jmp    c00049a2 <intr_keyboard_handler+0x18a>
      } else {
        shift = false;
c000499b:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
      }
    }

    uint8_t index = (scancode &= 0x00ff); // 针对高字节是e0的码,将高字节置0
c00049a2:	66 81 65 f6 ff 00    	andw   $0xff,-0xa(%ebp)
c00049a8:	0f b7 45 f6          	movzwl -0xa(%ebp),%eax
c00049ac:	88 45 e3             	mov    %al,-0x1d(%ebp)
    char cur_char = keymap[index][shift]; // 找到对应ASCII字符
c00049af:	0f b6 45 e3          	movzbl -0x1d(%ebp),%eax
c00049b3:	8d 14 00             	lea    (%eax,%eax,1),%edx
c00049b6:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00049b9:	01 d0                	add    %edx,%eax
c00049bb:	05 e0 10 01 c0       	add    $0xc00110e0,%eax
c00049c0:	0f b6 00             	movzbl (%eax),%eax
c00049c3:	88 45 e2             	mov    %al,-0x1e(%ebp)

    if (cur_char) { // 只处理ASCII码不为0的键
c00049c6:	80 7d e2 00          	cmpb   $0x0,-0x1e(%ebp)
c00049ca:	74 45                	je     c0004a11 <intr_keyboard_handler+0x1f9>
      // 若缓冲区未满且待加入的cur_char不为0，则将其加入到缓冲区中
      if (!ioq_full(&kbd_buf)) {
c00049cc:	83 ec 0c             	sub    $0xc,%esp
c00049cf:	68 60 1b 01 c0       	push   $0xc0011b60
c00049d4:	e8 64 01 00 00       	call   c0004b3d <ioq_full>
c00049d9:	83 c4 10             	add    $0x10,%esp
c00049dc:	85 c0                	test   %eax,%eax
c00049de:	0f 85 ae 00 00 00    	jne    c0004a92 <intr_keyboard_handler+0x27a>
        put_char(cur_char); // 临时的
c00049e4:	0f b6 45 e2          	movzbl -0x1e(%ebp),%eax
c00049e8:	0f b6 c0             	movzbl %al,%eax
c00049eb:	83 ec 0c             	sub    $0xc,%esp
c00049ee:	50                   	push   %eax
c00049ef:	e8 5a d0 ff ff       	call   c0001a4e <put_char>
c00049f4:	83 c4 10             	add    $0x10,%esp
        ioq_putchar(&kbd_buf, cur_char);
c00049f7:	0f be 45 e2          	movsbl -0x1e(%ebp),%eax
c00049fb:	83 ec 08             	sub    $0x8,%esp
c00049fe:	50                   	push   %eax
c00049ff:	68 60 1b 01 c0       	push   $0xc0011b60
c0004a04:	e8 00 03 00 00       	call   c0004d09 <ioq_putchar>
c0004a09:	83 c4 10             	add    $0x10,%esp
      }
      return;
c0004a0c:	e9 81 00 00 00       	jmp    c0004a92 <intr_keyboard_handler+0x27a>
    }

    if (scancode == ctrl_l_char || scancode == ctrl_r_char) {
c0004a11:	66 83 7d f6 00       	cmpw   $0x0,-0xa(%ebp)
c0004a16:	74 07                	je     c0004a1f <intr_keyboard_handler+0x207>
c0004a18:	66 83 7d f6 00       	cmpw   $0x0,-0xa(%ebp)
c0004a1d:	75 0c                	jne    c0004a2b <intr_keyboard_handler+0x213>
      ctrl_status = true;
c0004a1f:	c7 05 cc 1b 01 c0 01 	movl   $0x1,0xc0011bcc
c0004a26:	00 00 00 
c0004a29:	eb 50                	jmp    c0004a7b <intr_keyboard_handler+0x263>
    } else if (scancode == shift_l_make || scancode == shift_r_make) {
c0004a2b:	66 83 7d f6 2a       	cmpw   $0x2a,-0xa(%ebp)
c0004a30:	74 07                	je     c0004a39 <intr_keyboard_handler+0x221>
c0004a32:	66 83 7d f6 36       	cmpw   $0x36,-0xa(%ebp)
c0004a37:	75 0c                	jne    c0004a45 <intr_keyboard_handler+0x22d>
      shift_status = true;
c0004a39:	c7 05 d0 1b 01 c0 01 	movl   $0x1,0xc0011bd0
c0004a40:	00 00 00 
c0004a43:	eb 36                	jmp    c0004a7b <intr_keyboard_handler+0x263>
    } else if (scancode == alt_l_make || scancode == alt_r_make) {
c0004a45:	66 83 7d f6 38       	cmpw   $0x38,-0xa(%ebp)
c0004a4a:	74 08                	je     c0004a54 <intr_keyboard_handler+0x23c>
c0004a4c:	66 81 7d f6 38 e0    	cmpw   $0xe038,-0xa(%ebp)
c0004a52:	75 0c                	jne    c0004a60 <intr_keyboard_handler+0x248>
      alt_status = true;
c0004a54:	c7 05 d4 1b 01 c0 01 	movl   $0x1,0xc0011bd4
c0004a5b:	00 00 00 
c0004a5e:	eb 1b                	jmp    c0004a7b <intr_keyboard_handler+0x263>
    } else if (scancode == caps_lock_make) {
c0004a60:	66 83 7d f6 3a       	cmpw   $0x3a,-0xa(%ebp)
c0004a65:	75 2e                	jne    c0004a95 <intr_keyboard_handler+0x27d>
      caps_lock_status = !caps_lock_status;
c0004a67:	a1 d8 1b 01 c0       	mov    0xc0011bd8,%eax
c0004a6c:	85 c0                	test   %eax,%eax
c0004a6e:	0f 94 c0             	sete   %al
c0004a71:	0f b6 c0             	movzbl %al,%eax
c0004a74:	a3 d8 1b 01 c0       	mov    %eax,0xc0011bd8
             (scancode == ctrl_r_make)) { // 通码处理
c0004a79:	eb 1a                	jmp    c0004a95 <intr_keyboard_handler+0x27d>
c0004a7b:	eb 18                	jmp    c0004a95 <intr_keyboard_handler+0x27d>
    }
  } else {
    put_str("unknown key\n");
c0004a7d:	83 ec 0c             	sub    $0xc,%esp
c0004a80:	68 c9 cc 00 c0       	push   $0xc000ccc9
c0004a85:	e8 a6 cf ff ff       	call   c0001a30 <put_str>
c0004a8a:	83 c4 10             	add    $0x10,%esp
c0004a8d:	eb 07                	jmp    c0004a96 <intr_keyboard_handler+0x27e>
    return;
c0004a8f:	90                   	nop
c0004a90:	eb 04                	jmp    c0004a96 <intr_keyboard_handler+0x27e>
      return;
c0004a92:	90                   	nop
c0004a93:	eb 01                	jmp    c0004a96 <intr_keyboard_handler+0x27e>
             (scancode == ctrl_r_make)) { // 通码处理
c0004a95:	90                   	nop
  }
}
c0004a96:	c9                   	leave  
c0004a97:	c3                   	ret    

c0004a98 <keyboard_init>:

// 键盘初始化
void keyboard_init() {
c0004a98:	55                   	push   %ebp
c0004a99:	89 e5                	mov    %esp,%ebp
c0004a9b:	83 ec 08             	sub    $0x8,%esp
  put_str("keyboard_init start\n");
c0004a9e:	83 ec 0c             	sub    $0xc,%esp
c0004aa1:	68 d6 cc 00 c0       	push   $0xc000ccd6
c0004aa6:	e8 85 cf ff ff       	call   c0001a30 <put_str>
c0004aab:	83 c4 10             	add    $0x10,%esp
  ioqueue_init(&kbd_buf);
c0004aae:	83 ec 0c             	sub    $0xc,%esp
c0004ab1:	68 60 1b 01 c0       	push   $0xc0011b60
c0004ab6:	e8 28 00 00 00       	call   c0004ae3 <ioqueue_init>
c0004abb:	83 c4 10             	add    $0x10,%esp
  register_handler(0x21, intr_keyboard_handler);
c0004abe:	83 ec 08             	sub    $0x8,%esp
c0004ac1:	68 18 48 00 c0       	push   $0xc0004818
c0004ac6:	6a 21                	push   $0x21
c0004ac8:	e8 99 ce ff ff       	call   c0001966 <register_handler>
c0004acd:	83 c4 10             	add    $0x10,%esp
  put_str("keyboard_init done\n");
c0004ad0:	83 ec 0c             	sub    $0xc,%esp
c0004ad3:	68 eb cc 00 c0       	push   $0xc000cceb
c0004ad8:	e8 53 cf ff ff       	call   c0001a30 <put_str>
c0004add:	83 c4 10             	add    $0x10,%esp
c0004ae0:	90                   	nop
c0004ae1:	c9                   	leave  
c0004ae2:	c3                   	ret    

c0004ae3 <ioqueue_init>:
#include "debug.h"
#include "global.h"
#include "interrupt.h"
#include "stdint.h"

void ioqueue_init(struct ioqueue *ioq) {
c0004ae3:	55                   	push   %ebp
c0004ae4:	89 e5                	mov    %esp,%ebp
c0004ae6:	83 ec 08             	sub    $0x8,%esp
  lock_init(&ioq->lock);
c0004ae9:	8b 45 08             	mov    0x8(%ebp),%eax
c0004aec:	83 ec 0c             	sub    $0xc,%esp
c0004aef:	50                   	push   %eax
c0004af0:	e8 4a f9 ff ff       	call   c000443f <lock_init>
c0004af5:	83 c4 10             	add    $0x10,%esp
  ioq->producer = ioq->consumer = NULL;
c0004af8:	8b 45 08             	mov    0x8(%ebp),%eax
c0004afb:	c7 40 20 00 00 00 00 	movl   $0x0,0x20(%eax)
c0004b02:	8b 45 08             	mov    0x8(%ebp),%eax
c0004b05:	8b 50 20             	mov    0x20(%eax),%edx
c0004b08:	8b 45 08             	mov    0x8(%ebp),%eax
c0004b0b:	89 50 1c             	mov    %edx,0x1c(%eax)
  ioq->head = ioq->tail = 0;
c0004b0e:	8b 45 08             	mov    0x8(%ebp),%eax
c0004b11:	c7 40 68 00 00 00 00 	movl   $0x0,0x68(%eax)
c0004b18:	8b 45 08             	mov    0x8(%ebp),%eax
c0004b1b:	8b 50 68             	mov    0x68(%eax),%edx
c0004b1e:	8b 45 08             	mov    0x8(%ebp),%eax
c0004b21:	89 50 64             	mov    %edx,0x64(%eax)
}
c0004b24:	90                   	nop
c0004b25:	c9                   	leave  
c0004b26:	c3                   	ret    

c0004b27 <next_pos>:

// 返回pos在缓冲区中的下一个位置值
static int32_t next_pos(int32_t pos) { return (pos + 1) % bufsize; }
c0004b27:	55                   	push   %ebp
c0004b28:	89 e5                	mov    %esp,%ebp
c0004b2a:	8b 45 08             	mov    0x8(%ebp),%eax
c0004b2d:	83 c0 01             	add    $0x1,%eax
c0004b30:	99                   	cltd   
c0004b31:	c1 ea 1a             	shr    $0x1a,%edx
c0004b34:	01 d0                	add    %edx,%eax
c0004b36:	83 e0 3f             	and    $0x3f,%eax
c0004b39:	29 d0                	sub    %edx,%eax
c0004b3b:	5d                   	pop    %ebp
c0004b3c:	c3                   	ret    

c0004b3d <ioq_full>:

bool ioq_full(struct ioqueue *ioq) {
c0004b3d:	55                   	push   %ebp
c0004b3e:	89 e5                	mov    %esp,%ebp
c0004b40:	83 ec 08             	sub    $0x8,%esp
  ASSERT(intr_get_status() == INTR_OFF);
c0004b43:	e8 59 ce ff ff       	call   c00019a1 <intr_get_status>
c0004b48:	85 c0                	test   %eax,%eax
c0004b4a:	74 19                	je     c0004b65 <ioq_full+0x28>
c0004b4c:	68 00 cd 00 c0       	push   $0xc000cd00
c0004b51:	68 64 cd 00 c0       	push   $0xc000cd64
c0004b56:	6a 11                	push   $0x11
c0004b58:	68 1e cd 00 c0       	push   $0xc000cd1e
c0004b5d:	e8 76 d7 ff ff       	call   c00022d8 <panic_spin>
c0004b62:	83 c4 10             	add    $0x10,%esp
  return next_pos(ioq->head) == ioq->tail;
c0004b65:	8b 45 08             	mov    0x8(%ebp),%eax
c0004b68:	8b 40 64             	mov    0x64(%eax),%eax
c0004b6b:	83 ec 0c             	sub    $0xc,%esp
c0004b6e:	50                   	push   %eax
c0004b6f:	e8 b3 ff ff ff       	call   c0004b27 <next_pos>
c0004b74:	83 c4 10             	add    $0x10,%esp
c0004b77:	8b 55 08             	mov    0x8(%ebp),%edx
c0004b7a:	8b 52 68             	mov    0x68(%edx),%edx
c0004b7d:	39 d0                	cmp    %edx,%eax
c0004b7f:	0f 94 c0             	sete   %al
c0004b82:	0f b6 c0             	movzbl %al,%eax
}
c0004b85:	c9                   	leave  
c0004b86:	c3                   	ret    

c0004b87 <ioq_empty>:

bool ioq_empty(struct ioqueue *ioq) {
c0004b87:	55                   	push   %ebp
c0004b88:	89 e5                	mov    %esp,%ebp
c0004b8a:	83 ec 08             	sub    $0x8,%esp
  ASSERT(intr_get_status() == INTR_OFF);
c0004b8d:	e8 0f ce ff ff       	call   c00019a1 <intr_get_status>
c0004b92:	85 c0                	test   %eax,%eax
c0004b94:	74 19                	je     c0004baf <ioq_empty+0x28>
c0004b96:	68 00 cd 00 c0       	push   $0xc000cd00
c0004b9b:	68 70 cd 00 c0       	push   $0xc000cd70
c0004ba0:	6a 16                	push   $0x16
c0004ba2:	68 1e cd 00 c0       	push   $0xc000cd1e
c0004ba7:	e8 2c d7 ff ff       	call   c00022d8 <panic_spin>
c0004bac:	83 c4 10             	add    $0x10,%esp
  return ioq->head == ioq->tail;
c0004baf:	8b 45 08             	mov    0x8(%ebp),%eax
c0004bb2:	8b 50 64             	mov    0x64(%eax),%edx
c0004bb5:	8b 45 08             	mov    0x8(%ebp),%eax
c0004bb8:	8b 40 68             	mov    0x68(%eax),%eax
c0004bbb:	39 c2                	cmp    %eax,%edx
c0004bbd:	0f 94 c0             	sete   %al
c0004bc0:	0f b6 c0             	movzbl %al,%eax
}
c0004bc3:	c9                   	leave  
c0004bc4:	c3                   	ret    

c0004bc5 <ioq_wait>:

// 使当前生产者/消费者在此缓冲区上等待
static void ioq_wait(struct task_struct **waiter) {
c0004bc5:	55                   	push   %ebp
c0004bc6:	89 e5                	mov    %esp,%ebp
c0004bc8:	83 ec 08             	sub    $0x8,%esp
  ASSERT(*waiter == NULL && waiter != NULL);
c0004bcb:	8b 45 08             	mov    0x8(%ebp),%eax
c0004bce:	8b 00                	mov    (%eax),%eax
c0004bd0:	85 c0                	test   %eax,%eax
c0004bd2:	75 06                	jne    c0004bda <ioq_wait+0x15>
c0004bd4:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c0004bd8:	75 19                	jne    c0004bf3 <ioq_wait+0x2e>
c0004bda:	68 30 cd 00 c0       	push   $0xc000cd30
c0004bdf:	68 7c cd 00 c0       	push   $0xc000cd7c
c0004be4:	6a 1c                	push   $0x1c
c0004be6:	68 1e cd 00 c0       	push   $0xc000cd1e
c0004beb:	e8 e8 d6 ff ff       	call   c00022d8 <panic_spin>
c0004bf0:	83 c4 10             	add    $0x10,%esp
  *waiter = running_thread();
c0004bf3:	e8 17 ef ff ff       	call   c0003b0f <running_thread>
c0004bf8:	8b 55 08             	mov    0x8(%ebp),%edx
c0004bfb:	89 02                	mov    %eax,(%edx)
  thread_block(TASK_BLOCKED);
c0004bfd:	83 ec 0c             	sub    $0xc,%esp
c0004c00:	6a 02                	push   $0x2
c0004c02:	e8 07 f4 ff ff       	call   c000400e <thread_block>
c0004c07:	83 c4 10             	add    $0x10,%esp
}
c0004c0a:	90                   	nop
c0004c0b:	c9                   	leave  
c0004c0c:	c3                   	ret    

c0004c0d <wakeup>:

// 唤醒waiter
static void wakeup(struct task_struct **waiter) {
c0004c0d:	55                   	push   %ebp
c0004c0e:	89 e5                	mov    %esp,%ebp
c0004c10:	83 ec 08             	sub    $0x8,%esp
  ASSERT(*waiter != NULL);
c0004c13:	8b 45 08             	mov    0x8(%ebp),%eax
c0004c16:	8b 00                	mov    (%eax),%eax
c0004c18:	85 c0                	test   %eax,%eax
c0004c1a:	75 19                	jne    c0004c35 <wakeup+0x28>
c0004c1c:	68 52 cd 00 c0       	push   $0xc000cd52
c0004c21:	68 88 cd 00 c0       	push   $0xc000cd88
c0004c26:	6a 23                	push   $0x23
c0004c28:	68 1e cd 00 c0       	push   $0xc000cd1e
c0004c2d:	e8 a6 d6 ff ff       	call   c00022d8 <panic_spin>
c0004c32:	83 c4 10             	add    $0x10,%esp
  thread_unblock(*waiter);
c0004c35:	8b 45 08             	mov    0x8(%ebp),%eax
c0004c38:	8b 00                	mov    (%eax),%eax
c0004c3a:	83 ec 0c             	sub    $0xc,%esp
c0004c3d:	50                   	push   %eax
c0004c3e:	e8 2e f4 ff ff       	call   c0004071 <thread_unblock>
c0004c43:	83 c4 10             	add    $0x10,%esp
  *waiter = NULL;
c0004c46:	8b 45 08             	mov    0x8(%ebp),%eax
c0004c49:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
}
c0004c4f:	90                   	nop
c0004c50:	c9                   	leave  
c0004c51:	c3                   	ret    

c0004c52 <ioq_getchar>:

// 消费者从ioq队列中读一字节
char ioq_getchar(struct ioqueue *ioq) {
c0004c52:	55                   	push   %ebp
c0004c53:	89 e5                	mov    %esp,%ebp
c0004c55:	83 ec 18             	sub    $0x18,%esp
  ASSERT(intr_get_status() == INTR_OFF);
c0004c58:	e8 44 cd ff ff       	call   c00019a1 <intr_get_status>
c0004c5d:	85 c0                	test   %eax,%eax
c0004c5f:	74 4b                	je     c0004cac <ioq_getchar+0x5a>
c0004c61:	68 00 cd 00 c0       	push   $0xc000cd00
c0004c66:	68 90 cd 00 c0       	push   $0xc000cd90
c0004c6b:	6a 2a                	push   $0x2a
c0004c6d:	68 1e cd 00 c0       	push   $0xc000cd1e
c0004c72:	e8 61 d6 ff ff       	call   c00022d8 <panic_spin>
c0004c77:	83 c4 10             	add    $0x10,%esp
  while (ioq_empty(ioq)) {
c0004c7a:	eb 30                	jmp    c0004cac <ioq_getchar+0x5a>
    // 缓冲区为空-> 先睡眠
    lock_acquire(&ioq->lock);
c0004c7c:	8b 45 08             	mov    0x8(%ebp),%eax
c0004c7f:	83 ec 0c             	sub    $0xc,%esp
c0004c82:	50                   	push   %eax
c0004c83:	e8 91 f9 ff ff       	call   c0004619 <lock_acquire>
c0004c88:	83 c4 10             	add    $0x10,%esp
    ioq_wait(&ioq->consumer);
c0004c8b:	8b 45 08             	mov    0x8(%ebp),%eax
c0004c8e:	83 c0 20             	add    $0x20,%eax
c0004c91:	83 ec 0c             	sub    $0xc,%esp
c0004c94:	50                   	push   %eax
c0004c95:	e8 2b ff ff ff       	call   c0004bc5 <ioq_wait>
c0004c9a:	83 c4 10             	add    $0x10,%esp
    lock_release(&ioq->lock);
c0004c9d:	8b 45 08             	mov    0x8(%ebp),%eax
c0004ca0:	83 ec 0c             	sub    $0xc,%esp
c0004ca3:	50                   	push   %eax
c0004ca4:	e8 e5 f9 ff ff       	call   c000468e <lock_release>
c0004ca9:	83 c4 10             	add    $0x10,%esp
  while (ioq_empty(ioq)) {
c0004cac:	83 ec 0c             	sub    $0xc,%esp
c0004caf:	ff 75 08             	push   0x8(%ebp)
c0004cb2:	e8 d0 fe ff ff       	call   c0004b87 <ioq_empty>
c0004cb7:	83 c4 10             	add    $0x10,%esp
c0004cba:	85 c0                	test   %eax,%eax
c0004cbc:	75 be                	jne    c0004c7c <ioq_getchar+0x2a>
  }
  char byte = ioq->buf[ioq->tail]; // 从缓冲区中取出
c0004cbe:	8b 45 08             	mov    0x8(%ebp),%eax
c0004cc1:	8b 40 68             	mov    0x68(%eax),%eax
c0004cc4:	8b 55 08             	mov    0x8(%ebp),%edx
c0004cc7:	0f b6 44 02 24       	movzbl 0x24(%edx,%eax,1),%eax
c0004ccc:	88 45 f7             	mov    %al,-0x9(%ebp)
  ioq->tail = next_pos(ioq->tail); // 把读游标移到下一位置
c0004ccf:	8b 45 08             	mov    0x8(%ebp),%eax
c0004cd2:	8b 40 68             	mov    0x68(%eax),%eax
c0004cd5:	83 ec 0c             	sub    $0xc,%esp
c0004cd8:	50                   	push   %eax
c0004cd9:	e8 49 fe ff ff       	call   c0004b27 <next_pos>
c0004cde:	83 c4 10             	add    $0x10,%esp
c0004ce1:	8b 55 08             	mov    0x8(%ebp),%edx
c0004ce4:	89 42 68             	mov    %eax,0x68(%edx)
  if (ioq->producer != NULL) {
c0004ce7:	8b 45 08             	mov    0x8(%ebp),%eax
c0004cea:	8b 40 1c             	mov    0x1c(%eax),%eax
c0004ced:	85 c0                	test   %eax,%eax
c0004cef:	74 12                	je     c0004d03 <ioq_getchar+0xb1>
    wakeup(&ioq->producer); // 唤醒生产者
c0004cf1:	8b 45 08             	mov    0x8(%ebp),%eax
c0004cf4:	83 c0 1c             	add    $0x1c,%eax
c0004cf7:	83 ec 0c             	sub    $0xc,%esp
c0004cfa:	50                   	push   %eax
c0004cfb:	e8 0d ff ff ff       	call   c0004c0d <wakeup>
c0004d00:	83 c4 10             	add    $0x10,%esp
  }
  return byte;
c0004d03:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
}
c0004d07:	c9                   	leave  
c0004d08:	c3                   	ret    

c0004d09 <ioq_putchar>:

// 生产者往ioq队列中写一字节
void ioq_putchar(struct ioqueue *ioq, char byte) {
c0004d09:	55                   	push   %ebp
c0004d0a:	89 e5                	mov    %esp,%ebp
c0004d0c:	83 ec 18             	sub    $0x18,%esp
c0004d0f:	8b 45 0c             	mov    0xc(%ebp),%eax
c0004d12:	88 45 f4             	mov    %al,-0xc(%ebp)
  ASSERT(intr_get_status() == INTR_OFF);
c0004d15:	e8 87 cc ff ff       	call   c00019a1 <intr_get_status>
c0004d1a:	85 c0                	test   %eax,%eax
c0004d1c:	74 4b                	je     c0004d69 <ioq_putchar+0x60>
c0004d1e:	68 00 cd 00 c0       	push   $0xc000cd00
c0004d23:	68 9c cd 00 c0       	push   $0xc000cd9c
c0004d28:	6a 3b                	push   $0x3b
c0004d2a:	68 1e cd 00 c0       	push   $0xc000cd1e
c0004d2f:	e8 a4 d5 ff ff       	call   c00022d8 <panic_spin>
c0004d34:	83 c4 10             	add    $0x10,%esp
  while (ioq_full(ioq)) {
c0004d37:	eb 30                	jmp    c0004d69 <ioq_putchar+0x60>
    // 缓冲区满-> 先睡眠
    lock_acquire(&ioq->lock); // 避免惊群情况出现
c0004d39:	8b 45 08             	mov    0x8(%ebp),%eax
c0004d3c:	83 ec 0c             	sub    $0xc,%esp
c0004d3f:	50                   	push   %eax
c0004d40:	e8 d4 f8 ff ff       	call   c0004619 <lock_acquire>
c0004d45:	83 c4 10             	add    $0x10,%esp
    ioq_wait(&ioq->producer);
c0004d48:	8b 45 08             	mov    0x8(%ebp),%eax
c0004d4b:	83 c0 1c             	add    $0x1c,%eax
c0004d4e:	83 ec 0c             	sub    $0xc,%esp
c0004d51:	50                   	push   %eax
c0004d52:	e8 6e fe ff ff       	call   c0004bc5 <ioq_wait>
c0004d57:	83 c4 10             	add    $0x10,%esp
    lock_release(&ioq->lock);
c0004d5a:	8b 45 08             	mov    0x8(%ebp),%eax
c0004d5d:	83 ec 0c             	sub    $0xc,%esp
c0004d60:	50                   	push   %eax
c0004d61:	e8 28 f9 ff ff       	call   c000468e <lock_release>
c0004d66:	83 c4 10             	add    $0x10,%esp
  while (ioq_full(ioq)) {
c0004d69:	83 ec 0c             	sub    $0xc,%esp
c0004d6c:	ff 75 08             	push   0x8(%ebp)
c0004d6f:	e8 c9 fd ff ff       	call   c0004b3d <ioq_full>
c0004d74:	83 c4 10             	add    $0x10,%esp
c0004d77:	85 c0                	test   %eax,%eax
c0004d79:	75 be                	jne    c0004d39 <ioq_putchar+0x30>
  }
  ioq->buf[ioq->head] = byte;      // 把字节放入缓冲区中
c0004d7b:	8b 45 08             	mov    0x8(%ebp),%eax
c0004d7e:	8b 40 64             	mov    0x64(%eax),%eax
c0004d81:	8b 55 08             	mov    0x8(%ebp),%edx
c0004d84:	0f b6 4d f4          	movzbl -0xc(%ebp),%ecx
c0004d88:	88 4c 02 24          	mov    %cl,0x24(%edx,%eax,1)
  ioq->head = next_pos(ioq->head); // 把写游标移到下一位置
c0004d8c:	8b 45 08             	mov    0x8(%ebp),%eax
c0004d8f:	8b 40 64             	mov    0x64(%eax),%eax
c0004d92:	83 ec 0c             	sub    $0xc,%esp
c0004d95:	50                   	push   %eax
c0004d96:	e8 8c fd ff ff       	call   c0004b27 <next_pos>
c0004d9b:	83 c4 10             	add    $0x10,%esp
c0004d9e:	8b 55 08             	mov    0x8(%ebp),%edx
c0004da1:	89 42 64             	mov    %eax,0x64(%edx)
  if (ioq->consumer != NULL) {
c0004da4:	8b 45 08             	mov    0x8(%ebp),%eax
c0004da7:	8b 40 20             	mov    0x20(%eax),%eax
c0004daa:	85 c0                	test   %eax,%eax
c0004dac:	74 12                	je     c0004dc0 <ioq_putchar+0xb7>
    wakeup(&ioq->consumer); // 唤醒消费者
c0004dae:	8b 45 08             	mov    0x8(%ebp),%eax
c0004db1:	83 c0 20             	add    $0x20,%eax
c0004db4:	83 ec 0c             	sub    $0xc,%esp
c0004db7:	50                   	push   %eax
c0004db8:	e8 50 fe ff ff       	call   c0004c0d <wakeup>
c0004dbd:	83 c4 10             	add    $0x10,%esp
  }
c0004dc0:	90                   	nop
c0004dc1:	c9                   	leave  
c0004dc2:	c3                   	ret    

c0004dc3 <update_tss_esp>:
};
static struct tss tss;
#define PG_SIZE 4096

// 更新tss中的esp0-> pthread的0级栈
void update_tss_esp(struct task_struct *pthread) {
c0004dc3:	55                   	push   %ebp
c0004dc4:	89 e5                	mov    %esp,%ebp
  // Linux任务切换-> 仅修改TSS中特权级0对应的栈
  tss.esp0 = (uint32_t *)((uint32_t)pthread + PG_SIZE);
c0004dc6:	8b 45 08             	mov    0x8(%ebp),%eax
c0004dc9:	05 00 10 00 00       	add    $0x1000,%eax
c0004dce:	a3 e4 1b 01 c0       	mov    %eax,0xc0011be4
}
c0004dd3:	90                   	nop
c0004dd4:	5d                   	pop    %ebp
c0004dd5:	c3                   	ret    

c0004dd6 <make_gdt_desc>:

// 创建GDT描述符
static struct gdt_desc make_gdt_desc(uint32_t *desc_addr, uint32_t limit,
                                     uint8_t attr_low, uint8_t attr_high) {
c0004dd6:	55                   	push   %ebp
c0004dd7:	89 e5                	mov    %esp,%ebp
c0004dd9:	83 ec 18             	sub    $0x18,%esp
c0004ddc:	8b 55 14             	mov    0x14(%ebp),%edx
c0004ddf:	8b 45 18             	mov    0x18(%ebp),%eax
c0004de2:	88 55 ec             	mov    %dl,-0x14(%ebp)
c0004de5:	88 45 e8             	mov    %al,-0x18(%ebp)
  uint32_t desc_base = (uint32_t)desc_addr;
c0004de8:	8b 45 0c             	mov    0xc(%ebp),%eax
c0004deb:	89 45 fc             	mov    %eax,-0x4(%ebp)
  struct gdt_desc desc;
  desc.limit_low_word = limit & 0x0000ffff;
c0004dee:	8b 45 10             	mov    0x10(%ebp),%eax
c0004df1:	66 89 45 f4          	mov    %ax,-0xc(%ebp)
  desc.base_low_word = desc_base & 0x0000ffff;
c0004df5:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0004df8:	66 89 45 f6          	mov    %ax,-0xa(%ebp)
  desc.base_mid_byte = ((desc_base & 0x00ff0000) >> 16);
c0004dfc:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0004dff:	c1 e8 10             	shr    $0x10,%eax
c0004e02:	88 45 f8             	mov    %al,-0x8(%ebp)
  desc.attr_low_byte = (uint8_t)(attr_low);
c0004e05:	0f b6 45 ec          	movzbl -0x14(%ebp),%eax
c0004e09:	88 45 f9             	mov    %al,-0x7(%ebp)
  desc.limit_high_attr_high =
      (((limit & 0x000f0000) >> 16) + (uint8_t)(attr_high));
c0004e0c:	8b 45 10             	mov    0x10(%ebp),%eax
c0004e0f:	c1 e8 10             	shr    $0x10,%eax
c0004e12:	83 e0 0f             	and    $0xf,%eax
c0004e15:	89 c2                	mov    %eax,%edx
c0004e17:	0f b6 45 e8          	movzbl -0x18(%ebp),%eax
c0004e1b:	01 d0                	add    %edx,%eax
  desc.limit_high_attr_high =
c0004e1d:	88 45 fa             	mov    %al,-0x6(%ebp)
  desc.base_high_byte = desc_base >> 24;
c0004e20:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0004e23:	c1 e8 18             	shr    $0x18,%eax
c0004e26:	88 45 fb             	mov    %al,-0x5(%ebp)
  return desc;
c0004e29:	8b 4d 08             	mov    0x8(%ebp),%ecx
c0004e2c:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0004e2f:	8b 55 f8             	mov    -0x8(%ebp),%edx
c0004e32:	89 01                	mov    %eax,(%ecx)
c0004e34:	89 51 04             	mov    %edx,0x4(%ecx)
}
c0004e37:	8b 45 08             	mov    0x8(%ebp),%eax
c0004e3a:	c9                   	leave  
c0004e3b:	c2 04 00             	ret    $0x4

c0004e3e <tss_init>:

// 初始化tss并装到GDT中，并在GDT中安装两个供用户进程用的描述符（DATA和CODE）
void tss_init() {
c0004e3e:	55                   	push   %ebp
c0004e3f:	89 e5                	mov    %esp,%ebp
c0004e41:	53                   	push   %ebx
c0004e42:	83 ec 24             	sub    $0x24,%esp
  put_str("tss_init start\n");
c0004e45:	83 ec 0c             	sub    $0xc,%esp
c0004e48:	68 a8 cd 00 c0       	push   $0xc000cda8
c0004e4d:	e8 de cb ff ff       	call   c0001a30 <put_str>
c0004e52:	83 c4 10             	add    $0x10,%esp
  uint32_t tss_size = sizeof(tss);
c0004e55:	c7 45 f4 6c 00 00 00 	movl   $0x6c,-0xc(%ebp)
  memset(&tss, 0, tss_size);
c0004e5c:	83 ec 04             	sub    $0x4,%esp
c0004e5f:	ff 75 f4             	push   -0xc(%ebp)
c0004e62:	6a 00                	push   $0x0
c0004e64:	68 e0 1b 01 c0       	push   $0xc0011be0
c0004e69:	e8 40 d5 ff ff       	call   c00023ae <memset>
c0004e6e:	83 c4 10             	add    $0x10,%esp
  tss.ss0 = SELECTOR_K_STACK;
c0004e71:	c7 05 e8 1b 01 c0 10 	movl   $0x10,0xc0011be8
c0004e78:	00 00 00 
  tss.io_base = tss_size; // 表示此TSS中没有IO位图
c0004e7b:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0004e7e:	a3 48 1c 01 c0       	mov    %eax,0xc0011c48

  // gdt段基址为0x900，tss放第4个也就是0x900+0x20

  // GDT中添加dpl=0的tss描述符、dpl=3的数据段和代码段描述符
  *((struct gdt_desc *)0xc0000920) = make_gdt_desc(
c0004e83:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0004e86:	8d 50 ff             	lea    -0x1(%eax),%edx
c0004e89:	bb 20 09 00 c0       	mov    $0xc0000920,%ebx
c0004e8e:	8d 45 e0             	lea    -0x20(%ebp),%eax
c0004e91:	83 ec 0c             	sub    $0xc,%esp
c0004e94:	68 80 00 00 00       	push   $0x80
c0004e99:	68 89 00 00 00       	push   $0x89
c0004e9e:	52                   	push   %edx
c0004e9f:	68 e0 1b 01 c0       	push   $0xc0011be0
c0004ea4:	50                   	push   %eax
c0004ea5:	e8 2c ff ff ff       	call   c0004dd6 <make_gdt_desc>
c0004eaa:	83 c4 1c             	add    $0x1c,%esp
c0004ead:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0004eb0:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c0004eb3:	89 03                	mov    %eax,(%ebx)
c0004eb5:	89 53 04             	mov    %edx,0x4(%ebx)
      (uint32_t *)&tss, tss_size - 1, TSS_ATTR_LOW, TSS_ATTR_HIGH);
  *((struct gdt_desc *)0xc0000928) = make_gdt_desc(
c0004eb8:	bb 28 09 00 c0       	mov    $0xc0000928,%ebx
c0004ebd:	8d 45 e0             	lea    -0x20(%ebp),%eax
c0004ec0:	83 ec 0c             	sub    $0xc,%esp
c0004ec3:	68 c0 00 00 00       	push   $0xc0
c0004ec8:	68 f8 00 00 00       	push   $0xf8
c0004ecd:	68 ff ff 0f 00       	push   $0xfffff
c0004ed2:	6a 00                	push   $0x0
c0004ed4:	50                   	push   %eax
c0004ed5:	e8 fc fe ff ff       	call   c0004dd6 <make_gdt_desc>
c0004eda:	83 c4 1c             	add    $0x1c,%esp
c0004edd:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0004ee0:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c0004ee3:	89 03                	mov    %eax,(%ebx)
c0004ee5:	89 53 04             	mov    %edx,0x4(%ebx)
      (uint32_t *)0, 0xfffff, GDT_CODE_ATTR_LOW_DPL3, GDT_ATTR_HIGH);
  *((struct gdt_desc *)0xc0000930) = make_gdt_desc(
c0004ee8:	bb 30 09 00 c0       	mov    $0xc0000930,%ebx
c0004eed:	8d 45 e0             	lea    -0x20(%ebp),%eax
c0004ef0:	83 ec 0c             	sub    $0xc,%esp
c0004ef3:	68 c0 00 00 00       	push   $0xc0
c0004ef8:	68 f2 00 00 00       	push   $0xf2
c0004efd:	68 ff ff 0f 00       	push   $0xfffff
c0004f02:	6a 00                	push   $0x0
c0004f04:	50                   	push   %eax
c0004f05:	e8 cc fe ff ff       	call   c0004dd6 <make_gdt_desc>
c0004f0a:	83 c4 1c             	add    $0x1c,%esp
c0004f0d:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0004f10:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c0004f13:	89 03                	mov    %eax,(%ebx)
c0004f15:	89 53 04             	mov    %edx,0x4(%ebx)
      (uint32_t *)0, 0xfffff, GDT_DATA_ATTR_LOW_DPL3, GDT_ATTR_HIGH);

  // 16位表界限 & 32位表起始地址
  uint64_t gdt_operand = ((8 * 7 - 1) | ((uint64_t)(uint32_t)0xc0000900 << 16));
c0004f18:	c7 45 e8 37 00 00 09 	movl   $0x9000037,-0x18(%ebp)
c0004f1f:	c7 45 ec 00 c0 00 00 	movl   $0xc000,-0x14(%ebp)
  asm volatile("lgdt %0" : : "m"(gdt_operand));  // GDT变更，重新加载GDT
c0004f26:	0f 01 55 e8          	lgdtl  -0x18(%ebp)
  asm volatile("ltr %w0" : : "r"(SELECTOR_TSS)); // 将tss加载到TR
c0004f2a:	b8 20 00 00 00       	mov    $0x20,%eax
c0004f2f:	0f 00 d8             	ltr    %ax
  put_str("tss_init and ltr done\n");
c0004f32:	83 ec 0c             	sub    $0xc,%esp
c0004f35:	68 b8 cd 00 c0       	push   $0xc000cdb8
c0004f3a:	e8 f1 ca ff ff       	call   c0001a30 <put_str>
c0004f3f:	83 c4 10             	add    $0x10,%esp
c0004f42:	90                   	nop
c0004f43:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c0004f46:	c9                   	leave  
c0004f47:	c3                   	ret    

c0004f48 <start_process>:
#include "userprog.h"

extern void intr_exit(void);

// 创建用户进程filename的上下文（填充用户进程的中断栈intr_stack
void start_process(void *filename_) {
c0004f48:	55                   	push   %ebp
c0004f49:	89 e5                	mov    %esp,%ebp
c0004f4b:	83 ec 18             	sub    $0x18,%esp
  void *func = filename_;
c0004f4e:	8b 45 08             	mov    0x8(%ebp),%eax
c0004f51:	89 45 f4             	mov    %eax,-0xc(%ebp)
  struct task_struct *cur = running_thread();
c0004f54:	e8 b6 eb ff ff       	call   c0003b0f <running_thread>
c0004f59:	89 45 f0             	mov    %eax,-0x10(%ebp)
  cur->self_kstack +=
c0004f5c:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0004f5f:	8b 00                	mov    (%eax),%eax
c0004f61:	8d 90 80 00 00 00    	lea    0x80(%eax),%edx
c0004f67:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0004f6a:	89 10                	mov    %edx,(%eax)
  /*
   *【创建线程的时候没预留但是运行正常的原因猜测】
   * 此时处与内核态，指针可能指向了内核空间。
   * PCB放在内核空间中，导致越界的空间可能是刚好初始化预留过的
   */
  struct intr_stack *proc_stack = (struct intr_stack *)cur->self_kstack;
c0004f6c:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0004f6f:	8b 00                	mov    (%eax),%eax
c0004f71:	89 45 ec             	mov    %eax,-0x14(%ebp)
  proc_stack->edi = 0;
c0004f74:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004f77:	c7 40 04 00 00 00 00 	movl   $0x0,0x4(%eax)
  proc_stack->esi = 0;
c0004f7e:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004f81:	c7 40 08 00 00 00 00 	movl   $0x0,0x8(%eax)
  proc_stack->ebp = 0;
c0004f88:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004f8b:	c7 40 0c 00 00 00 00 	movl   $0x0,0xc(%eax)
  proc_stack->esp_dummy = 0;
c0004f92:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004f95:	c7 40 10 00 00 00 00 	movl   $0x0,0x10(%eax)

  proc_stack->ebx = 0;
c0004f9c:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004f9f:	c7 40 14 00 00 00 00 	movl   $0x0,0x14(%eax)
  proc_stack->edx = 0;
c0004fa6:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004fa9:	c7 40 18 00 00 00 00 	movl   $0x0,0x18(%eax)
  proc_stack->ecx = 0;
c0004fb0:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004fb3:	c7 40 1c 00 00 00 00 	movl   $0x0,0x1c(%eax)
  proc_stack->eax = 0;
c0004fba:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004fbd:	c7 40 20 00 00 00 00 	movl   $0x0,0x20(%eax)

  proc_stack->gs = 0; // 显存段用户态用不上
c0004fc4:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004fc7:	c7 40 24 00 00 00 00 	movl   $0x0,0x24(%eax)

  proc_stack->ds = SELECTOR_U_DATA;
c0004fce:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004fd1:	c7 40 30 33 00 00 00 	movl   $0x33,0x30(%eax)
  proc_stack->es = SELECTOR_U_DATA;
c0004fd8:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004fdb:	c7 40 2c 33 00 00 00 	movl   $0x33,0x2c(%eax)
  proc_stack->fs = SELECTOR_U_DATA;
c0004fe2:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004fe5:	c7 40 28 33 00 00 00 	movl   $0x33,0x28(%eax)

  proc_stack->eip = func; // 待执行的用户程序
c0004fec:	8b 55 f4             	mov    -0xc(%ebp),%edx
c0004fef:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004ff2:	89 50 38             	mov    %edx,0x38(%eax)
  proc_stack->cs = SELECTOR_U_CODE;
c0004ff5:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004ff8:	c7 40 3c 2b 00 00 00 	movl   $0x2b,0x3c(%eax)
  proc_stack->eflags = (EFLAGS_IOPL_0 | EFLAGS_MBS | EFLAGS_IF_1);
c0004fff:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0005002:	c7 40 40 02 02 00 00 	movl   $0x202,0x40(%eax)

  // 为用户进程分配3特权级栈->（esp指向从用户内存池中分配的地址
  proc_stack->esp =
      (void *)((uint32_t)get_a_page(PF_USER, USER_STACK3_VADDR) + PG_SIZE);
c0005009:	83 ec 08             	sub    $0x8,%esp
c000500c:	68 00 f0 ff bf       	push   $0xbffff000
c0005011:	6a 02                	push   $0x2
c0005013:	e8 27 de ff ff       	call   c0002e3f <get_a_page>
c0005018:	83 c4 10             	add    $0x10,%esp
c000501b:	05 00 10 00 00       	add    $0x1000,%eax
c0005020:	89 c2                	mov    %eax,%edx
  proc_stack->esp =
c0005022:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0005025:	89 50 44             	mov    %edx,0x44(%eax)
  proc_stack->ss = SELECTOR_U_DATA; // 栈段
c0005028:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000502b:	c7 40 48 33 00 00 00 	movl   $0x33,0x48(%eax)

  asm volatile("movl %0, %%esp; jmp intr_exit" ::"g"(proc_stack) : "memory");
c0005032:	8b 65 ec             	mov    -0x14(%ebp),%esp
c0005035:	e9 56 cb ff ff       	jmp    c0001b90 <intr_exit>
}
c000503a:	90                   	nop
c000503b:	c9                   	leave  
c000503c:	c3                   	ret    

c000503d <page_dir_activate>:

// 激活进程/线程页表-> 更新cr3
void page_dir_activate(struct task_struct *p_thread) {
c000503d:	55                   	push   %ebp
c000503e:	89 e5                	mov    %esp,%ebp
c0005040:	83 ec 18             	sub    $0x18,%esp
  // 内核线程，默认为内核页目录物理地址
  uint32_t pagedir_phy_addr = 0x100000;
c0005043:	c7 45 f4 00 00 10 00 	movl   $0x100000,-0xc(%ebp)
  if (p_thread->pgdir != NULL) { // 用户进程有自己的页目录表
c000504a:	8b 45 08             	mov    0x8(%ebp),%eax
c000504d:	8b 40 34             	mov    0x34(%eax),%eax
c0005050:	85 c0                	test   %eax,%eax
c0005052:	74 15                	je     c0005069 <page_dir_activate+0x2c>
    pagedir_phy_addr = addr_v2p((uint32_t)p_thread->pgdir);
c0005054:	8b 45 08             	mov    0x8(%ebp),%eax
c0005057:	8b 40 34             	mov    0x34(%eax),%eax
c000505a:	83 ec 0c             	sub    $0xc,%esp
c000505d:	50                   	push   %eax
c000505e:	e8 a8 d9 ff ff       	call   c0002a0b <addr_v2p>
c0005063:	83 c4 10             	add    $0x10,%esp
c0005066:	89 45 f4             	mov    %eax,-0xc(%ebp)
  }
  asm volatile("movl %0, %%cr3" ::"r"(pagedir_phy_addr) : "memory");
c0005069:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000506c:	0f 22 d8             	mov    %eax,%cr3
}
c000506f:	90                   	nop
c0005070:	c9                   	leave  
c0005071:	c3                   	ret    

c0005072 <process_active>:

// 激活页表，并根据任务是否为进程来修改tss.esp0
void process_active(struct task_struct *p_thread) {
c0005072:	55                   	push   %ebp
c0005073:	89 e5                	mov    %esp,%ebp
c0005075:	83 ec 08             	sub    $0x8,%esp
  ASSERT(p_thread != NULL);
c0005078:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c000507c:	75 19                	jne    c0005097 <process_active+0x25>
c000507e:	68 d0 cd 00 c0       	push   $0xc000cdd0
c0005083:	68 8c ce 00 c0       	push   $0xc000ce8c
c0005088:	6a 44                	push   $0x44
c000508a:	68 e1 cd 00 c0       	push   $0xc000cde1
c000508f:	e8 44 d2 ff ff       	call   c00022d8 <panic_spin>
c0005094:	83 c4 10             	add    $0x10,%esp
  page_dir_activate(p_thread);
c0005097:	83 ec 0c             	sub    $0xc,%esp
c000509a:	ff 75 08             	push   0x8(%ebp)
c000509d:	e8 9b ff ff ff       	call   c000503d <page_dir_activate>
c00050a2:	83 c4 10             	add    $0x10,%esp

  if (p_thread->pgdir) {
c00050a5:	8b 45 08             	mov    0x8(%ebp),%eax
c00050a8:	8b 40 34             	mov    0x34(%eax),%eax
c00050ab:	85 c0                	test   %eax,%eax
c00050ad:	74 0e                	je     c00050bd <process_active+0x4b>
    // 更新tss.esp0-> 进程的特权级0栈，用于此进程中断进入内核态下保留上下文
    update_tss_esp(p_thread);
c00050af:	83 ec 0c             	sub    $0xc,%esp
c00050b2:	ff 75 08             	push   0x8(%ebp)
c00050b5:	e8 09 fd ff ff       	call   c0004dc3 <update_tss_esp>
c00050ba:	83 c4 10             	add    $0x10,%esp
  }
}
c00050bd:	90                   	nop
c00050be:	c9                   	leave  
c00050bf:	c3                   	ret    

c00050c0 <create_page_dir>:

// 创建页目录表，返回页目录虚拟地址
uint32_t *create_page_dir(void) {
c00050c0:	55                   	push   %ebp
c00050c1:	89 e5                	mov    %esp,%ebp
c00050c3:	83 ec 18             	sub    $0x18,%esp
  uint32_t *page_dir_vaddr = get_kernel_pages(1); // 内核空间申请
c00050c6:	83 ec 0c             	sub    $0xc,%esp
c00050c9:	6a 01                	push   $0x1
c00050cb:	e8 d9 dc ff ff       	call   c0002da9 <get_kernel_pages>
c00050d0:	83 c4 10             	add    $0x10,%esp
c00050d3:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (page_dir_vaddr == NULL) {
c00050d6:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
c00050da:	75 17                	jne    c00050f3 <create_page_dir+0x33>
    console_put_str("create_page_dir: get_kernel_page failed!");
c00050dc:	83 ec 0c             	sub    $0xc,%esp
c00050df:	68 f4 cd 00 c0       	push   $0xc000cdf4
c00050e4:	e8 88 f6 ff ff       	call   c0004771 <console_put_str>
c00050e9:	83 c4 10             	add    $0x10,%esp
    return NULL;
c00050ec:	b8 00 00 00 00       	mov    $0x0,%eax
c00050f1:	eb 43                	jmp    c0005136 <create_page_dir+0x76>
  }

  // 为让所有进程共享内核：将内核所在页目录项（访问内核的入口）复制到进程页目录项目的同等位置
  // 1、复制页表（page_dir_vaddr + 0x300*4 ：内核页目录第768项
  memcpy((uint32_t *)((uint32_t)page_dir_vaddr + 0x300 * 4),
c00050f3:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00050f6:	05 00 0c 00 00       	add    $0xc00,%eax
c00050fb:	83 ec 04             	sub    $0x4,%esp
c00050fe:	68 00 04 00 00       	push   $0x400
c0005103:	68 00 fc ff ff       	push   $0xfffffc00
c0005108:	50                   	push   %eax
c0005109:	e8 f3 d2 ff ff       	call   c0002401 <memcpy>
c000510e:	83 c4 10             	add    $0x10,%esp
         (uint32_t *)(0xfffff000 + 0x300 * 4), 1024);
  // 2、更新页目录地址
  uint32_t new_page_dir_phy_addr = addr_v2p((uint32_t)page_dir_vaddr);
c0005111:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0005114:	83 ec 0c             	sub    $0xc,%esp
c0005117:	50                   	push   %eax
c0005118:	e8 ee d8 ff ff       	call   c0002a0b <addr_v2p>
c000511d:	83 c4 10             	add    $0x10,%esp
c0005120:	89 45 f0             	mov    %eax,-0x10(%ebp)
  page_dir_vaddr[1023] =
c0005123:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0005126:	05 fc 0f 00 00       	add    $0xffc,%eax
      new_page_dir_phy_addr | PG_US_U | PG_RW_W | PG_P_1; // 最后一项指向自己
c000512b:	8b 55 f0             	mov    -0x10(%ebp),%edx
c000512e:	83 ca 07             	or     $0x7,%edx
  page_dir_vaddr[1023] =
c0005131:	89 10                	mov    %edx,(%eax)

  return page_dir_vaddr;
c0005133:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0005136:	c9                   	leave  
c0005137:	c3                   	ret    

c0005138 <create_user_vaddr_bitmap>:

// 创建用户进程的虚拟内存池（bitmap
void create_user_vaddr_bitmap(struct task_struct *user_prog) {
c0005138:	55                   	push   %ebp
c0005139:	89 e5                	mov    %esp,%ebp
c000513b:	83 ec 18             	sub    $0x18,%esp
  user_prog->userprog_vaddr.vaddr_start = USER_VADDR_START;
c000513e:	8b 45 08             	mov    0x8(%ebp),%eax
c0005141:	c7 40 40 00 80 04 08 	movl   $0x8048000,0x40(%eax)
  uint32_t bitmap_pg_cnt =
c0005148:	c7 45 f4 17 00 00 00 	movl   $0x17,-0xc(%ebp)
      DIV_ROUND_UP((0xc0000000 - USER_VADDR_START) / PG_SIZE / 8, PG_SIZE);
  user_prog->userprog_vaddr.vaddr_bitmap.bits = get_kernel_pages(bitmap_pg_cnt);
c000514f:	83 ec 0c             	sub    $0xc,%esp
c0005152:	ff 75 f4             	push   -0xc(%ebp)
c0005155:	e8 4f dc ff ff       	call   c0002da9 <get_kernel_pages>
c000515a:	83 c4 10             	add    $0x10,%esp
c000515d:	8b 55 08             	mov    0x8(%ebp),%edx
c0005160:	89 42 3c             	mov    %eax,0x3c(%edx)
  user_prog->userprog_vaddr.vaddr_bitmap.btmp_bytes_len =
c0005163:	8b 45 08             	mov    0x8(%ebp),%eax
c0005166:	c7 40 38 f7 6f 01 00 	movl   $0x16ff7,0x38(%eax)
      (0xc0000000 - USER_VADDR_START) / PG_SIZE / 8;
  bitmap_init(&user_prog->userprog_vaddr.vaddr_bitmap);
c000516d:	8b 45 08             	mov    0x8(%ebp),%eax
c0005170:	83 c0 38             	add    $0x38,%eax
c0005173:	83 ec 0c             	sub    $0xc,%esp
c0005176:	50                   	push   %eax
c0005177:	e8 00 d6 ff ff       	call   c000277c <bitmap_init>
c000517c:	83 c4 10             	add    $0x10,%esp
}
c000517f:	90                   	nop
c0005180:	c9                   	leave  
c0005181:	c3                   	ret    

c0005182 <process_execute>:

// 创建用户进程
void process_execute(void *filename, char *name) { // filename：用户进程地址
c0005182:	55                   	push   %ebp
c0005183:	89 e5                	mov    %esp,%ebp
c0005185:	83 ec 18             	sub    $0x18,%esp
  struct task_struct *thread = get_kernel_pages(1);
c0005188:	83 ec 0c             	sub    $0xc,%esp
c000518b:	6a 01                	push   $0x1
c000518d:	e8 17 dc ff ff       	call   c0002da9 <get_kernel_pages>
c0005192:	83 c4 10             	add    $0x10,%esp
c0005195:	89 45 f4             	mov    %eax,-0xc(%ebp)
  init_thread(thread, name, default_prio);
c0005198:	83 ec 04             	sub    $0x4,%esp
c000519b:	6a 14                	push   $0x14
c000519d:	ff 75 0c             	push   0xc(%ebp)
c00051a0:	ff 75 f4             	push   -0xc(%ebp)
c00051a3:	e8 65 ea ff ff       	call   c0003c0d <init_thread>
c00051a8:	83 c4 10             	add    $0x10,%esp
  create_user_vaddr_bitmap(thread);
c00051ab:	83 ec 0c             	sub    $0xc,%esp
c00051ae:	ff 75 f4             	push   -0xc(%ebp)
c00051b1:	e8 82 ff ff ff       	call   c0005138 <create_user_vaddr_bitmap>
c00051b6:	83 c4 10             	add    $0x10,%esp
  thread_create(thread, start_process, filename);
c00051b9:	83 ec 04             	sub    $0x4,%esp
c00051bc:	ff 75 08             	push   0x8(%ebp)
c00051bf:	68 48 4f 00 c0       	push   $0xc0004f48
c00051c4:	ff 75 f4             	push   -0xc(%ebp)
c00051c7:	e8 ca e9 ff ff       	call   c0003b96 <thread_create>
c00051cc:	83 c4 10             	add    $0x10,%esp
  thread->pgdir = create_page_dir();
c00051cf:	e8 ec fe ff ff       	call   c00050c0 <create_page_dir>
c00051d4:	8b 55 f4             	mov    -0xc(%ebp),%edx
c00051d7:	89 42 34             	mov    %eax,0x34(%edx)
  block_desc_init(thread->u_block_desc);
c00051da:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00051dd:	83 c0 44             	add    $0x44,%eax
c00051e0:	83 ec 0c             	sub    $0xc,%esp
c00051e3:	50                   	push   %eax
c00051e4:	e8 40 e8 ff ff       	call   c0003a29 <block_desc_init>
c00051e9:	83 c4 10             	add    $0x10,%esp

  enum intr_status old_status = intr_disable();
c00051ec:	e8 4c c7 ff ff       	call   c000193d <intr_disable>
c00051f1:	89 45 f0             	mov    %eax,-0x10(%ebp)
  ASSERT(!elem_find(&thread_ready_list, &thread->general_tag));
c00051f4:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00051f7:	83 c0 24             	add    $0x24,%eax
c00051fa:	83 ec 08             	sub    $0x8,%esp
c00051fd:	50                   	push   %eax
c00051fe:	68 fc 1a 01 c0       	push   $0xc0011afc
c0005203:	e8 09 f1 ff ff       	call   c0004311 <elem_find>
c0005208:	83 c4 10             	add    $0x10,%esp
c000520b:	85 c0                	test   %eax,%eax
c000520d:	74 19                	je     c0005228 <process_execute+0xa6>
c000520f:	68 20 ce 00 c0       	push   $0xc000ce20
c0005214:	68 9c ce 00 c0       	push   $0xc000ce9c
c0005219:	6a 76                	push   $0x76
c000521b:	68 e1 cd 00 c0       	push   $0xc000cde1
c0005220:	e8 b3 d0 ff ff       	call   c00022d8 <panic_spin>
c0005225:	83 c4 10             	add    $0x10,%esp
  list_append(&thread_ready_list, &thread->general_tag);
c0005228:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000522b:	83 c0 24             	add    $0x24,%eax
c000522e:	83 ec 08             	sub    $0x8,%esp
c0005231:	50                   	push   %eax
c0005232:	68 fc 1a 01 c0       	push   $0xc0011afc
c0005237:	e8 5b f0 ff ff       	call   c0004297 <list_append>
c000523c:	83 c4 10             	add    $0x10,%esp

  ASSERT(!elem_find(&thread_all_list, &thread->all_list_tag));
c000523f:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0005242:	83 c0 2c             	add    $0x2c,%eax
c0005245:	83 ec 08             	sub    $0x8,%esp
c0005248:	50                   	push   %eax
c0005249:	68 0c 1b 01 c0       	push   $0xc0011b0c
c000524e:	e8 be f0 ff ff       	call   c0004311 <elem_find>
c0005253:	83 c4 10             	add    $0x10,%esp
c0005256:	85 c0                	test   %eax,%eax
c0005258:	74 19                	je     c0005273 <process_execute+0xf1>
c000525a:	68 58 ce 00 c0       	push   $0xc000ce58
c000525f:	68 9c ce 00 c0       	push   $0xc000ce9c
c0005264:	6a 79                	push   $0x79
c0005266:	68 e1 cd 00 c0       	push   $0xc000cde1
c000526b:	e8 68 d0 ff ff       	call   c00022d8 <panic_spin>
c0005270:	83 c4 10             	add    $0x10,%esp
    list_append(&thread_all_list, &thread->all_list_tag);
c0005273:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0005276:	83 c0 2c             	add    $0x2c,%eax
c0005279:	83 ec 08             	sub    $0x8,%esp
c000527c:	50                   	push   %eax
c000527d:	68 0c 1b 01 c0       	push   $0xc0011b0c
c0005282:	e8 10 f0 ff ff       	call   c0004297 <list_append>
c0005287:	83 c4 10             	add    $0x10,%esp
  intr_set_status(old_status);
c000528a:	83 ec 0c             	sub    $0xc,%esp
c000528d:	ff 75 f0             	push   -0x10(%ebp)
c0005290:	e8 ee c6 ff ff       	call   c0001983 <intr_set_status>
c0005295:	83 c4 10             	add    $0x10,%esp
c0005298:	90                   	nop
c0005299:	c9                   	leave  
c000529a:	c3                   	ret    

c000529b <getpid>:
    retval;                                                                    \
  })

// 系统调用用户接口

uint32_t getpid() { return _syscall0(SYS_GETPID); }
c000529b:	55                   	push   %ebp
c000529c:	89 e5                	mov    %esp,%ebp
c000529e:	83 ec 10             	sub    $0x10,%esp
c00052a1:	b8 00 00 00 00       	mov    $0x0,%eax
c00052a6:	cd 80                	int    $0x80
c00052a8:	89 45 fc             	mov    %eax,-0x4(%ebp)
c00052ab:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00052ae:	c9                   	leave  
c00052af:	c3                   	ret    

c00052b0 <write>:

// 把buf中count个字符写入文件描述符fd
uint32_t write(int32_t fd, const void *buf, uint32_t count) {
c00052b0:	55                   	push   %ebp
c00052b1:	89 e5                	mov    %esp,%ebp
c00052b3:	53                   	push   %ebx
c00052b4:	83 ec 10             	sub    $0x10,%esp
  return _syscall3(SYS_WRITE, fd, buf, count);
c00052b7:	b8 01 00 00 00       	mov    $0x1,%eax
c00052bc:	8b 5d 08             	mov    0x8(%ebp),%ebx
c00052bf:	8b 4d 0c             	mov    0xc(%ebp),%ecx
c00052c2:	8b 55 10             	mov    0x10(%ebp),%edx
c00052c5:	cd 80                	int    $0x80
c00052c7:	89 45 f8             	mov    %eax,-0x8(%ebp)
c00052ca:	8b 45 f8             	mov    -0x8(%ebp),%eax
}
c00052cd:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c00052d0:	c9                   	leave  
c00052d1:	c3                   	ret    

c00052d2 <malloc>:

void *malloc(uint32_t size) { return (void *)_syscall1(SYS_MALLOC, size); }
c00052d2:	55                   	push   %ebp
c00052d3:	89 e5                	mov    %esp,%ebp
c00052d5:	53                   	push   %ebx
c00052d6:	83 ec 10             	sub    $0x10,%esp
c00052d9:	b8 02 00 00 00       	mov    $0x2,%eax
c00052de:	8b 55 08             	mov    0x8(%ebp),%edx
c00052e1:	89 d3                	mov    %edx,%ebx
c00052e3:	cd 80                	int    $0x80
c00052e5:	89 45 f8             	mov    %eax,-0x8(%ebp)
c00052e8:	8b 45 f8             	mov    -0x8(%ebp),%eax
c00052eb:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c00052ee:	c9                   	leave  
c00052ef:	c3                   	ret    

c00052f0 <free>:

void free(void *ptr) { _syscall1(SYS_FREE, ptr); }
c00052f0:	55                   	push   %ebp
c00052f1:	89 e5                	mov    %esp,%ebp
c00052f3:	53                   	push   %ebx
c00052f4:	83 ec 10             	sub    $0x10,%esp
c00052f7:	b8 03 00 00 00       	mov    $0x3,%eax
c00052fc:	8b 55 08             	mov    0x8(%ebp),%edx
c00052ff:	89 d3                	mov    %edx,%ebx
c0005301:	cd 80                	int    $0x80
c0005303:	89 45 f8             	mov    %eax,-0x8(%ebp)
c0005306:	90                   	nop
c0005307:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c000530a:	c9                   	leave  
c000530b:	c3                   	ret    

c000530c <fork>:

pid_t fork() { return _syscall0(SYS_FORK); }
c000530c:	55                   	push   %ebp
c000530d:	89 e5                	mov    %esp,%ebp
c000530f:	83 ec 10             	sub    $0x10,%esp
c0005312:	b8 04 00 00 00       	mov    $0x4,%eax
c0005317:	cd 80                	int    $0x80
c0005319:	89 45 fc             	mov    %eax,-0x4(%ebp)
c000531c:	8b 45 fc             	mov    -0x4(%ebp),%eax
c000531f:	c9                   	leave  
c0005320:	c3                   	ret    

c0005321 <read>:

int32_t read(int32_t fd, void *buf, uint32_t count) {
c0005321:	55                   	push   %ebp
c0005322:	89 e5                	mov    %esp,%ebp
c0005324:	53                   	push   %ebx
c0005325:	83 ec 10             	sub    $0x10,%esp
  return _syscall3(SYS_READ, fd, buf, count);
c0005328:	b8 05 00 00 00       	mov    $0x5,%eax
c000532d:	8b 5d 08             	mov    0x8(%ebp),%ebx
c0005330:	8b 4d 0c             	mov    0xc(%ebp),%ecx
c0005333:	8b 55 10             	mov    0x10(%ebp),%edx
c0005336:	cd 80                	int    $0x80
c0005338:	89 45 f8             	mov    %eax,-0x8(%ebp)
c000533b:	8b 45 f8             	mov    -0x8(%ebp),%eax
}
c000533e:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c0005341:	c9                   	leave  
c0005342:	c3                   	ret    

c0005343 <putchar>:

void putchar(char char_asci) { _syscall1(SYS_PUTCHAR, char_asci); }
c0005343:	55                   	push   %ebp
c0005344:	89 e5                	mov    %esp,%ebp
c0005346:	53                   	push   %ebx
c0005347:	83 ec 14             	sub    $0x14,%esp
c000534a:	8b 45 08             	mov    0x8(%ebp),%eax
c000534d:	88 45 e8             	mov    %al,-0x18(%ebp)
c0005350:	b8 06 00 00 00       	mov    $0x6,%eax
c0005355:	0f b6 55 e8          	movzbl -0x18(%ebp),%edx
c0005359:	89 d3                	mov    %edx,%ebx
c000535b:	cd 80                	int    $0x80
c000535d:	89 45 f8             	mov    %eax,-0x8(%ebp)
c0005360:	90                   	nop
c0005361:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c0005364:	c9                   	leave  
c0005365:	c3                   	ret    

c0005366 <clear>:

c0005366:	55                   	push   %ebp
c0005367:	89 e5                	mov    %esp,%ebp
c0005369:	83 ec 10             	sub    $0x10,%esp
c000536c:	b8 07 00 00 00       	mov    $0x7,%eax
c0005371:	cd 80                	int    $0x80
c0005373:	89 45 fc             	mov    %eax,-0x4(%ebp)
c0005376:	90                   	nop
c0005377:	c9                   	leave  
c0005378:	c3                   	ret    

c0005379 <sys_getpid>:

#define syscall_nr 32 // 最大支持的系统调用子功能个数
typedef void *syscall;
syscall syscall_table[syscall_nr];

uint32_t sys_getpid(void) { return running_thread()->pid; }
c0005379:	55                   	push   %ebp
c000537a:	89 e5                	mov    %esp,%ebp
c000537c:	83 ec 08             	sub    $0x8,%esp
c000537f:	e8 8b e7 ff ff       	call   c0003b0f <running_thread>
c0005384:	0f b7 40 04          	movzwl 0x4(%eax),%eax
c0005388:	98                   	cwtl   
c0005389:	c9                   	leave  
c000538a:	c3                   	ret    

c000538b <syscall_init>:

// 初始化系统调用
void syscall_init(void) {
c000538b:	55                   	push   %ebp
c000538c:	89 e5                	mov    %esp,%ebp
c000538e:	83 ec 08             	sub    $0x8,%esp
  put_str("syscall_init start\n");
c0005391:	83 ec 0c             	sub    $0xc,%esp
c0005394:	68 ac ce 00 c0       	push   $0xc000ceac
c0005399:	e8 92 c6 ff ff       	call   c0001a30 <put_str>
c000539e:	83 c4 10             	add    $0x10,%esp
  syscall_table[SYS_GETPID] = sys_getpid;
c00053a1:	c7 05 60 1c 01 c0 79 	movl   $0xc0005379,0xc0011c60
c00053a8:	53 00 c0 
  syscall_table[SYS_WRITE] = sys_write;
c00053ab:	c7 05 64 1c 01 c0 6d 	movl   $0xc000716d,0xc0011c64
c00053b2:	71 00 c0 
  syscall_table[SYS_MALLOC] = sys_malloc;
c00053b5:	c7 05 68 1c 01 c0 24 	movl   $0xc0003024,0xc0011c68
c00053bc:	30 00 c0 
  syscall_table[SYS_FREE] = sys_free;
c00053bf:	c7 05 6c 1c 01 c0 43 	movl   $0xc0003643,0xc0011c6c
c00053c6:	36 00 c0 
  syscall_table[SYS_FORK] = sys_fork;
c00053c9:	c7 05 70 1c 01 c0 cd 	movl   $0xc000afcd,0xc0011c70
c00053d0:	af 00 c0 
  syscall_table[SYS_READ] = sys_read;
c00053d3:	c7 05 74 1c 01 c0 60 	movl   $0xc0007260,0xc0011c74
c00053da:	72 00 c0 
  syscall_table[SYS_PUTCHAR] = sys_putchar;
c00053dd:	c7 05 78 1c 01 c0 dc 	movl   $0xc00047dc,0xc0011c78
c00053e4:	47 00 c0 
  syscall_table[SYS_CLEAR] = cls_screen;
c00053e7:	c7 05 7c 1c 01 c0 ee 	movl   $0xc0001aee,0xc0011c7c
c00053ee:	1a 00 c0 
  put_str("syscall_init done\n");
c00053f1:	83 ec 0c             	sub    $0xc,%esp
c00053f4:	68 c0 ce 00 c0       	push   $0xc000cec0
c00053f9:	e8 32 c6 ff ff       	call   c0001a30 <put_str>
c00053fe:	83 c4 10             	add    $0x10,%esp
c0005401:	90                   	nop
c0005402:	c9                   	leave  
c0005403:	c3                   	ret    

c0005404 <itoa>:
#include "stdint.h"
#include "string.h"
#include "syscall.h"

// 整型int转字符ASCII（base：转换的进制
static void itoa(uint32_t value, char **buf_ptr_addr, uint8_t base) {
c0005404:	55                   	push   %ebp
c0005405:	89 e5                	mov    %esp,%ebp
c0005407:	53                   	push   %ebx
c0005408:	83 ec 24             	sub    $0x24,%esp
c000540b:	8b 45 10             	mov    0x10(%ebp),%eax
c000540e:	88 45 e4             	mov    %al,-0x1c(%ebp)
  uint32_t m = value % base; // 求模（最先掉低位但最后写入缓冲区
c0005411:	0f b6 4d e4          	movzbl -0x1c(%ebp),%ecx
c0005415:	8b 45 08             	mov    0x8(%ebp),%eax
c0005418:	ba 00 00 00 00       	mov    $0x0,%edx
c000541d:	f7 f1                	div    %ecx
c000541f:	89 55 f4             	mov    %edx,-0xc(%ebp)
  uint32_t i = value / base; // 取整
c0005422:	0f b6 5d e4          	movzbl -0x1c(%ebp),%ebx
c0005426:	8b 45 08             	mov    0x8(%ebp),%eax
c0005429:	ba 00 00 00 00       	mov    $0x0,%edx
c000542e:	f7 f3                	div    %ebx
c0005430:	89 45 f0             	mov    %eax,-0x10(%ebp)

  if (i) {
c0005433:	83 7d f0 00          	cmpl   $0x0,-0x10(%ebp)
c0005437:	74 16                	je     c000544f <itoa+0x4b>
    itoa(i, buf_ptr_addr, base);
c0005439:	0f b6 45 e4          	movzbl -0x1c(%ebp),%eax
c000543d:	83 ec 04             	sub    $0x4,%esp
c0005440:	50                   	push   %eax
c0005441:	ff 75 0c             	push   0xc(%ebp)
c0005444:	ff 75 f0             	push   -0x10(%ebp)
c0005447:	e8 b8 ff ff ff       	call   c0005404 <itoa>
c000544c:	83 c4 10             	add    $0x10,%esp
  }
  if (m < 10) {
c000544f:	83 7d f4 09          	cmpl   $0x9,-0xc(%ebp)
c0005453:	77 19                	ja     c000546e <itoa+0x6a>
    //将数字 0～9 转换为字符'0'～'9'
    *((*buf_ptr_addr)++) = m + '0';
c0005455:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0005458:	8d 58 30             	lea    0x30(%eax),%ebx
c000545b:	8b 45 0c             	mov    0xc(%ebp),%eax
c000545e:	8b 00                	mov    (%eax),%eax
c0005460:	8d 48 01             	lea    0x1(%eax),%ecx
c0005463:	8b 55 0c             	mov    0xc(%ebp),%edx
c0005466:	89 0a                	mov    %ecx,(%edx)
c0005468:	89 da                	mov    %ebx,%edx
c000546a:	88 10                	mov    %dl,(%eax)
  } else {
    //将数字 A～F 转换为字符'A'～'F'
    *((*buf_ptr_addr)++) = m - 10 + 'A';
  }
}
c000546c:	eb 17                	jmp    c0005485 <itoa+0x81>
    *((*buf_ptr_addr)++) = m - 10 + 'A';
c000546e:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0005471:	8d 58 37             	lea    0x37(%eax),%ebx
c0005474:	8b 45 0c             	mov    0xc(%ebp),%eax
c0005477:	8b 00                	mov    (%eax),%eax
c0005479:	8d 48 01             	lea    0x1(%eax),%ecx
c000547c:	8b 55 0c             	mov    0xc(%ebp),%edx
c000547f:	89 0a                	mov    %ecx,(%edx)
c0005481:	89 da                	mov    %ebx,%edx
c0005483:	88 10                	mov    %dl,(%eax)
}
c0005485:	90                   	nop
c0005486:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c0005489:	c9                   	leave  
c000548a:	c3                   	ret    

c000548b <vsprintf>:

// 将参数ap按照格式format输出到字符串str，返回替换后str长度
uint32_t vsprintf(char *str, const char *format, va_list ap) {
c000548b:	55                   	push   %ebp
c000548c:	89 e5                	mov    %esp,%ebp
c000548e:	83 ec 28             	sub    $0x28,%esp
  char *buf_ptr = str;
c0005491:	8b 45 08             	mov    0x8(%ebp),%eax
c0005494:	89 45 e4             	mov    %eax,-0x1c(%ebp)
  const char *index_ptr = format;
c0005497:	8b 45 0c             	mov    0xc(%ebp),%eax
c000549a:	89 45 f4             	mov    %eax,-0xc(%ebp)
  char index_char = *index_ptr; // 指向format中的每个字符
c000549d:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00054a0:	0f b6 00             	movzbl (%eax),%eax
c00054a3:	88 45 f3             	mov    %al,-0xd(%ebp)
  int32_t arg_int;
  char *arg_str;

  while (index_char) {
c00054a6:	e9 45 01 00 00       	jmp    c00055f0 <vsprintf+0x165>
    if (index_char != '%') {
c00054ab:	80 7d f3 25          	cmpb   $0x25,-0xd(%ebp)
c00054af:	74 21                	je     c00054d2 <vsprintf+0x47>
      *(buf_ptr++) = index_char;
c00054b1:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c00054b4:	8d 50 01             	lea    0x1(%eax),%edx
c00054b7:	89 55 e4             	mov    %edx,-0x1c(%ebp)
c00054ba:	0f b6 55 f3          	movzbl -0xd(%ebp),%edx
c00054be:	88 10                	mov    %dl,(%eax)
      index_char = *(++index_ptr);
c00054c0:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
c00054c4:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00054c7:	0f b6 00             	movzbl (%eax),%eax
c00054ca:	88 45 f3             	mov    %al,-0xd(%ebp)
      continue;
c00054cd:	e9 1e 01 00 00       	jmp    c00055f0 <vsprintf+0x165>
    }
    index_char = *(++index_ptr); // 得到%后面的字符
c00054d2:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
c00054d6:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00054d9:	0f b6 00             	movzbl (%eax),%eax
c00054dc:	88 45 f3             	mov    %al,-0xd(%ebp)
    switch (index_char) {
c00054df:	0f be 45 f3          	movsbl -0xd(%ebp),%eax
c00054e3:	83 f8 78             	cmp    $0x78,%eax
c00054e6:	0f 84 d5 00 00 00    	je     c00055c1 <vsprintf+0x136>
c00054ec:	83 f8 78             	cmp    $0x78,%eax
c00054ef:	0f 8f fb 00 00 00    	jg     c00055f0 <vsprintf+0x165>
c00054f5:	83 f8 73             	cmp    $0x73,%eax
c00054f8:	74 18                	je     c0005512 <vsprintf+0x87>
c00054fa:	83 f8 73             	cmp    $0x73,%eax
c00054fd:	0f 8f ed 00 00 00    	jg     c00055f0 <vsprintf+0x165>
c0005503:	83 f8 63             	cmp    $0x63,%eax
c0005506:	74 50                	je     c0005558 <vsprintf+0xcd>
c0005508:	83 f8 64             	cmp    $0x64,%eax
c000550b:	74 6f                	je     c000557c <vsprintf+0xf1>
c000550d:	e9 de 00 00 00       	jmp    c00055f0 <vsprintf+0x165>
    case 's':
      arg_str = va_arg(ap, char *);
c0005512:	83 45 10 04          	addl   $0x4,0x10(%ebp)
c0005516:	8b 45 10             	mov    0x10(%ebp),%eax
c0005519:	8b 00                	mov    (%eax),%eax
c000551b:	89 45 e8             	mov    %eax,-0x18(%ebp)
      strcpy(buf_ptr, arg_str);
c000551e:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0005521:	83 ec 08             	sub    $0x8,%esp
c0005524:	ff 75 e8             	push   -0x18(%ebp)
c0005527:	50                   	push   %eax
c0005528:	e8 b8 cf ff ff       	call   c00024e5 <strcpy>
c000552d:	83 c4 10             	add    $0x10,%esp
      buf_ptr += strlen(arg_str);
c0005530:	83 ec 0c             	sub    $0xc,%esp
c0005533:	ff 75 e8             	push   -0x18(%ebp)
c0005536:	e8 ff cf ff ff       	call   c000253a <strlen>
c000553b:	83 c4 10             	add    $0x10,%esp
c000553e:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c0005541:	01 d0                	add    %edx,%eax
c0005543:	89 45 e4             	mov    %eax,-0x1c(%ebp)
      index_char = *(++index_ptr);
c0005546:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
c000554a:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000554d:	0f b6 00             	movzbl (%eax),%eax
c0005550:	88 45 f3             	mov    %al,-0xd(%ebp)
      break;
c0005553:	e9 98 00 00 00       	jmp    c00055f0 <vsprintf+0x165>

    case 'c':
      *(buf_ptr++) = va_arg(ap, char);
c0005558:	83 45 10 04          	addl   $0x4,0x10(%ebp)
c000555c:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c000555f:	8d 50 01             	lea    0x1(%eax),%edx
c0005562:	89 55 e4             	mov    %edx,-0x1c(%ebp)
c0005565:	8b 55 10             	mov    0x10(%ebp),%edx
c0005568:	0f b6 12             	movzbl (%edx),%edx
c000556b:	88 10                	mov    %dl,(%eax)
      index_char = *(++index_ptr);
c000556d:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
c0005571:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0005574:	0f b6 00             	movzbl (%eax),%eax
c0005577:	88 45 f3             	mov    %al,-0xd(%ebp)
      break;
c000557a:	eb 74                	jmp    c00055f0 <vsprintf+0x165>

    case 'd':
      arg_int = va_arg(ap, int);
c000557c:	83 45 10 04          	addl   $0x4,0x10(%ebp)
c0005580:	8b 45 10             	mov    0x10(%ebp),%eax
c0005583:	8b 00                	mov    (%eax),%eax
c0005585:	89 45 ec             	mov    %eax,-0x14(%ebp)
      if (arg_int < 0) {
c0005588:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c000558c:	79 0f                	jns    c000559d <vsprintf+0x112>
        arg_int = 0 - arg_int;
c000558e:	f7 5d ec             	negl   -0x14(%ebp)
        *buf_ptr++ = '-';
c0005591:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0005594:	8d 50 01             	lea    0x1(%eax),%edx
c0005597:	89 55 e4             	mov    %edx,-0x1c(%ebp)
c000559a:	c6 00 2d             	movb   $0x2d,(%eax)
      }
      itoa(arg_int, &buf_ptr, 10);
c000559d:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00055a0:	83 ec 04             	sub    $0x4,%esp
c00055a3:	6a 0a                	push   $0xa
c00055a5:	8d 55 e4             	lea    -0x1c(%ebp),%edx
c00055a8:	52                   	push   %edx
c00055a9:	50                   	push   %eax
c00055aa:	e8 55 fe ff ff       	call   c0005404 <itoa>
c00055af:	83 c4 10             	add    $0x10,%esp
      index_char = *(++index_ptr);
c00055b2:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
c00055b6:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00055b9:	0f b6 00             	movzbl (%eax),%eax
c00055bc:	88 45 f3             	mov    %al,-0xd(%ebp)
      break;
c00055bf:	eb 2f                	jmp    c00055f0 <vsprintf+0x165>

    case 'x':
      arg_int = va_arg(ap, int);
c00055c1:	83 45 10 04          	addl   $0x4,0x10(%ebp)
c00055c5:	8b 45 10             	mov    0x10(%ebp),%eax
c00055c8:	8b 00                	mov    (%eax),%eax
c00055ca:	89 45 ec             	mov    %eax,-0x14(%ebp)
      itoa(arg_int, &buf_ptr, 16);
c00055cd:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00055d0:	83 ec 04             	sub    $0x4,%esp
c00055d3:	6a 10                	push   $0x10
c00055d5:	8d 55 e4             	lea    -0x1c(%ebp),%edx
c00055d8:	52                   	push   %edx
c00055d9:	50                   	push   %eax
c00055da:	e8 25 fe ff ff       	call   c0005404 <itoa>
c00055df:	83 c4 10             	add    $0x10,%esp
      index_char = *(++index_ptr); // 跳过格式字符并更新index_char
c00055e2:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
c00055e6:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00055e9:	0f b6 00             	movzbl (%eax),%eax
c00055ec:	88 45 f3             	mov    %al,-0xd(%ebp)
      break;
c00055ef:	90                   	nop
  while (index_char) {
c00055f0:	80 7d f3 00          	cmpb   $0x0,-0xd(%ebp)
c00055f4:	0f 85 b1 fe ff ff    	jne    c00054ab <vsprintf+0x20>
    }
  }

  return strlen(str);
c00055fa:	83 ec 0c             	sub    $0xc,%esp
c00055fd:	ff 75 08             	push   0x8(%ebp)
c0005600:	e8 35 cf ff ff       	call   c000253a <strlen>
c0005605:	83 c4 10             	add    $0x10,%esp
}
c0005608:	c9                   	leave  
c0005609:	c3                   	ret    

c000560a <sprintf>:

// sprintf
uint32_t sprintf(char *buf, const char *format, ...) {
c000560a:	55                   	push   %ebp
c000560b:	89 e5                	mov    %esp,%ebp
c000560d:	83 ec 18             	sub    $0x18,%esp
  va_list args;
  uint32_t retval;
  va_start(args, format);
c0005610:	8d 45 0c             	lea    0xc(%ebp),%eax
c0005613:	89 45 f4             	mov    %eax,-0xc(%ebp)
  retval = vsprintf(buf, format, args);
c0005616:	8b 45 0c             	mov    0xc(%ebp),%eax
c0005619:	83 ec 04             	sub    $0x4,%esp
c000561c:	ff 75 f4             	push   -0xc(%ebp)
c000561f:	50                   	push   %eax
c0005620:	ff 75 08             	push   0x8(%ebp)
c0005623:	e8 63 fe ff ff       	call   c000548b <vsprintf>
c0005628:	83 c4 10             	add    $0x10,%esp
c000562b:	89 45 f0             	mov    %eax,-0x10(%ebp)
  va_end(args);
c000562e:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  return retval;
c0005635:	8b 45 f0             	mov    -0x10(%ebp),%eax
}
c0005638:	c9                   	leave  
c0005639:	c3                   	ret    

c000563a <printf>:

// 格式化format
uint32_t printf(const char *format, ...) {
c000563a:	55                   	push   %ebp
c000563b:	89 e5                	mov    %esp,%ebp
c000563d:	57                   	push   %edi
c000563e:	81 ec 14 04 00 00    	sub    $0x414,%esp
  va_list args; // args指向参数
  va_start(args, format);
c0005644:	8d 45 08             	lea    0x8(%ebp),%eax
c0005647:	89 45 f4             	mov    %eax,-0xc(%ebp)
  char buf[1024] = {0}; // 存储拼接后的字符串
c000564a:	c7 85 f4 fb ff ff 00 	movl   $0x0,-0x40c(%ebp)
c0005651:	00 00 00 
c0005654:	8d 95 f8 fb ff ff    	lea    -0x408(%ebp),%edx
c000565a:	b8 00 00 00 00       	mov    $0x0,%eax
c000565f:	b9 ff 00 00 00       	mov    $0xff,%ecx
c0005664:	89 d7                	mov    %edx,%edi
c0005666:	f3 ab                	rep stos %eax,%es:(%edi)
  vsprintf(buf, format, args);
c0005668:	8b 45 08             	mov    0x8(%ebp),%eax
c000566b:	83 ec 04             	sub    $0x4,%esp
c000566e:	ff 75 f4             	push   -0xc(%ebp)
c0005671:	50                   	push   %eax
c0005672:	8d 85 f4 fb ff ff    	lea    -0x40c(%ebp),%eax
c0005678:	50                   	push   %eax
c0005679:	e8 0d fe ff ff       	call   c000548b <vsprintf>
c000567e:	83 c4 10             	add    $0x10,%esp
  va_end(args);
c0005681:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  return write(1, buf, strlen(buf));
c0005688:	83 ec 0c             	sub    $0xc,%esp
c000568b:	8d 85 f4 fb ff ff    	lea    -0x40c(%ebp),%eax
c0005691:	50                   	push   %eax
c0005692:	e8 a3 ce ff ff       	call   c000253a <strlen>
c0005697:	83 c4 10             	add    $0x10,%esp
c000569a:	83 ec 04             	sub    $0x4,%esp
c000569d:	50                   	push   %eax
c000569e:	8d 85 f4 fb ff ff    	lea    -0x40c(%ebp),%eax
c00056a4:	50                   	push   %eax
c00056a5:	6a 01                	push   $0x1
c00056a7:	e8 04 fc ff ff       	call   c00052b0 <write>
c00056ac:	83 c4 10             	add    $0x10,%esp
c00056af:	8b 7d fc             	mov    -0x4(%ebp),%edi
c00056b2:	c9                   	leave  
c00056b3:	c3                   	ret    

c00056b4 <printk>:
// 提供内核的格式化输出
#include "console.h"
#include "global.h"
#include "stdio.h"

void printk(const char *format, ...) {
c00056b4:	55                   	push   %ebp
c00056b5:	89 e5                	mov    %esp,%ebp
c00056b7:	57                   	push   %edi
c00056b8:	81 ec 14 04 00 00    	sub    $0x414,%esp
  va_list args;
  va_start(args, format);
c00056be:	8d 45 08             	lea    0x8(%ebp),%eax
c00056c1:	89 45 f4             	mov    %eax,-0xc(%ebp)
  char buf[1024] = {0};
c00056c4:	c7 85 f4 fb ff ff 00 	movl   $0x0,-0x40c(%ebp)
c00056cb:	00 00 00 
c00056ce:	8d 95 f8 fb ff ff    	lea    -0x408(%ebp),%edx
c00056d4:	b8 00 00 00 00       	mov    $0x0,%eax
c00056d9:	b9 ff 00 00 00       	mov    $0xff,%ecx
c00056de:	89 d7                	mov    %edx,%edi
c00056e0:	f3 ab                	rep stos %eax,%es:(%edi)
  vsprintf(buf, format, args);
c00056e2:	8b 45 08             	mov    0x8(%ebp),%eax
c00056e5:	83 ec 04             	sub    $0x4,%esp
c00056e8:	ff 75 f4             	push   -0xc(%ebp)
c00056eb:	50                   	push   %eax
c00056ec:	8d 85 f4 fb ff ff    	lea    -0x40c(%ebp),%eax
c00056f2:	50                   	push   %eax
c00056f3:	e8 93 fd ff ff       	call   c000548b <vsprintf>
c00056f8:	83 c4 10             	add    $0x10,%esp
  va_end(args);
c00056fb:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  console_put_str(buf);
c0005702:	83 ec 0c             	sub    $0xc,%esp
c0005705:	8d 85 f4 fb ff ff    	lea    -0x40c(%ebp),%eax
c000570b:	50                   	push   %eax
c000570c:	e8 60 f0 ff ff       	call   c0004771 <console_put_str>
c0005711:	83 c4 10             	add    $0x10,%esp
c0005714:	90                   	nop
c0005715:	8b 7d fc             	mov    -0x4(%ebp),%edi
c0005718:	c9                   	leave  
c0005719:	c3                   	ret    

c000571a <outb>:
static inline void outb(uint16_t port, uint8_t data) {
c000571a:	55                   	push   %ebp
c000571b:	89 e5                	mov    %esp,%ebp
c000571d:	83 ec 08             	sub    $0x8,%esp
c0005720:	8b 45 08             	mov    0x8(%ebp),%eax
c0005723:	8b 55 0c             	mov    0xc(%ebp),%edx
c0005726:	66 89 45 fc          	mov    %ax,-0x4(%ebp)
c000572a:	89 d0                	mov    %edx,%eax
c000572c:	88 45 f8             	mov    %al,-0x8(%ebp)
  asm volatile("outb %b0, %w1" ::"a"(data), "Nd"(port));
c000572f:	0f b6 45 f8          	movzbl -0x8(%ebp),%eax
c0005733:	0f b7 55 fc          	movzwl -0x4(%ebp),%edx
c0005737:	ee                   	out    %al,(%dx)
}
c0005738:	90                   	nop
c0005739:	c9                   	leave  
c000573a:	c3                   	ret    

c000573b <outsw>:
static inline void outsw(uint16_t port, const void *addr, uint32_t word_cnt) {
c000573b:	55                   	push   %ebp
c000573c:	89 e5                	mov    %esp,%ebp
c000573e:	56                   	push   %esi
c000573f:	53                   	push   %ebx
c0005740:	83 ec 04             	sub    $0x4,%esp
c0005743:	8b 45 08             	mov    0x8(%ebp),%eax
c0005746:	66 89 45 f4          	mov    %ax,-0xc(%ebp)
  asm volatile("cld; rep outsw" : "+S"(addr), "+c"(word_cnt) : "d"(port));
c000574a:	0f b7 55 f4          	movzwl -0xc(%ebp),%edx
c000574e:	8b 4d 0c             	mov    0xc(%ebp),%ecx
c0005751:	8b 45 10             	mov    0x10(%ebp),%eax
c0005754:	89 cb                	mov    %ecx,%ebx
c0005756:	89 de                	mov    %ebx,%esi
c0005758:	89 c1                	mov    %eax,%ecx
c000575a:	fc                   	cld    
c000575b:	66 f3 6f             	rep outsw %ds:(%esi),(%dx)
c000575e:	89 c8                	mov    %ecx,%eax
c0005760:	89 f3                	mov    %esi,%ebx
c0005762:	89 5d 0c             	mov    %ebx,0xc(%ebp)
c0005765:	89 45 10             	mov    %eax,0x10(%ebp)
}
c0005768:	90                   	nop
c0005769:	83 c4 04             	add    $0x4,%esp
c000576c:	5b                   	pop    %ebx
c000576d:	5e                   	pop    %esi
c000576e:	5d                   	pop    %ebp
c000576f:	c3                   	ret    

c0005770 <inb>:
static inline uint8_t inb(uint16_t port) {
c0005770:	55                   	push   %ebp
c0005771:	89 e5                	mov    %esp,%ebp
c0005773:	83 ec 14             	sub    $0x14,%esp
c0005776:	8b 45 08             	mov    0x8(%ebp),%eax
c0005779:	66 89 45 ec          	mov    %ax,-0x14(%ebp)
  asm volatile("inb %w1, %b0" : "=a"(data) : "Nd"(port));
c000577d:	0f b7 45 ec          	movzwl -0x14(%ebp),%eax
c0005781:	89 c2                	mov    %eax,%edx
c0005783:	ec                   	in     (%dx),%al
c0005784:	88 45 ff             	mov    %al,-0x1(%ebp)
  return data;
c0005787:	0f b6 45 ff          	movzbl -0x1(%ebp),%eax
}
c000578b:	c9                   	leave  
c000578c:	c3                   	ret    

c000578d <insw>:

// 把从端口读的word_cnt个字【2字节为单位】写入addr
static inline void insw(uint16_t port, void *addr, uint32_t word_cnt) {
c000578d:	55                   	push   %ebp
c000578e:	89 e5                	mov    %esp,%ebp
c0005790:	57                   	push   %edi
c0005791:	53                   	push   %ebx
c0005792:	83 ec 04             	sub    $0x4,%esp
c0005795:	8b 45 08             	mov    0x8(%ebp),%eax
c0005798:	66 89 45 f4          	mov    %ax,-0xc(%ebp)
  asm volatile("cld; rep insw"
c000579c:	0f b7 55 f4          	movzwl -0xc(%ebp),%edx
c00057a0:	8b 4d 0c             	mov    0xc(%ebp),%ecx
c00057a3:	8b 45 10             	mov    0x10(%ebp),%eax
c00057a6:	89 cb                	mov    %ecx,%ebx
c00057a8:	89 df                	mov    %ebx,%edi
c00057aa:	89 c1                	mov    %eax,%ecx
c00057ac:	fc                   	cld    
c00057ad:	66 f3 6d             	rep insw (%dx),%es:(%edi)
c00057b0:	89 c8                	mov    %ecx,%eax
c00057b2:	89 fb                	mov    %edi,%ebx
c00057b4:	89 5d 0c             	mov    %ebx,0xc(%ebp)
c00057b7:	89 45 10             	mov    %eax,0x10(%ebp)
               : "+D"(addr), "+c"(word_cnt)
               : "d"(port)
               : "memory");
}
c00057ba:	90                   	nop
c00057bb:	83 c4 04             	add    $0x4,%esp
c00057be:	5b                   	pop    %ebx
c00057bf:	5f                   	pop    %edi
c00057c0:	5d                   	pop    %ebp
c00057c1:	c3                   	ret    

c00057c2 <select_disk>:
  struct partition_table_entry partition_table[4]; // 分区表中有4项，共64字节
  uint16_t signature; // 启动扇区结束标志：0x55,0xaa
} __attribute__((packed));

// 选择读写的硬盘
static void select_disk(struct disk *hd) {
c00057c2:	55                   	push   %ebp
c00057c3:	89 e5                	mov    %esp,%ebp
c00057c5:	83 ec 10             	sub    $0x10,%esp
  uint8_t reg_device = BIT_DEV_MBS | BIT_DEV_LBA;
c00057c8:	c6 45 ff e0          	movb   $0xe0,-0x1(%ebp)
  if (hd->dev_no == 1) { // 若是从盘-> 置dev位为1
c00057cc:	8b 45 08             	mov    0x8(%ebp),%eax
c00057cf:	0f b6 40 0c          	movzbl 0xc(%eax),%eax
c00057d3:	3c 01                	cmp    $0x1,%al
c00057d5:	75 04                	jne    c00057db <select_disk+0x19>
    reg_device |= BIT_DEV_DEV;
c00057d7:	80 4d ff 10          	orb    $0x10,-0x1(%ebp)
  }
  outb(reg_dev(hd->my_channel), reg_device);
c00057db:	0f b6 55 ff          	movzbl -0x1(%ebp),%edx
c00057df:	8b 45 08             	mov    0x8(%ebp),%eax
c00057e2:	8b 40 08             	mov    0x8(%eax),%eax
c00057e5:	0f b7 40 08          	movzwl 0x8(%eax),%eax
c00057e9:	83 c0 06             	add    $0x6,%eax
c00057ec:	0f b7 c0             	movzwl %ax,%eax
c00057ef:	52                   	push   %edx
c00057f0:	50                   	push   %eax
c00057f1:	e8 24 ff ff ff       	call   c000571a <outb>
c00057f6:	83 c4 08             	add    $0x8,%esp
}
c00057f9:	90                   	nop
c00057fa:	c9                   	leave  
c00057fb:	c3                   	ret    

c00057fc <select_sector>:

// 向硬盘控制器写入 起始扇区地址lba 及 读写扇区数sec_cnt
static void select_sector(struct disk *hd, uint32_t lba, uint8_t sec_cnt) {
c00057fc:	55                   	push   %ebp
c00057fd:	89 e5                	mov    %esp,%ebp
c00057ff:	83 ec 28             	sub    $0x28,%esp
c0005802:	8b 45 10             	mov    0x10(%ebp),%eax
c0005805:	88 45 e4             	mov    %al,-0x1c(%ebp)
  ASSERT(lba <= max_lba);
c0005808:	81 7d 0c ff 7f 02 00 	cmpl   $0x27fff,0xc(%ebp)
c000580f:	76 19                	jbe    c000582a <select_sector+0x2e>
c0005811:	68 d4 ce 00 c0       	push   $0xc000ced4
c0005816:	68 64 d0 00 c0       	push   $0xc000d064
c000581b:	6a 57                	push   $0x57
c000581d:	68 e3 ce 00 c0       	push   $0xc000cee3
c0005822:	e8 b1 ca ff ff       	call   c00022d8 <panic_spin>
c0005827:	83 c4 10             	add    $0x10,%esp
  struct ide_channel *channel = hd->my_channel;
c000582a:	8b 45 08             	mov    0x8(%ebp),%eax
c000582d:	8b 40 08             	mov    0x8(%eax),%eax
c0005830:	89 45 f4             	mov    %eax,-0xc(%ebp)

  // 写入要读写扇区数
  outb(reg_sect_cnt(channel), sec_cnt); // 如果sec_cnt=0则表示写入256个扇区
c0005833:	0f b6 55 e4          	movzbl -0x1c(%ebp),%edx
c0005837:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000583a:	0f b7 40 08          	movzwl 0x8(%eax),%eax
c000583e:	83 c0 02             	add    $0x2,%eax
c0005841:	0f b7 c0             	movzwl %ax,%eax
c0005844:	83 ec 08             	sub    $0x8,%esp
c0005847:	52                   	push   %edx
c0005848:	50                   	push   %eax
c0005849:	e8 cc fe ff ff       	call   c000571a <outb>
c000584e:	83 c4 10             	add    $0x10,%esp

  // 写入lba地址，即扇区号
  outb(reg_lba_l(channel), lba);
c0005851:	8b 45 0c             	mov    0xc(%ebp),%eax
c0005854:	0f b6 d0             	movzbl %al,%edx
c0005857:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000585a:	0f b7 40 08          	movzwl 0x8(%eax),%eax
c000585e:	83 c0 03             	add    $0x3,%eax
c0005861:	0f b7 c0             	movzwl %ax,%eax
c0005864:	83 ec 08             	sub    $0x8,%esp
c0005867:	52                   	push   %edx
c0005868:	50                   	push   %eax
c0005869:	e8 ac fe ff ff       	call   c000571a <outb>
c000586e:	83 c4 10             	add    $0x10,%esp
  outb(reg_lba_m(channel), lba >> 8);  // lba地址的8～15位
c0005871:	8b 45 0c             	mov    0xc(%ebp),%eax
c0005874:	c1 e8 08             	shr    $0x8,%eax
c0005877:	0f b6 d0             	movzbl %al,%edx
c000587a:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000587d:	0f b7 40 08          	movzwl 0x8(%eax),%eax
c0005881:	83 c0 04             	add    $0x4,%eax
c0005884:	0f b7 c0             	movzwl %ax,%eax
c0005887:	83 ec 08             	sub    $0x8,%esp
c000588a:	52                   	push   %edx
c000588b:	50                   	push   %eax
c000588c:	e8 89 fe ff ff       	call   c000571a <outb>
c0005891:	83 c4 10             	add    $0x10,%esp
  outb(reg_lba_h(channel), lba >> 16); // lba地址的16～23位
c0005894:	8b 45 0c             	mov    0xc(%ebp),%eax
c0005897:	c1 e8 10             	shr    $0x10,%eax
c000589a:	0f b6 d0             	movzbl %al,%edx
c000589d:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00058a0:	0f b7 40 08          	movzwl 0x8(%eax),%eax
c00058a4:	83 c0 05             	add    $0x5,%eax
c00058a7:	0f b7 c0             	movzwl %ax,%eax
c00058aa:	83 ec 08             	sub    $0x8,%esp
c00058ad:	52                   	push   %edx
c00058ae:	50                   	push   %eax
c00058af:	e8 66 fe ff ff       	call   c000571a <outb>
c00058b4:	83 c4 10             	add    $0x10,%esp

  // lba地址第24～27位存储在device寄存器的0～3位，所以在此处把device寄存器再重新写入一次
  outb(reg_dev(channel), BIT_DEV_MBS | BIT_DEV_LBA |
                             (hd->dev_no == 1 ? BIT_DEV_DEV : 0) | lba >> 24);
c00058b7:	8b 45 08             	mov    0x8(%ebp),%eax
c00058ba:	0f b6 40 0c          	movzbl 0xc(%eax),%eax
c00058be:	3c 01                	cmp    $0x1,%al
c00058c0:	75 07                	jne    c00058c9 <select_sector+0xcd>
c00058c2:	ba f0 ff ff ff       	mov    $0xfffffff0,%edx
c00058c7:	eb 05                	jmp    c00058ce <select_sector+0xd2>
c00058c9:	ba e0 ff ff ff       	mov    $0xffffffe0,%edx
c00058ce:	8b 45 0c             	mov    0xc(%ebp),%eax
c00058d1:	c1 e8 18             	shr    $0x18,%eax
c00058d4:	09 d0                	or     %edx,%eax
  outb(reg_dev(channel), BIT_DEV_MBS | BIT_DEV_LBA |
c00058d6:	0f b6 d0             	movzbl %al,%edx
c00058d9:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00058dc:	0f b7 40 08          	movzwl 0x8(%eax),%eax
c00058e0:	83 c0 06             	add    $0x6,%eax
c00058e3:	0f b7 c0             	movzwl %ax,%eax
c00058e6:	83 ec 08             	sub    $0x8,%esp
c00058e9:	52                   	push   %edx
c00058ea:	50                   	push   %eax
c00058eb:	e8 2a fe ff ff       	call   c000571a <outb>
c00058f0:	83 c4 10             	add    $0x10,%esp
}
c00058f3:	90                   	nop
c00058f4:	c9                   	leave  
c00058f5:	c3                   	ret    

c00058f6 <cmd_out>:

// 向channel发命令cmd
static void cmd_out(struct ide_channel *channel, uint8_t cmd) {
c00058f6:	55                   	push   %ebp
c00058f7:	89 e5                	mov    %esp,%ebp
c00058f9:	83 ec 04             	sub    $0x4,%esp
c00058fc:	8b 45 0c             	mov    0xc(%ebp),%eax
c00058ff:	88 45 fc             	mov    %al,-0x4(%ebp)
  channel->expecting_intr =
c0005902:	8b 45 08             	mov    0x8(%ebp),%eax
c0005905:	c7 40 28 01 00 00 00 	movl   $0x1,0x28(%eax)
      true; // 向硬盘发命令便将此标置为true，硬盘中断处理程序根据它来判断
  outb(reg_cmd(channel), cmd);
c000590c:	0f b6 55 fc          	movzbl -0x4(%ebp),%edx
c0005910:	8b 45 08             	mov    0x8(%ebp),%eax
c0005913:	0f b7 40 08          	movzwl 0x8(%eax),%eax
c0005917:	83 c0 07             	add    $0x7,%eax
c000591a:	0f b7 c0             	movzwl %ax,%eax
c000591d:	52                   	push   %edx
c000591e:	50                   	push   %eax
c000591f:	e8 f6 fd ff ff       	call   c000571a <outb>
c0005924:	83 c4 08             	add    $0x8,%esp
}
c0005927:	90                   	nop
c0005928:	c9                   	leave  
c0005929:	c3                   	ret    

c000592a <read_from_sector>:

// 硬盘读入sec_cnt个扇区的数据到buf
static void read_from_sector(struct disk *hd, void *buf, uint8_t sec_cnt) {
c000592a:	55                   	push   %ebp
c000592b:	89 e5                	mov    %esp,%ebp
c000592d:	83 ec 14             	sub    $0x14,%esp
c0005930:	8b 45 10             	mov    0x10(%ebp),%eax
c0005933:	88 45 ec             	mov    %al,-0x14(%ebp)
  uint32_t size_in_byte;
  // 扇区数转字节
  if (sec_cnt == 0) {
c0005936:	80 7d ec 00          	cmpb   $0x0,-0x14(%ebp)
c000593a:	75 09                	jne    c0005945 <read_from_sector+0x1b>
    size_in_byte = 256 * 512; // sec_cnt=0表示256个扇区
c000593c:	c7 45 fc 00 00 02 00 	movl   $0x20000,-0x4(%ebp)
c0005943:	eb 0a                	jmp    c000594f <read_from_sector+0x25>
  } else {
    size_in_byte = sec_cnt * 512;
c0005945:	0f b6 45 ec          	movzbl -0x14(%ebp),%eax
c0005949:	c1 e0 09             	shl    $0x9,%eax
c000594c:	89 45 fc             	mov    %eax,-0x4(%ebp)
  }
  insw(reg_data(hd->my_channel), buf, size_in_byte / 2);
c000594f:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0005952:	d1 e8                	shr    %eax
c0005954:	89 c2                	mov    %eax,%edx
c0005956:	8b 45 08             	mov    0x8(%ebp),%eax
c0005959:	8b 40 08             	mov    0x8(%eax),%eax
c000595c:	0f b7 40 08          	movzwl 0x8(%eax),%eax
c0005960:	0f b7 c0             	movzwl %ax,%eax
c0005963:	52                   	push   %edx
c0005964:	ff 75 0c             	push   0xc(%ebp)
c0005967:	50                   	push   %eax
c0005968:	e8 20 fe ff ff       	call   c000578d <insw>
c000596d:	83 c4 0c             	add    $0xc,%esp
}
c0005970:	90                   	nop
c0005971:	c9                   	leave  
c0005972:	c3                   	ret    

c0005973 <write2sector>:

// 将buf中sec_cnt扇区的数据写入硬盘
static void write2sector(struct disk *hd, void *buf, uint8_t sec_cnt) {
c0005973:	55                   	push   %ebp
c0005974:	89 e5                	mov    %esp,%ebp
c0005976:	83 ec 14             	sub    $0x14,%esp
c0005979:	8b 45 10             	mov    0x10(%ebp),%eax
c000597c:	88 45 ec             	mov    %al,-0x14(%ebp)
  uint32_t size_in_byte;
  if (sec_cnt == 0) {
c000597f:	80 7d ec 00          	cmpb   $0x0,-0x14(%ebp)
c0005983:	75 09                	jne    c000598e <write2sector+0x1b>
    size_in_byte = 256 * 512;
c0005985:	c7 45 fc 00 00 02 00 	movl   $0x20000,-0x4(%ebp)
c000598c:	eb 0a                	jmp    c0005998 <write2sector+0x25>
  } else {
    size_in_byte = sec_cnt * 512;
c000598e:	0f b6 45 ec          	movzbl -0x14(%ebp),%eax
c0005992:	c1 e0 09             	shl    $0x9,%eax
c0005995:	89 45 fc             	mov    %eax,-0x4(%ebp)
  }
  outsw(reg_data(hd->my_channel), buf, size_in_byte / 2);
c0005998:	8b 45 fc             	mov    -0x4(%ebp),%eax
c000599b:	d1 e8                	shr    %eax
c000599d:	89 c2                	mov    %eax,%edx
c000599f:	8b 45 08             	mov    0x8(%ebp),%eax
c00059a2:	8b 40 08             	mov    0x8(%eax),%eax
c00059a5:	0f b7 40 08          	movzwl 0x8(%eax),%eax
c00059a9:	0f b7 c0             	movzwl %ax,%eax
c00059ac:	52                   	push   %edx
c00059ad:	ff 75 0c             	push   0xc(%ebp)
c00059b0:	50                   	push   %eax
c00059b1:	e8 85 fd ff ff       	call   c000573b <outsw>
c00059b6:	83 c4 0c             	add    $0xc,%esp
}
c00059b9:	90                   	nop
c00059ba:	c9                   	leave  
c00059bb:	c3                   	ret    

c00059bc <busy_wait>:

// 等待硬盘30s（驱动程序让出CPU使用权使其他任务得到调度
static bool busy_wait(struct disk *hd) {
c00059bc:	55                   	push   %ebp
c00059bd:	89 e5                	mov    %esp,%ebp
c00059bf:	83 ec 18             	sub    $0x18,%esp
  struct ide_channel *channel = hd->my_channel;
c00059c2:	8b 45 08             	mov    0x8(%ebp),%eax
c00059c5:	8b 40 08             	mov    0x8(%eax),%eax
c00059c8:	89 45 f0             	mov    %eax,-0x10(%ebp)
  uint16_t time_limit = 30 * 1000;
c00059cb:	66 c7 45 f6 30 75    	movw   $0x7530,-0xa(%ebp)

  while (time_limit -= 10 >= 0) {
c00059d1:	eb 45                	jmp    c0005a18 <busy_wait+0x5c>
    // 判断status寄存器BSY位是否为1
    if (!(inb(reg_status(channel)) & BIT_ALT_STAT_BSY)) {
c00059d3:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00059d6:	0f b7 40 08          	movzwl 0x8(%eax),%eax
c00059da:	83 c0 07             	add    $0x7,%eax
c00059dd:	0f b7 c0             	movzwl %ax,%eax
c00059e0:	50                   	push   %eax
c00059e1:	e8 8a fd ff ff       	call   c0005770 <inb>
c00059e6:	83 c4 04             	add    $0x4,%esp
c00059e9:	84 c0                	test   %al,%al
c00059eb:	78 1e                	js     c0005a0b <busy_wait+0x4f>
      // DRQ=1 硬盘已准备好数据
      return (inb(reg_status(channel)) & BIT_ALT_STAT_DRQ);
c00059ed:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00059f0:	0f b7 40 08          	movzwl 0x8(%eax),%eax
c00059f4:	83 c0 07             	add    $0x7,%eax
c00059f7:	0f b7 c0             	movzwl %ax,%eax
c00059fa:	50                   	push   %eax
c00059fb:	e8 70 fd ff ff       	call   c0005770 <inb>
c0005a00:	83 c4 04             	add    $0x4,%esp
c0005a03:	0f b6 c0             	movzbl %al,%eax
c0005a06:	83 e0 08             	and    $0x8,%eax
c0005a09:	eb 1e                	jmp    c0005a29 <busy_wait+0x6d>
    } else {
      mtime_sleep(10); // 硬盘繁忙，睡10ms（忙等
c0005a0b:	83 ec 0c             	sub    $0xc,%esp
c0005a0e:	6a 0a                	push   $0xa
c0005a10:	e8 78 c8 ff ff       	call   c000228d <mtime_sleep>
c0005a15:	83 c4 10             	add    $0x10,%esp
  while (time_limit -= 10 >= 0) {
c0005a18:	66 83 6d f6 01       	subw   $0x1,-0xa(%ebp)
c0005a1d:	66 83 7d f6 00       	cmpw   $0x0,-0xa(%ebp)
c0005a22:	75 af                	jne    c00059d3 <busy_wait+0x17>
    }
  }
  return false;
c0005a24:	b8 00 00 00 00       	mov    $0x0,%eax
}
c0005a29:	c9                   	leave  
c0005a2a:	c3                   	ret    

c0005a2b <ide_read>:

// 从硬盘读sec_cnt个扇区到buf
void ide_read(struct disk *hd, uint32_t lba, void *buf, uint32_t sec_cnt) {
c0005a2b:	55                   	push   %ebp
c0005a2c:	89 e5                	mov    %esp,%ebp
c0005a2e:	83 ec 58             	sub    $0x58,%esp
  ASSERT(lba <= max_lba);
c0005a31:	81 7d 0c ff 7f 02 00 	cmpl   $0x27fff,0xc(%ebp)
c0005a38:	76 1c                	jbe    c0005a56 <ide_read+0x2b>
c0005a3a:	68 d4 ce 00 c0       	push   $0xc000ced4
c0005a3f:	68 74 d0 00 c0       	push   $0xc000d074
c0005a44:	68 98 00 00 00       	push   $0x98
c0005a49:	68 e3 ce 00 c0       	push   $0xc000cee3
c0005a4e:	e8 85 c8 ff ff       	call   c00022d8 <panic_spin>
c0005a53:	83 c4 10             	add    $0x10,%esp
  ASSERT(sec_cnt > 0);
c0005a56:	83 7d 14 00          	cmpl   $0x0,0x14(%ebp)
c0005a5a:	75 1c                	jne    c0005a78 <ide_read+0x4d>
c0005a5c:	68 f0 ce 00 c0       	push   $0xc000cef0
c0005a61:	68 74 d0 00 c0       	push   $0xc000d074
c0005a66:	68 99 00 00 00       	push   $0x99
c0005a6b:	68 e3 ce 00 c0       	push   $0xc000cee3
c0005a70:	e8 63 c8 ff ff       	call   c00022d8 <panic_spin>
c0005a75:	83 c4 10             	add    $0x10,%esp
  lock_acquire(&hd->my_channel->lock);
c0005a78:	8b 45 08             	mov    0x8(%ebp),%eax
c0005a7b:	8b 40 08             	mov    0x8(%eax),%eax
c0005a7e:	83 c0 0c             	add    $0xc,%eax
c0005a81:	83 ec 0c             	sub    $0xc,%esp
c0005a84:	50                   	push   %eax
c0005a85:	e8 8f eb ff ff       	call   c0004619 <lock_acquire>
c0005a8a:	83 c4 10             	add    $0x10,%esp

  // 1、选择操作的硬盘
  select_disk(hd);
c0005a8d:	83 ec 0c             	sub    $0xc,%esp
c0005a90:	ff 75 08             	push   0x8(%ebp)
c0005a93:	e8 2a fd ff ff       	call   c00057c2 <select_disk>
c0005a98:	83 c4 10             	add    $0x10,%esp
  uint32_t secs_op;       // 每次操作的扇区数（<=256）
  uint32_t secs_done = 0; // 已完成的扇区数
c0005a9b:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
  while (secs_done < sec_cnt) {
c0005aa2:	e9 d4 00 00 00       	jmp    c0005b7b <ide_read+0x150>
    if ((secs_done + 256) <= sec_cnt) {
c0005aa7:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0005aaa:	05 00 01 00 00       	add    $0x100,%eax
c0005aaf:	39 45 14             	cmp    %eax,0x14(%ebp)
c0005ab2:	72 09                	jb     c0005abd <ide_read+0x92>
      secs_op = 256;
c0005ab4:	c7 45 f4 00 01 00 00 	movl   $0x100,-0xc(%ebp)
c0005abb:	eb 09                	jmp    c0005ac6 <ide_read+0x9b>
    } else {
      secs_op = sec_cnt - secs_done;
c0005abd:	8b 45 14             	mov    0x14(%ebp),%eax
c0005ac0:	2b 45 f0             	sub    -0x10(%ebp),%eax
c0005ac3:	89 45 f4             	mov    %eax,-0xc(%ebp)
    }
    // 2、写入待读入的扇区数和起始扇区号
    select_sector(hd, lba + secs_done, secs_op);
c0005ac6:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0005ac9:	0f b6 c0             	movzbl %al,%eax
c0005acc:	8b 4d 0c             	mov    0xc(%ebp),%ecx
c0005acf:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0005ad2:	01 ca                	add    %ecx,%edx
c0005ad4:	83 ec 04             	sub    $0x4,%esp
c0005ad7:	50                   	push   %eax
c0005ad8:	52                   	push   %edx
c0005ad9:	ff 75 08             	push   0x8(%ebp)
c0005adc:	e8 1b fd ff ff       	call   c00057fc <select_sector>
c0005ae1:	83 c4 10             	add    $0x10,%esp
    // 3、向硬盘发读扇区命令
    cmd_out(hd->my_channel, CMD_READ_SECTOR);
c0005ae4:	8b 45 08             	mov    0x8(%ebp),%eax
c0005ae7:	8b 40 08             	mov    0x8(%eax),%eax
c0005aea:	83 ec 08             	sub    $0x8,%esp
c0005aed:	6a 20                	push   $0x20
c0005aef:	50                   	push   %eax
c0005af0:	e8 01 fe ff ff       	call   c00058f6 <cmd_out>
c0005af5:	83 c4 10             	add    $0x10,%esp

    /* 硬盘开始工作（开始在内部读数据或写数据）后阻塞自己，等硬盘完成读操作后通过中断处理程序唤醒自己*/
    sema_down(&hd->my_channel->disk_done);
c0005af8:	8b 45 08             	mov    0x8(%ebp),%eax
c0005afb:	8b 40 08             	mov    0x8(%eax),%eax
c0005afe:	83 c0 2c             	add    $0x2c,%eax
c0005b01:	83 ec 0c             	sub    $0xc,%esp
c0005b04:	50                   	push   %eax
c0005b05:	e8 65 e9 ff ff       	call   c000446f <sema_down>
c0005b0a:	83 c4 10             	add    $0x10,%esp

    // 【醒后执行】4、检测硬盘状态是否可读
    if (!busy_wait(hd)) { // 失败
c0005b0d:	83 ec 0c             	sub    $0xc,%esp
c0005b10:	ff 75 08             	push   0x8(%ebp)
c0005b13:	e8 a4 fe ff ff       	call   c00059bc <busy_wait>
c0005b18:	83 c4 10             	add    $0x10,%esp
c0005b1b:	85 c0                	test   %eax,%eax
c0005b1d:	75 33                	jne    c0005b52 <ide_read+0x127>
      char error[64];
      sprintf(error, "%s read sector %d failed!!!!!!\n", hd->name, lba);
c0005b1f:	8b 45 08             	mov    0x8(%ebp),%eax
c0005b22:	ff 75 0c             	push   0xc(%ebp)
c0005b25:	50                   	push   %eax
c0005b26:	68 fc ce 00 c0       	push   $0xc000cefc
c0005b2b:	8d 45 b0             	lea    -0x50(%ebp),%eax
c0005b2e:	50                   	push   %eax
c0005b2f:	e8 d6 fa ff ff       	call   c000560a <sprintf>
c0005b34:	83 c4 10             	add    $0x10,%esp
      PANIC(error);
c0005b37:	8d 45 b0             	lea    -0x50(%ebp),%eax
c0005b3a:	50                   	push   %eax
c0005b3b:	68 74 d0 00 c0       	push   $0xc000d074
c0005b40:	68 b2 00 00 00       	push   $0xb2
c0005b45:	68 e3 ce 00 c0       	push   $0xc000cee3
c0005b4a:	e8 89 c7 ff ff       	call   c00022d8 <panic_spin>
c0005b4f:	83 c4 10             	add    $0x10,%esp
    }

    // 5、将扇区数据读入到缓冲区(buf+secs_done*512)处
    read_from_sector(hd, (void *)((uint32_t)buf + secs_done * 512), secs_op);
c0005b52:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0005b55:	0f b6 c0             	movzbl %al,%eax
c0005b58:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0005b5b:	89 d1                	mov    %edx,%ecx
c0005b5d:	c1 e1 09             	shl    $0x9,%ecx
c0005b60:	8b 55 10             	mov    0x10(%ebp),%edx
c0005b63:	01 ca                	add    %ecx,%edx
c0005b65:	83 ec 04             	sub    $0x4,%esp
c0005b68:	50                   	push   %eax
c0005b69:	52                   	push   %edx
c0005b6a:	ff 75 08             	push   0x8(%ebp)
c0005b6d:	e8 b8 fd ff ff       	call   c000592a <read_from_sector>
c0005b72:	83 c4 10             	add    $0x10,%esp
    secs_done += secs_op;
c0005b75:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0005b78:	01 45 f0             	add    %eax,-0x10(%ebp)
  while (secs_done < sec_cnt) {
c0005b7b:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0005b7e:	3b 45 14             	cmp    0x14(%ebp),%eax
c0005b81:	0f 82 20 ff ff ff    	jb     c0005aa7 <ide_read+0x7c>
  }
  lock_release(&hd->my_channel->lock);
c0005b87:	8b 45 08             	mov    0x8(%ebp),%eax
c0005b8a:	8b 40 08             	mov    0x8(%eax),%eax
c0005b8d:	83 c0 0c             	add    $0xc,%eax
c0005b90:	83 ec 0c             	sub    $0xc,%esp
c0005b93:	50                   	push   %eax
c0005b94:	e8 f5 ea ff ff       	call   c000468e <lock_release>
c0005b99:	83 c4 10             	add    $0x10,%esp
}
c0005b9c:	90                   	nop
c0005b9d:	c9                   	leave  
c0005b9e:	c3                   	ret    

c0005b9f <ide_write>:

// 将buf中sec_cnt扇区数据写入硬盘
void ide_write(struct disk *hd, uint32_t lba, void *buf, uint32_t sec_cnt) {
c0005b9f:	55                   	push   %ebp
c0005ba0:	89 e5                	mov    %esp,%ebp
c0005ba2:	83 ec 58             	sub    $0x58,%esp
  ASSERT(lba <= max_lba);
c0005ba5:	81 7d 0c ff 7f 02 00 	cmpl   $0x27fff,0xc(%ebp)
c0005bac:	76 1c                	jbe    c0005bca <ide_write+0x2b>
c0005bae:	68 d4 ce 00 c0       	push   $0xc000ced4
c0005bb3:	68 80 d0 00 c0       	push   $0xc000d080
c0005bb8:	68 be 00 00 00       	push   $0xbe
c0005bbd:	68 e3 ce 00 c0       	push   $0xc000cee3
c0005bc2:	e8 11 c7 ff ff       	call   c00022d8 <panic_spin>
c0005bc7:	83 c4 10             	add    $0x10,%esp
  ASSERT(sec_cnt > 0);
c0005bca:	83 7d 14 00          	cmpl   $0x0,0x14(%ebp)
c0005bce:	75 1c                	jne    c0005bec <ide_write+0x4d>
c0005bd0:	68 f0 ce 00 c0       	push   $0xc000cef0
c0005bd5:	68 80 d0 00 c0       	push   $0xc000d080
c0005bda:	68 bf 00 00 00       	push   $0xbf
c0005bdf:	68 e3 ce 00 c0       	push   $0xc000cee3
c0005be4:	e8 ef c6 ff ff       	call   c00022d8 <panic_spin>
c0005be9:	83 c4 10             	add    $0x10,%esp
  lock_acquire(&hd->my_channel->lock);
c0005bec:	8b 45 08             	mov    0x8(%ebp),%eax
c0005bef:	8b 40 08             	mov    0x8(%eax),%eax
c0005bf2:	83 c0 0c             	add    $0xc,%eax
c0005bf5:	83 ec 0c             	sub    $0xc,%esp
c0005bf8:	50                   	push   %eax
c0005bf9:	e8 1b ea ff ff       	call   c0004619 <lock_acquire>
c0005bfe:	83 c4 10             	add    $0x10,%esp

  select_disk(hd);
c0005c01:	83 ec 0c             	sub    $0xc,%esp
c0005c04:	ff 75 08             	push   0x8(%ebp)
c0005c07:	e8 b6 fb ff ff       	call   c00057c2 <select_disk>
c0005c0c:	83 c4 10             	add    $0x10,%esp
  uint32_t secs_op;
  uint32_t secs_done = 0;
c0005c0f:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
  while (secs_done < sec_cnt) {
c0005c16:	e9 d4 00 00 00       	jmp    c0005cef <ide_write+0x150>
    if ((secs_done + 256) <= sec_cnt) {
c0005c1b:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0005c1e:	05 00 01 00 00       	add    $0x100,%eax
c0005c23:	39 45 14             	cmp    %eax,0x14(%ebp)
c0005c26:	72 09                	jb     c0005c31 <ide_write+0x92>
      secs_op = 256;
c0005c28:	c7 45 f4 00 01 00 00 	movl   $0x100,-0xc(%ebp)
c0005c2f:	eb 09                	jmp    c0005c3a <ide_write+0x9b>
    } else {
      secs_op = sec_cnt - secs_done;
c0005c31:	8b 45 14             	mov    0x14(%ebp),%eax
c0005c34:	2b 45 f0             	sub    -0x10(%ebp),%eax
c0005c37:	89 45 f4             	mov    %eax,-0xc(%ebp)
    }
    select_sector(hd, lba + secs_done, secs_op);
c0005c3a:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0005c3d:	0f b6 c0             	movzbl %al,%eax
c0005c40:	8b 4d 0c             	mov    0xc(%ebp),%ecx
c0005c43:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0005c46:	01 ca                	add    %ecx,%edx
c0005c48:	83 ec 04             	sub    $0x4,%esp
c0005c4b:	50                   	push   %eax
c0005c4c:	52                   	push   %edx
c0005c4d:	ff 75 08             	push   0x8(%ebp)
c0005c50:	e8 a7 fb ff ff       	call   c00057fc <select_sector>
c0005c55:	83 c4 10             	add    $0x10,%esp
    cmd_out(hd->my_channel, CMD_WRITE_SECTOR);
c0005c58:	8b 45 08             	mov    0x8(%ebp),%eax
c0005c5b:	8b 40 08             	mov    0x8(%eax),%eax
c0005c5e:	83 ec 08             	sub    $0x8,%esp
c0005c61:	6a 30                	push   $0x30
c0005c63:	50                   	push   %eax
c0005c64:	e8 8d fc ff ff       	call   c00058f6 <cmd_out>
c0005c69:	83 c4 10             	add    $0x10,%esp

    if (!busy_wait(hd)) {
c0005c6c:	83 ec 0c             	sub    $0xc,%esp
c0005c6f:	ff 75 08             	push   0x8(%ebp)
c0005c72:	e8 45 fd ff ff       	call   c00059bc <busy_wait>
c0005c77:	83 c4 10             	add    $0x10,%esp
c0005c7a:	85 c0                	test   %eax,%eax
c0005c7c:	75 33                	jne    c0005cb1 <ide_write+0x112>
      char error[64];
      sprintf(error, "%s write sector %d failed!!!!!!\n", hd->name, lba);
c0005c7e:	8b 45 08             	mov    0x8(%ebp),%eax
c0005c81:	ff 75 0c             	push   0xc(%ebp)
c0005c84:	50                   	push   %eax
c0005c85:	68 1c cf 00 c0       	push   $0xc000cf1c
c0005c8a:	8d 45 b0             	lea    -0x50(%ebp),%eax
c0005c8d:	50                   	push   %eax
c0005c8e:	e8 77 f9 ff ff       	call   c000560a <sprintf>
c0005c93:	83 c4 10             	add    $0x10,%esp
      PANIC(error);
c0005c96:	8d 45 b0             	lea    -0x50(%ebp),%eax
c0005c99:	50                   	push   %eax
c0005c9a:	68 80 d0 00 c0       	push   $0xc000d080
c0005c9f:	68 d1 00 00 00       	push   $0xd1
c0005ca4:	68 e3 ce 00 c0       	push   $0xc000cee3
c0005ca9:	e8 2a c6 ff ff       	call   c00022d8 <panic_spin>
c0005cae:	83 c4 10             	add    $0x10,%esp
    }

    // 将数据写入硬盘
    write2sector(hd, (void *)((uint32_t)buf + secs_done * 512), secs_op);
c0005cb1:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0005cb4:	0f b6 c0             	movzbl %al,%eax
c0005cb7:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0005cba:	89 d1                	mov    %edx,%ecx
c0005cbc:	c1 e1 09             	shl    $0x9,%ecx
c0005cbf:	8b 55 10             	mov    0x10(%ebp),%edx
c0005cc2:	01 ca                	add    %ecx,%edx
c0005cc4:	83 ec 04             	sub    $0x4,%esp
c0005cc7:	50                   	push   %eax
c0005cc8:	52                   	push   %edx
c0005cc9:	ff 75 08             	push   0x8(%ebp)
c0005ccc:	e8 a2 fc ff ff       	call   c0005973 <write2sector>
c0005cd1:	83 c4 10             	add    $0x10,%esp
    /* 在硬盘响应期间阻塞自己 */
    sema_down(&hd->my_channel->disk_done);
c0005cd4:	8b 45 08             	mov    0x8(%ebp),%eax
c0005cd7:	8b 40 08             	mov    0x8(%eax),%eax
c0005cda:	83 c0 2c             	add    $0x2c,%eax
c0005cdd:	83 ec 0c             	sub    $0xc,%esp
c0005ce0:	50                   	push   %eax
c0005ce1:	e8 89 e7 ff ff       	call   c000446f <sema_down>
c0005ce6:	83 c4 10             	add    $0x10,%esp
    secs_done += secs_op;
c0005ce9:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0005cec:	01 45 f0             	add    %eax,-0x10(%ebp)
  while (secs_done < sec_cnt) {
c0005cef:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0005cf2:	3b 45 14             	cmp    0x14(%ebp),%eax
c0005cf5:	0f 82 20 ff ff ff    	jb     c0005c1b <ide_write+0x7c>
  }
  // 【醒后执行】开始释放锁
  lock_release(&hd->my_channel->lock);
c0005cfb:	8b 45 08             	mov    0x8(%ebp),%eax
c0005cfe:	8b 40 08             	mov    0x8(%eax),%eax
c0005d01:	83 c0 0c             	add    $0xc,%eax
c0005d04:	83 ec 0c             	sub    $0xc,%esp
c0005d07:	50                   	push   %eax
c0005d08:	e8 81 e9 ff ff       	call   c000468e <lock_release>
c0005d0d:	83 c4 10             	add    $0x10,%esp
}
c0005d10:	90                   	nop
c0005d11:	c9                   	leave  
c0005d12:	c3                   	ret    

c0005d13 <intr_hd_handler>:

// 硬盘中断处理程序
void intr_hd_handler(uint8_t irq_no) {
c0005d13:	55                   	push   %ebp
c0005d14:	89 e5                	mov    %esp,%ebp
c0005d16:	83 ec 28             	sub    $0x28,%esp
c0005d19:	8b 45 08             	mov    0x8(%ebp),%eax
c0005d1c:	88 45 e4             	mov    %al,-0x1c(%ebp)
  ASSERT(irq_no == 0x2e || irq_no == 0x2f); // irq_no中断号
c0005d1f:	80 7d e4 2e          	cmpb   $0x2e,-0x1c(%ebp)
c0005d23:	74 22                	je     c0005d47 <intr_hd_handler+0x34>
c0005d25:	80 7d e4 2f          	cmpb   $0x2f,-0x1c(%ebp)
c0005d29:	74 1c                	je     c0005d47 <intr_hd_handler+0x34>
c0005d2b:	68 40 cf 00 c0       	push   $0xc000cf40
c0005d30:	68 8c d0 00 c0       	push   $0xc000d08c
c0005d35:	68 e0 00 00 00       	push   $0xe0
c0005d3a:	68 e3 ce 00 c0       	push   $0xc000cee3
c0005d3f:	e8 94 c5 ff ff       	call   c00022d8 <panic_spin>
c0005d44:	83 c4 10             	add    $0x10,%esp
  uint8_t ch_no = irq_no - 0x2e;
c0005d47:	0f b6 45 e4          	movzbl -0x1c(%ebp),%eax
c0005d4b:	83 e8 2e             	sub    $0x2e,%eax
c0005d4e:	88 45 f7             	mov    %al,-0x9(%ebp)
  struct ide_channel *channel = &channels[ch_no];
c0005d51:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0005d55:	69 c0 60 06 00 00    	imul   $0x660,%eax,%eax
c0005d5b:	05 00 1d 01 c0       	add    $0xc0011d00,%eax
c0005d60:	89 45 f0             	mov    %eax,-0x10(%ebp)
  ASSERT(channel->irq_no == irq_no);
c0005d63:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0005d66:	0f b6 40 0a          	movzbl 0xa(%eax),%eax
c0005d6a:	38 45 e4             	cmp    %al,-0x1c(%ebp)
c0005d6d:	74 1c                	je     c0005d8b <intr_hd_handler+0x78>
c0005d6f:	68 61 cf 00 c0       	push   $0xc000cf61
c0005d74:	68 8c d0 00 c0       	push   $0xc000d08c
c0005d79:	68 e3 00 00 00       	push   $0xe3
c0005d7e:	68 e3 ce 00 c0       	push   $0xc000cee3
c0005d83:	e8 50 c5 ff ff       	call   c00022d8 <panic_spin>
c0005d88:	83 c4 10             	add    $0x10,%esp

  // 锁的存在保证了expecting_intr和中断的一一对应
  if (channel->expecting_intr) {
c0005d8b:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0005d8e:	8b 40 28             	mov    0x28(%eax),%eax
c0005d91:	85 c0                	test   %eax,%eax
c0005d93:	74 35                	je     c0005dca <intr_hd_handler+0xb7>
    channel->expecting_intr = false;
c0005d95:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0005d98:	c7 40 28 00 00 00 00 	movl   $0x0,0x28(%eax)
    sema_up(&channel->disk_done);
c0005d9f:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0005da2:	83 c0 2c             	add    $0x2c,%eax
c0005da5:	83 ec 0c             	sub    $0xc,%esp
c0005da8:	50                   	push   %eax
c0005da9:	e8 bc e7 ff ff       	call   c000456a <sema_up>
c0005dae:	83 c4 10             	add    $0x10,%esp
    inb(reg_status(
c0005db1:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0005db4:	0f b7 40 08          	movzwl 0x8(%eax),%eax
c0005db8:	83 c0 07             	add    $0x7,%eax
c0005dbb:	0f b7 c0             	movzwl %ax,%eax
c0005dbe:	83 ec 0c             	sub    $0xc,%esp
c0005dc1:	50                   	push   %eax
c0005dc2:	e8 a9 f9 ff ff       	call   c0005770 <inb>
c0005dc7:	83 c4 10             	add    $0x10,%esp
        channel)); // 读取状态寄存器后硬盘中断被处理，硬盘可继续执行新读写
  }
}
c0005dca:	90                   	nop
c0005dcb:	c9                   	leave  
c0005dcc:	c3                   	ret    

c0005dcd <swap_pairs_bytes>:

// 将dst中len个相邻字节交换位置后存入buf（处理identify命令的返回信息
static void swap_pairs_bytes(const char *dst, char *buf, uint32_t len) {
c0005dcd:	55                   	push   %ebp
c0005dce:	89 e5                	mov    %esp,%ebp
c0005dd0:	83 ec 10             	sub    $0x10,%esp
  uint8_t idx;
  for (idx = 0; idx < len; idx += 2) {
c0005dd3:	c6 45 ff 00          	movb   $0x0,-0x1(%ebp)
c0005dd7:	eb 35                	jmp    c0005e0e <swap_pairs_bytes+0x41>
    // buf中存储dst中两相邻元素交换位置后的字符串
    buf[idx + 1] = *dst++;
c0005dd9:	8b 45 08             	mov    0x8(%ebp),%eax
c0005ddc:	8d 50 01             	lea    0x1(%eax),%edx
c0005ddf:	89 55 08             	mov    %edx,0x8(%ebp)
c0005de2:	0f b6 55 ff          	movzbl -0x1(%ebp),%edx
c0005de6:	8d 4a 01             	lea    0x1(%edx),%ecx
c0005de9:	8b 55 0c             	mov    0xc(%ebp),%edx
c0005dec:	01 ca                	add    %ecx,%edx
c0005dee:	0f b6 00             	movzbl (%eax),%eax
c0005df1:	88 02                	mov    %al,(%edx)
    buf[idx] = *dst++;
c0005df3:	8b 45 08             	mov    0x8(%ebp),%eax
c0005df6:	8d 50 01             	lea    0x1(%eax),%edx
c0005df9:	89 55 08             	mov    %edx,0x8(%ebp)
c0005dfc:	0f b6 4d ff          	movzbl -0x1(%ebp),%ecx
c0005e00:	8b 55 0c             	mov    0xc(%ebp),%edx
c0005e03:	01 ca                	add    %ecx,%edx
c0005e05:	0f b6 00             	movzbl (%eax),%eax
c0005e08:	88 02                	mov    %al,(%edx)
  for (idx = 0; idx < len; idx += 2) {
c0005e0a:	80 45 ff 02          	addb   $0x2,-0x1(%ebp)
c0005e0e:	0f b6 45 ff          	movzbl -0x1(%ebp),%eax
c0005e12:	39 45 10             	cmp    %eax,0x10(%ebp)
c0005e15:	77 c2                	ja     c0005dd9 <swap_pairs_bytes+0xc>
  }
  buf[idx] = '\0';
c0005e17:	0f b6 55 ff          	movzbl -0x1(%ebp),%edx
c0005e1b:	8b 45 0c             	mov    0xc(%ebp),%eax
c0005e1e:	01 d0                	add    %edx,%eax
c0005e20:	c6 00 00             	movb   $0x0,(%eax)
}
c0005e23:	90                   	nop
c0005e24:	c9                   	leave  
c0005e25:	c3                   	ret    

c0005e26 <identify_disk>:

// 获取硬盘参数信息
static void identify_disk(struct disk *hd) {
c0005e26:	55                   	push   %ebp
c0005e27:	89 e5                	mov    %esp,%ebp
c0005e29:	81 ec 98 02 00 00    	sub    $0x298,%esp
  char id_info[512];
  select_disk(hd);
c0005e2f:	ff 75 08             	push   0x8(%ebp)
c0005e32:	e8 8b f9 ff ff       	call   c00057c2 <select_disk>
c0005e37:	83 c4 04             	add    $0x4,%esp
  cmd_out(hd->my_channel, CMD_IDENTIFY);
c0005e3a:	8b 45 08             	mov    0x8(%ebp),%eax
c0005e3d:	8b 40 08             	mov    0x8(%eax),%eax
c0005e40:	68 ec 00 00 00       	push   $0xec
c0005e45:	50                   	push   %eax
c0005e46:	e8 ab fa ff ff       	call   c00058f6 <cmd_out>
c0005e4b:	83 c4 08             	add    $0x8,%esp
  sema_down(&hd->my_channel->disk_done);
c0005e4e:	8b 45 08             	mov    0x8(%ebp),%eax
c0005e51:	8b 40 08             	mov    0x8(%eax),%eax
c0005e54:	83 c0 2c             	add    $0x2c,%eax
c0005e57:	83 ec 0c             	sub    $0xc,%esp
c0005e5a:	50                   	push   %eax
c0005e5b:	e8 0f e6 ff ff       	call   c000446f <sema_down>
c0005e60:	83 c4 10             	add    $0x10,%esp

  if (!busy_wait(hd)) {
c0005e63:	83 ec 0c             	sub    $0xc,%esp
c0005e66:	ff 75 08             	push   0x8(%ebp)
c0005e69:	e8 4e fb ff ff       	call   c00059bc <busy_wait>
c0005e6e:	83 c4 10             	add    $0x10,%esp
c0005e71:	85 c0                	test   %eax,%eax
c0005e73:	75 39                	jne    c0005eae <identify_disk+0x88>
    char error[64];
    sprintf(error, "%s identify failed!!!!!!\n", hd->name);
c0005e75:	8b 45 08             	mov    0x8(%ebp),%eax
c0005e78:	83 ec 04             	sub    $0x4,%esp
c0005e7b:	50                   	push   %eax
c0005e7c:	68 7b cf 00 c0       	push   $0xc000cf7b
c0005e81:	8d 85 70 fd ff ff    	lea    -0x290(%ebp),%eax
c0005e87:	50                   	push   %eax
c0005e88:	e8 7d f7 ff ff       	call   c000560a <sprintf>
c0005e8d:	83 c4 10             	add    $0x10,%esp
    PANIC(error);
c0005e90:	8d 85 70 fd ff ff    	lea    -0x290(%ebp),%eax
c0005e96:	50                   	push   %eax
c0005e97:	68 9c d0 00 c0       	push   $0xc000d09c
c0005e9c:	68 03 01 00 00       	push   $0x103
c0005ea1:	68 e3 ce 00 c0       	push   $0xc000cee3
c0005ea6:	e8 2d c4 ff ff       	call   c00022d8 <panic_spin>
c0005eab:	83 c4 10             	add    $0x10,%esp
  }
  read_from_sector(hd, id_info, 1);
c0005eae:	83 ec 04             	sub    $0x4,%esp
c0005eb1:	6a 01                	push   $0x1
c0005eb3:	8d 85 f0 fd ff ff    	lea    -0x210(%ebp),%eax
c0005eb9:	50                   	push   %eax
c0005eba:	ff 75 08             	push   0x8(%ebp)
c0005ebd:	e8 68 fa ff ff       	call   c000592a <read_from_sector>
c0005ec2:	83 c4 10             	add    $0x10,%esp

  char buf[64]; // 缓冲区，存储转换后的结果
  uint8_t sn_start = 10 * 2, sn_len = 20, md_start = 27 * 2, md_len = 40;
c0005ec5:	c6 45 f7 14          	movb   $0x14,-0x9(%ebp)
c0005ec9:	c6 45 f6 14          	movb   $0x14,-0xa(%ebp)
c0005ecd:	c6 45 f5 36          	movb   $0x36,-0xb(%ebp)
c0005ed1:	c6 45 f4 28          	movb   $0x28,-0xc(%ebp)
  swap_pairs_bytes(&id_info[sn_start], buf, sn_len);
c0005ed5:	0f b6 45 f6          	movzbl -0xa(%ebp),%eax
c0005ed9:	0f b6 55 f7          	movzbl -0x9(%ebp),%edx
c0005edd:	8d 8d f0 fd ff ff    	lea    -0x210(%ebp),%ecx
c0005ee3:	01 ca                	add    %ecx,%edx
c0005ee5:	83 ec 04             	sub    $0x4,%esp
c0005ee8:	50                   	push   %eax
c0005ee9:	8d 85 b0 fd ff ff    	lea    -0x250(%ebp),%eax
c0005eef:	50                   	push   %eax
c0005ef0:	52                   	push   %edx
c0005ef1:	e8 d7 fe ff ff       	call   c0005dcd <swap_pairs_bytes>
c0005ef6:	83 c4 10             	add    $0x10,%esp
  printk("  disk %s info:\n    SN: %s\n", hd->name, buf);
c0005ef9:	8b 45 08             	mov    0x8(%ebp),%eax
c0005efc:	83 ec 04             	sub    $0x4,%esp
c0005eff:	8d 95 b0 fd ff ff    	lea    -0x250(%ebp),%edx
c0005f05:	52                   	push   %edx
c0005f06:	50                   	push   %eax
c0005f07:	68 95 cf 00 c0       	push   $0xc000cf95
c0005f0c:	e8 a3 f7 ff ff       	call   c00056b4 <printk>
c0005f11:	83 c4 10             	add    $0x10,%esp
  memset(buf, 0, sizeof(buf));
c0005f14:	83 ec 04             	sub    $0x4,%esp
c0005f17:	6a 40                	push   $0x40
c0005f19:	6a 00                	push   $0x0
c0005f1b:	8d 85 b0 fd ff ff    	lea    -0x250(%ebp),%eax
c0005f21:	50                   	push   %eax
c0005f22:	e8 87 c4 ff ff       	call   c00023ae <memset>
c0005f27:	83 c4 10             	add    $0x10,%esp
  swap_pairs_bytes(&id_info[md_start], buf, md_len);
c0005f2a:	0f b6 45 f4          	movzbl -0xc(%ebp),%eax
c0005f2e:	0f b6 55 f5          	movzbl -0xb(%ebp),%edx
c0005f32:	8d 8d f0 fd ff ff    	lea    -0x210(%ebp),%ecx
c0005f38:	01 ca                	add    %ecx,%edx
c0005f3a:	83 ec 04             	sub    $0x4,%esp
c0005f3d:	50                   	push   %eax
c0005f3e:	8d 85 b0 fd ff ff    	lea    -0x250(%ebp),%eax
c0005f44:	50                   	push   %eax
c0005f45:	52                   	push   %edx
c0005f46:	e8 82 fe ff ff       	call   c0005dcd <swap_pairs_bytes>
c0005f4b:	83 c4 10             	add    $0x10,%esp
  printk("    MODULE: %s\n", buf);
c0005f4e:	83 ec 08             	sub    $0x8,%esp
c0005f51:	8d 85 b0 fd ff ff    	lea    -0x250(%ebp),%eax
c0005f57:	50                   	push   %eax
c0005f58:	68 b1 cf 00 c0       	push   $0xc000cfb1
c0005f5d:	e8 52 f7 ff ff       	call   c00056b4 <printk>
c0005f62:	83 c4 10             	add    $0x10,%esp
  uint32_t sectors = *(uint32_t *)&id_info[60 * 2];
c0005f65:	8d 85 f0 fd ff ff    	lea    -0x210(%ebp),%eax
c0005f6b:	83 c0 78             	add    $0x78,%eax
c0005f6e:	8b 00                	mov    (%eax),%eax
c0005f70:	89 45 f0             	mov    %eax,-0x10(%ebp)
  printk("    SECTORS: %d\n", sectors);
c0005f73:	83 ec 08             	sub    $0x8,%esp
c0005f76:	ff 75 f0             	push   -0x10(%ebp)
c0005f79:	68 c1 cf 00 c0       	push   $0xc000cfc1
c0005f7e:	e8 31 f7 ff ff       	call   c00056b4 <printk>
c0005f83:	83 c4 10             	add    $0x10,%esp
  printk("    CAPACITY: %dMB\n", sectors * 512 / 1024 / 1024);
c0005f86:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0005f89:	c1 e0 09             	shl    $0x9,%eax
c0005f8c:	c1 e8 14             	shr    $0x14,%eax
c0005f8f:	83 ec 08             	sub    $0x8,%esp
c0005f92:	50                   	push   %eax
c0005f93:	68 d2 cf 00 c0       	push   $0xc000cfd2
c0005f98:	e8 17 f7 ff ff       	call   c00056b4 <printk>
c0005f9d:	83 c4 10             	add    $0x10,%esp
}
c0005fa0:	90                   	nop
c0005fa1:	c9                   	leave  
c0005fa2:	c3                   	ret    

c0005fa3 <partition_scan>:

// 扫描硬盘中地址为ext_lba的扇区中的所有分区
static void partition_scan(struct disk *hd, uint32_t ext_lba) {
c0005fa3:	55                   	push   %ebp
c0005fa4:	89 e5                	mov    %esp,%ebp
c0005fa6:	53                   	push   %ebx
c0005fa7:	83 ec 14             	sub    $0x14,%esp
  struct boot_sector *bs = sys_malloc(sizeof(struct boot_sector));
c0005faa:	83 ec 0c             	sub    $0xc,%esp
c0005fad:	68 00 02 00 00       	push   $0x200
c0005fb2:	e8 6d d0 ff ff       	call   c0003024 <sys_malloc>
c0005fb7:	83 c4 10             	add    $0x10,%esp
c0005fba:	89 45 ec             	mov    %eax,-0x14(%ebp)
  ide_read(hd, ext_lba, bs, 1);
c0005fbd:	6a 01                	push   $0x1
c0005fbf:	ff 75 ec             	push   -0x14(%ebp)
c0005fc2:	ff 75 0c             	push   0xc(%ebp)
c0005fc5:	ff 75 08             	push   0x8(%ebp)
c0005fc8:	e8 5e fa ff ff       	call   c0005a2b <ide_read>
c0005fcd:	83 c4 10             	add    $0x10,%esp
  uint8_t part_idx = 0;
c0005fd0:	c6 45 f7 00          	movb   $0x0,-0x9(%ebp)
  struct partition_table_entry *p = bs->partition_table;
c0005fd4:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0005fd7:	05 be 01 00 00       	add    $0x1be,%eax
c0005fdc:	89 45 f0             	mov    %eax,-0x10(%ebp)

  // 遍历分区表4个分区表项
  while (part_idx++ < 4) {
c0005fdf:	e9 52 02 00 00       	jmp    c0006236 <partition_scan+0x293>
    if (p->fs_type == 0x5) { // 扩展分区，递归
c0005fe4:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0005fe7:	0f b6 40 04          	movzbl 0x4(%eax),%eax
c0005feb:	3c 05                	cmp    $0x5,%al
c0005fed:	75 4f                	jne    c000603e <partition_scan+0x9b>
      if (ext_lba_base != 0) {
c0005fef:	a1 c0 29 01 c0       	mov    0xc00129c0,%eax
c0005ff4:	85 c0                	test   %eax,%eax
c0005ff6:	74 21                	je     c0006019 <partition_scan+0x76>
        partition_scan(hd, p->start_lba + ext_lba_base);
c0005ff8:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0005ffb:	8b 50 08             	mov    0x8(%eax),%edx
c0005ffe:	a1 c0 29 01 c0       	mov    0xc00129c0,%eax
c0006003:	01 d0                	add    %edx,%eax
c0006005:	83 ec 08             	sub    $0x8,%esp
c0006008:	50                   	push   %eax
c0006009:	ff 75 08             	push   0x8(%ebp)
c000600c:	e8 92 ff ff ff       	call   c0005fa3 <partition_scan>
c0006011:	83 c4 10             	add    $0x10,%esp
c0006014:	e9 19 02 00 00       	jmp    c0006232 <partition_scan+0x28f>
      } else { // 第一次读取引导块（主mbr所在扇区）记录起始lba地址，后面所有扩展分区地址都相对于此
        ext_lba_base = p->start_lba;
c0006019:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000601c:	8b 40 08             	mov    0x8(%eax),%eax
c000601f:	a3 c0 29 01 c0       	mov    %eax,0xc00129c0
        partition_scan(hd, p->start_lba);
c0006024:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0006027:	8b 40 08             	mov    0x8(%eax),%eax
c000602a:	83 ec 08             	sub    $0x8,%esp
c000602d:	50                   	push   %eax
c000602e:	ff 75 08             	push   0x8(%ebp)
c0006031:	e8 6d ff ff ff       	call   c0005fa3 <partition_scan>
c0006036:	83 c4 10             	add    $0x10,%esp
c0006039:	e9 f4 01 00 00       	jmp    c0006232 <partition_scan+0x28f>
      }
    } else if (p->fs_type != 0) { // 有效的分区类型
c000603e:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0006041:	0f b6 40 04          	movzbl 0x4(%eax),%eax
c0006045:	84 c0                	test   %al,%al
c0006047:	0f 84 e5 01 00 00    	je     c0006232 <partition_scan+0x28f>
      if (ext_lba == 0) {         // MBR主分区
c000604d:	83 7d 0c 00          	cmpl   $0x0,0xc(%ebp)
c0006051:	0f 85 f9 00 00 00    	jne    c0006150 <partition_scan+0x1ad>
        hd->prim_parts[p_no].start_lba = ext_lba + p->start_lba;
c0006057:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000605a:	8b 48 08             	mov    0x8(%eax),%ecx
c000605d:	0f b6 05 c4 29 01 c0 	movzbl 0xc00129c4,%eax
c0006064:	0f b6 c0             	movzbl %al,%eax
c0006067:	8b 55 0c             	mov    0xc(%ebp),%edx
c000606a:	01 ca                	add    %ecx,%edx
c000606c:	8b 4d 08             	mov    0x8(%ebp),%ecx
c000606f:	c1 e0 06             	shl    $0x6,%eax
c0006072:	01 c8                	add    %ecx,%eax
c0006074:	83 c0 10             	add    $0x10,%eax
c0006077:	89 10                	mov    %edx,(%eax)
        hd->prim_parts[p_no].sec_cnt = p->sec_cnt;
c0006079:	0f b6 05 c4 29 01 c0 	movzbl 0xc00129c4,%eax
c0006080:	0f b6 d0             	movzbl %al,%edx
c0006083:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0006086:	8b 40 0c             	mov    0xc(%eax),%eax
c0006089:	8b 4d 08             	mov    0x8(%ebp),%ecx
c000608c:	c1 e2 06             	shl    $0x6,%edx
c000608f:	01 ca                	add    %ecx,%edx
c0006091:	83 c2 14             	add    $0x14,%edx
c0006094:	89 02                	mov    %eax,(%edx)
        hd->prim_parts[p_no].my_disk = hd;
c0006096:	0f b6 05 c4 29 01 c0 	movzbl 0xc00129c4,%eax
c000609d:	0f b6 c0             	movzbl %al,%eax
c00060a0:	8b 55 08             	mov    0x8(%ebp),%edx
c00060a3:	c1 e0 06             	shl    $0x6,%eax
c00060a6:	01 d0                	add    %edx,%eax
c00060a8:	8d 50 18             	lea    0x18(%eax),%edx
c00060ab:	8b 45 08             	mov    0x8(%ebp),%eax
c00060ae:	89 02                	mov    %eax,(%edx)
        list_append(&partition_list, &hd->prim_parts[p_no].part_tag);
c00060b0:	0f b6 05 c4 29 01 c0 	movzbl 0xc00129c4,%eax
c00060b7:	0f b6 c0             	movzbl %al,%eax
c00060ba:	c1 e0 06             	shl    $0x6,%eax
c00060bd:	8d 50 10             	lea    0x10(%eax),%edx
c00060c0:	8b 45 08             	mov    0x8(%ebp),%eax
c00060c3:	01 d0                	add    %edx,%eax
c00060c5:	83 c0 0c             	add    $0xc,%eax
c00060c8:	83 ec 08             	sub    $0x8,%esp
c00060cb:	50                   	push   %eax
c00060cc:	68 c8 29 01 c0       	push   $0xc00129c8
c00060d1:	e8 c1 e1 ff ff       	call   c0004297 <list_append>
c00060d6:	83 c4 10             	add    $0x10,%esp
        sprintf(hd->prim_parts[p_no].name, "%s%d", hd->name, p_no + 1);
c00060d9:	0f b6 05 c4 29 01 c0 	movzbl 0xc00129c4,%eax
c00060e0:	0f b6 c0             	movzbl %al,%eax
c00060e3:	8d 48 01             	lea    0x1(%eax),%ecx
c00060e6:	8b 45 08             	mov    0x8(%ebp),%eax
c00060e9:	0f b6 15 c4 29 01 c0 	movzbl 0xc00129c4,%edx
c00060f0:	0f b6 d2             	movzbl %dl,%edx
c00060f3:	c1 e2 06             	shl    $0x6,%edx
c00060f6:	8d 5a 20             	lea    0x20(%edx),%ebx
c00060f9:	8b 55 08             	mov    0x8(%ebp),%edx
c00060fc:	01 da                	add    %ebx,%edx
c00060fe:	83 c2 04             	add    $0x4,%edx
c0006101:	51                   	push   %ecx
c0006102:	50                   	push   %eax
c0006103:	68 e6 cf 00 c0       	push   $0xc000cfe6
c0006108:	52                   	push   %edx
c0006109:	e8 fc f4 ff ff       	call   c000560a <sprintf>
c000610e:	83 c4 10             	add    $0x10,%esp
        p_no++;
c0006111:	0f b6 05 c4 29 01 c0 	movzbl 0xc00129c4,%eax
c0006118:	83 c0 01             	add    $0x1,%eax
c000611b:	a2 c4 29 01 c0       	mov    %al,0xc00129c4
        ASSERT(p_no < 4);
c0006120:	0f b6 05 c4 29 01 c0 	movzbl 0xc00129c4,%eax
c0006127:	3c 03                	cmp    $0x3,%al
c0006129:	0f 86 03 01 00 00    	jbe    c0006232 <partition_scan+0x28f>
c000612f:	68 eb cf 00 c0       	push   $0xc000cfeb
c0006134:	68 ac d0 00 c0       	push   $0xc000d0ac
c0006139:	68 2b 01 00 00       	push   $0x12b
c000613e:	68 e3 ce 00 c0       	push   $0xc000cee3
c0006143:	e8 90 c1 ff ff       	call   c00022d8 <panic_spin>
c0006148:	83 c4 10             	add    $0x10,%esp
c000614b:	e9 e2 00 00 00       	jmp    c0006232 <partition_scan+0x28f>
      } else { // 逻辑分区（从5开始
        hd->logic_parts[l_no].start_lba = ext_lba + p->start_lba;
c0006150:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0006153:	8b 48 08             	mov    0x8(%eax),%ecx
c0006156:	0f b6 05 c5 29 01 c0 	movzbl 0xc00129c5,%eax
c000615d:	0f b6 c0             	movzbl %al,%eax
c0006160:	8b 55 0c             	mov    0xc(%ebp),%edx
c0006163:	01 ca                	add    %ecx,%edx
c0006165:	8b 4d 08             	mov    0x8(%ebp),%ecx
c0006168:	c1 e0 06             	shl    $0x6,%eax
c000616b:	01 c8                	add    %ecx,%eax
c000616d:	05 10 01 00 00       	add    $0x110,%eax
c0006172:	89 10                	mov    %edx,(%eax)
        hd->logic_parts[l_no].sec_cnt = p->sec_cnt;
c0006174:	0f b6 05 c5 29 01 c0 	movzbl 0xc00129c5,%eax
c000617b:	0f b6 d0             	movzbl %al,%edx
c000617e:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0006181:	8b 40 0c             	mov    0xc(%eax),%eax
c0006184:	8b 4d 08             	mov    0x8(%ebp),%ecx
c0006187:	c1 e2 06             	shl    $0x6,%edx
c000618a:	01 ca                	add    %ecx,%edx
c000618c:	81 c2 14 01 00 00    	add    $0x114,%edx
c0006192:	89 02                	mov    %eax,(%edx)
        hd->logic_parts[l_no].my_disk = hd;
c0006194:	0f b6 05 c5 29 01 c0 	movzbl 0xc00129c5,%eax
c000619b:	0f b6 c0             	movzbl %al,%eax
c000619e:	8b 55 08             	mov    0x8(%ebp),%edx
c00061a1:	c1 e0 06             	shl    $0x6,%eax
c00061a4:	01 d0                	add    %edx,%eax
c00061a6:	8d 90 18 01 00 00    	lea    0x118(%eax),%edx
c00061ac:	8b 45 08             	mov    0x8(%ebp),%eax
c00061af:	89 02                	mov    %eax,(%edx)
        list_append(&partition_list, &hd->logic_parts[l_no].part_tag);
c00061b1:	0f b6 05 c5 29 01 c0 	movzbl 0xc00129c5,%eax
c00061b8:	0f b6 c0             	movzbl %al,%eax
c00061bb:	c1 e0 06             	shl    $0x6,%eax
c00061be:	8d 90 10 01 00 00    	lea    0x110(%eax),%edx
c00061c4:	8b 45 08             	mov    0x8(%ebp),%eax
c00061c7:	01 d0                	add    %edx,%eax
c00061c9:	83 c0 0c             	add    $0xc,%eax
c00061cc:	83 ec 08             	sub    $0x8,%esp
c00061cf:	50                   	push   %eax
c00061d0:	68 c8 29 01 c0       	push   $0xc00129c8
c00061d5:	e8 bd e0 ff ff       	call   c0004297 <list_append>
c00061da:	83 c4 10             	add    $0x10,%esp
        sprintf(hd->logic_parts[l_no].name, "%s%d", hd->name, l_no + 5);
c00061dd:	0f b6 05 c5 29 01 c0 	movzbl 0xc00129c5,%eax
c00061e4:	0f b6 c0             	movzbl %al,%eax
c00061e7:	8d 48 05             	lea    0x5(%eax),%ecx
c00061ea:	8b 45 08             	mov    0x8(%ebp),%eax
c00061ed:	0f b6 15 c5 29 01 c0 	movzbl 0xc00129c5,%edx
c00061f4:	0f b6 d2             	movzbl %dl,%edx
c00061f7:	c1 e2 06             	shl    $0x6,%edx
c00061fa:	8d 9a 20 01 00 00    	lea    0x120(%edx),%ebx
c0006200:	8b 55 08             	mov    0x8(%ebp),%edx
c0006203:	01 da                	add    %ebx,%edx
c0006205:	83 c2 04             	add    $0x4,%edx
c0006208:	51                   	push   %ecx
c0006209:	50                   	push   %eax
c000620a:	68 e6 cf 00 c0       	push   $0xc000cfe6
c000620f:	52                   	push   %edx
c0006210:	e8 f5 f3 ff ff       	call   c000560a <sprintf>
c0006215:	83 c4 10             	add    $0x10,%esp
        l_no++;
c0006218:	0f b6 05 c5 29 01 c0 	movzbl 0xc00129c5,%eax
c000621f:	83 c0 01             	add    $0x1,%eax
c0006222:	a2 c5 29 01 c0       	mov    %al,0xc00129c5
        if (l_no >= 8) { // 只支持8个逻辑分区，避免数组越界
c0006227:	0f b6 05 c5 29 01 c0 	movzbl 0xc00129c5,%eax
c000622e:	3c 07                	cmp    $0x7,%al
c0006230:	77 26                	ja     c0006258 <partition_scan+0x2b5>
          return;
        }
      }
    }
    p++;
c0006232:	83 45 f0 10          	addl   $0x10,-0x10(%ebp)
  while (part_idx++ < 4) {
c0006236:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c000623a:	8d 50 01             	lea    0x1(%eax),%edx
c000623d:	88 55 f7             	mov    %dl,-0x9(%ebp)
c0006240:	3c 03                	cmp    $0x3,%al
c0006242:	0f 86 9c fd ff ff    	jbe    c0005fe4 <partition_scan+0x41>
  }
  sys_free(bs);
c0006248:	83 ec 0c             	sub    $0xc,%esp
c000624b:	ff 75 ec             	push   -0x14(%ebp)
c000624e:	e8 f0 d3 ff ff       	call   c0003643 <sys_free>
c0006253:	83 c4 10             	add    $0x10,%esp
c0006256:	eb 01                	jmp    c0006259 <partition_scan+0x2b6>
          return;
c0006258:	90                   	nop
}
c0006259:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c000625c:	c9                   	leave  
c000625d:	c3                   	ret    

c000625e <partition_info>:

// 打印分区信息
static bool partition_info(struct list_elem *pelem, int arg UNUSED) {
c000625e:	55                   	push   %ebp
c000625f:	89 e5                	mov    %esp,%ebp
c0006261:	83 ec 18             	sub    $0x18,%esp
  struct partition *part = elem2entry(struct partition, part_tag, pelem);
c0006264:	8b 45 08             	mov    0x8(%ebp),%eax
c0006267:	83 e8 0c             	sub    $0xc,%eax
c000626a:	89 45 f4             	mov    %eax,-0xc(%ebp)
  printk("  %s start_lba:0x%x, sec_cnt:0x%x\n", part->name, part->start_lba,
c000626d:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0006270:	8b 50 04             	mov    0x4(%eax),%edx
c0006273:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0006276:	8b 00                	mov    (%eax),%eax
c0006278:	8b 4d f4             	mov    -0xc(%ebp),%ecx
c000627b:	83 c1 14             	add    $0x14,%ecx
c000627e:	52                   	push   %edx
c000627f:	50                   	push   %eax
c0006280:	51                   	push   %ecx
c0006281:	68 f4 cf 00 c0       	push   $0xc000cff4
c0006286:	e8 29 f4 ff ff       	call   c00056b4 <printk>
c000628b:	83 c4 10             	add    $0x10,%esp
         part->sec_cnt);
  return false; // return与函数本身功能无关，只为了让主调函数list_traversal继续向下遍历元素
c000628e:	b8 00 00 00 00       	mov    $0x0,%eax
}
c0006293:	c9                   	leave  
c0006294:	c3                   	ret    

c0006295 <ide_init>:

void ide_init() {
c0006295:	55                   	push   %ebp
c0006296:	89 e5                	mov    %esp,%ebp
c0006298:	83 ec 18             	sub    $0x18,%esp
  printk("ide_init start\n");
c000629b:	83 ec 0c             	sub    $0xc,%esp
c000629e:	68 17 d0 00 c0       	push   $0xc000d017
c00062a3:	e8 0c f4 ff ff       	call   c00056b4 <printk>
c00062a8:	83 c4 10             	add    $0x10,%esp
  uint8_t hd_cnt = *((uint8_t *)(0x475)); // 获取硬盘数
c00062ab:	b8 75 04 00 00       	mov    $0x475,%eax
c00062b0:	0f b6 00             	movzbl (%eax),%eax
c00062b3:	88 45 f5             	mov    %al,-0xb(%ebp)
  ASSERT(hd_cnt > 0);
c00062b6:	80 7d f5 00          	cmpb   $0x0,-0xb(%ebp)
c00062ba:	75 1c                	jne    c00062d8 <ide_init+0x43>
c00062bc:	68 27 d0 00 c0       	push   $0xc000d027
c00062c1:	68 bc d0 00 c0       	push   $0xc000d0bc
c00062c6:	68 48 01 00 00       	push   $0x148
c00062cb:	68 e3 ce 00 c0       	push   $0xc000cee3
c00062d0:	e8 03 c0 ff ff       	call   c00022d8 <panic_spin>
c00062d5:	83 c4 10             	add    $0x10,%esp
  list_init(&partition_list);
c00062d8:	83 ec 0c             	sub    $0xc,%esp
c00062db:	68 c8 29 01 c0       	push   $0xc00129c8
c00062e0:	e8 21 df ff ff       	call   c0004206 <list_init>
c00062e5:	83 c4 10             	add    $0x10,%esp
  channel_cnt = DIV_ROUND_UP(hd_cnt, 2); // 根据硬盘数反推ide通道数
c00062e8:	0f b6 45 f5          	movzbl -0xb(%ebp),%eax
c00062ec:	83 c0 01             	add    $0x1,%eax
c00062ef:	89 c2                	mov    %eax,%edx
c00062f1:	c1 ea 1f             	shr    $0x1f,%edx
c00062f4:	01 d0                	add    %edx,%eax
c00062f6:	d1 f8                	sar    %eax
c00062f8:	a2 e0 1c 01 c0       	mov    %al,0xc0011ce0
  struct ide_channel *channel;
  uint8_t channel_no = 0, dev_no = 0;
c00062fd:	c6 45 f7 00          	movb   $0x0,-0x9(%ebp)
c0006301:	c6 45 f6 00          	movb   $0x0,-0xa(%ebp)

  while (channel_no < channel_cnt) {
c0006305:	e9 4d 01 00 00       	jmp    c0006457 <ide_init+0x1c2>
    channel = &channels[channel_no];
c000630a:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c000630e:	69 c0 60 06 00 00    	imul   $0x660,%eax,%eax
c0006314:	05 00 1d 01 c0       	add    $0xc0011d00,%eax
c0006319:	89 45 f0             	mov    %eax,-0x10(%ebp)
    sprintf(channel->name, "ide%d", channel_no);
c000631c:	0f b6 55 f7          	movzbl -0x9(%ebp),%edx
c0006320:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0006323:	83 ec 04             	sub    $0x4,%esp
c0006326:	52                   	push   %edx
c0006327:	68 32 d0 00 c0       	push   $0xc000d032
c000632c:	50                   	push   %eax
c000632d:	e8 d8 f2 ff ff       	call   c000560a <sprintf>
c0006332:	83 c4 10             	add    $0x10,%esp

    /* 为每个ide通道初始化端口基址及中断向量 */
    switch (channel_no) {
c0006335:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0006339:	85 c0                	test   %eax,%eax
c000633b:	74 07                	je     c0006344 <ide_init+0xaf>
c000633d:	83 f8 01             	cmp    $0x1,%eax
c0006340:	74 14                	je     c0006356 <ide_init+0xc1>
c0006342:	eb 23                	jmp    c0006367 <ide_init+0xd2>
    case 0:
      channel->port_base = 0x1f0;
c0006344:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0006347:	66 c7 40 08 f0 01    	movw   $0x1f0,0x8(%eax)
      // 从片8259A上倒二的中断引脚（响应ide0通道上的硬盘中断
      channel->irq_no = 0x20 + 14;
c000634d:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0006350:	c6 40 0a 2e          	movb   $0x2e,0xa(%eax)
      break;
c0006354:	eb 11                	jmp    c0006367 <ide_init+0xd2>
    case 1:
      channel->port_base = 0x170;
c0006356:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0006359:	66 c7 40 08 70 01    	movw   $0x170,0x8(%eax)
      // 从片8259A上的最后一个中断引脚（响应ide1通道上的硬盘中断
      channel->irq_no = 0x20 + 15;
c000635f:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0006362:	c6 40 0a 2f          	movb   $0x2f,0xa(%eax)
      break;
c0006366:	90                   	nop
    }
    channel->expecting_intr = false; // 未向硬盘写入指令时不期待硬盘的中断
c0006367:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000636a:	c7 40 28 00 00 00 00 	movl   $0x0,0x28(%eax)
    lock_init(&channel->lock);
c0006371:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0006374:	83 c0 0c             	add    $0xc,%eax
c0006377:	83 ec 0c             	sub    $0xc,%esp
c000637a:	50                   	push   %eax
c000637b:	e8 bf e0 ff ff       	call   c000443f <lock_init>
c0006380:	83 c4 10             	add    $0x10,%esp
    /* 初始化为0，目的是向硬盘控制器请求数据后，硬盘驱动sema_down阻塞线程，
    直到硬盘完成后通过发中断，由中断处理程序将此信号量sema_up，唤醒线程 */
    sema_init(&channel->disk_done, 0);
c0006383:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0006386:	83 c0 2c             	add    $0x2c,%eax
c0006389:	83 ec 08             	sub    $0x8,%esp
c000638c:	6a 00                	push   $0x0
c000638e:	50                   	push   %eax
c000638f:	e8 81 e0 ff ff       	call   c0004415 <sema_init>
c0006394:	83 c4 10             	add    $0x10,%esp
    register_handler(channel->irq_no, intr_hd_handler);
c0006397:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000639a:	0f b6 40 0a          	movzbl 0xa(%eax),%eax
c000639e:	0f b6 c0             	movzbl %al,%eax
c00063a1:	83 ec 08             	sub    $0x8,%esp
c00063a4:	68 13 5d 00 c0       	push   $0xc0005d13
c00063a9:	50                   	push   %eax
c00063aa:	e8 b7 b5 ff ff       	call   c0001966 <register_handler>
c00063af:	83 c4 10             	add    $0x10,%esp

    // 分别获取俩硬盘的参数和分区信息
    while (dev_no < 2) {
c00063b2:	e9 88 00 00 00       	jmp    c000643f <ide_init+0x1aa>
      struct disk *hd = &channel->devices[dev_no];
c00063b7:	0f b6 45 f6          	movzbl -0xa(%ebp),%eax
c00063bb:	69 c0 10 03 00 00    	imul   $0x310,%eax,%eax
c00063c1:	8d 50 40             	lea    0x40(%eax),%edx
c00063c4:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00063c7:	01 d0                	add    %edx,%eax
c00063c9:	89 45 ec             	mov    %eax,-0x14(%ebp)
      hd->my_channel = channel;
c00063cc:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00063cf:	8b 55 f0             	mov    -0x10(%ebp),%edx
c00063d2:	89 50 08             	mov    %edx,0x8(%eax)
      hd->dev_no = dev_no;
c00063d5:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00063d8:	0f b6 55 f6          	movzbl -0xa(%ebp),%edx
c00063dc:	88 50 0c             	mov    %dl,0xc(%eax)
      sprintf(hd->name, "sd%c", 'a' + channel_no * 2 + dev_no);
c00063df:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c00063e3:	01 c0                	add    %eax,%eax
c00063e5:	8d 50 61             	lea    0x61(%eax),%edx
c00063e8:	0f b6 45 f6          	movzbl -0xa(%ebp),%eax
c00063ec:	01 c2                	add    %eax,%edx
c00063ee:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00063f1:	83 ec 04             	sub    $0x4,%esp
c00063f4:	52                   	push   %edx
c00063f5:	68 38 d0 00 c0       	push   $0xc000d038
c00063fa:	50                   	push   %eax
c00063fb:	e8 0a f2 ff ff       	call   c000560a <sprintf>
c0006400:	83 c4 10             	add    $0x10,%esp
      identify_disk(hd); // 获取硬盘参数
c0006403:	83 ec 0c             	sub    $0xc,%esp
c0006406:	ff 75 ec             	push   -0x14(%ebp)
c0006409:	e8 18 fa ff ff       	call   c0005e26 <identify_disk>
c000640e:	83 c4 10             	add    $0x10,%esp
      if (dev_no != 0) { // 内核本身的裸硬盘（hd60M.img）不处理
c0006411:	80 7d f6 00          	cmpb   $0x0,-0xa(%ebp)
c0006415:	74 10                	je     c0006427 <ide_init+0x192>
        partition_scan(hd, 0); // 扫描该硬盘上的分区
c0006417:	83 ec 08             	sub    $0x8,%esp
c000641a:	6a 00                	push   $0x0
c000641c:	ff 75 ec             	push   -0x14(%ebp)
c000641f:	e8 7f fb ff ff       	call   c0005fa3 <partition_scan>
c0006424:	83 c4 10             	add    $0x10,%esp
      }
      p_no = 0, l_no = 0; // 将硬盘驱动器号置0，为下个channel的两个硬盘初始化
c0006427:	c6 05 c4 29 01 c0 00 	movb   $0x0,0xc00129c4
c000642e:	c6 05 c5 29 01 c0 00 	movb   $0x0,0xc00129c5
      dev_no++;
c0006435:	0f b6 45 f6          	movzbl -0xa(%ebp),%eax
c0006439:	83 c0 01             	add    $0x1,%eax
c000643c:	88 45 f6             	mov    %al,-0xa(%ebp)
    while (dev_no < 2) {
c000643f:	80 7d f6 01          	cmpb   $0x1,-0xa(%ebp)
c0006443:	0f 86 6e ff ff ff    	jbe    c00063b7 <ide_init+0x122>
    }
    dev_no = 0; // 将硬盘驱动器号置0，为下个channel的两个硬盘初始化
c0006449:	c6 45 f6 00          	movb   $0x0,-0xa(%ebp)
    channel_no++; // 下个channel
c000644d:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0006451:	83 c0 01             	add    $0x1,%eax
c0006454:	88 45 f7             	mov    %al,-0x9(%ebp)
  while (channel_no < channel_cnt) {
c0006457:	0f b6 05 e0 1c 01 c0 	movzbl 0xc0011ce0,%eax
c000645e:	38 45 f7             	cmp    %al,-0x9(%ebp)
c0006461:	0f 82 a3 fe ff ff    	jb     c000630a <ide_init+0x75>
  }

  printk("\n  all partition info\n");
c0006467:	83 ec 0c             	sub    $0xc,%esp
c000646a:	68 3d d0 00 c0       	push   $0xc000d03d
c000646f:	e8 40 f2 ff ff       	call   c00056b4 <printk>
c0006474:	83 c4 10             	add    $0x10,%esp
  list_traversal(&partition_list, partition_info, (int)NULL);
c0006477:	83 ec 04             	sub    $0x4,%esp
c000647a:	6a 00                	push   $0x0
c000647c:	68 5e 62 00 c0       	push   $0xc000625e
c0006481:	68 c8 29 01 c0       	push   $0xc00129c8
c0006486:	e8 c1 de ff ff       	call   c000434c <list_traversal>
c000648b:	83 c4 10             	add    $0x10,%esp
  printk("ide_init done\n");
c000648e:	83 ec 0c             	sub    $0xc,%esp
c0006491:	68 54 d0 00 c0       	push   $0xc000d054
c0006496:	e8 19 f2 ff ff       	call   c00056b4 <printk>
c000649b:	83 c4 10             	add    $0x10,%esp
c000649e:	90                   	nop
c000649f:	c9                   	leave  
c00064a0:	c3                   	ret    

c00064a1 <mount_partition>:
#include "thread.h"

struct partition *cur_part; // 默认情况下操作的是哪个分区

// 在分区链表中找到名为part_name的分区，并将其指针赋值给cur_part
static bool mount_partition(struct list_elem *pelem, int arg) {
c00064a1:	55                   	push   %ebp
c00064a2:	89 e5                	mov    %esp,%ebp
c00064a4:	53                   	push   %ebx
c00064a5:	83 ec 14             	sub    $0x14,%esp
  char *part_name = (char *)arg;
c00064a8:	8b 45 0c             	mov    0xc(%ebp),%eax
c00064ab:	89 45 f4             	mov    %eax,-0xc(%ebp)
  struct partition *part = elem2entry(struct partition, part_tag, pelem);
c00064ae:	8b 45 08             	mov    0x8(%ebp),%eax
c00064b1:	83 e8 0c             	sub    $0xc,%eax
c00064b4:	89 45 f0             	mov    %eax,-0x10(%ebp)

  if (!strcmp(part->name, part_name)) {
c00064b7:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00064ba:	83 c0 14             	add    $0x14,%eax
c00064bd:	83 ec 08             	sub    $0x8,%esp
c00064c0:	ff 75 f4             	push   -0xc(%ebp)
c00064c3:	50                   	push   %eax
c00064c4:	e8 b8 c0 ff ff       	call   c0002581 <strcmp>
c00064c9:	83 c4 10             	add    $0x10,%esp
c00064cc:	84 c0                	test   %al,%al
c00064ce:	0f 85 ce 01 00 00    	jne    c00066a2 <mount_partition+0x201>
    cur_part = part;
c00064d4:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00064d7:	a3 d8 29 01 c0       	mov    %eax,0xc00129d8
    struct disk *hd = cur_part->my_disk;
c00064dc:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c00064e1:	8b 40 08             	mov    0x8(%eax),%eax
c00064e4:	89 45 ec             	mov    %eax,-0x14(%ebp)
    struct super_block *sb_buf = (struct super_block *)sys_malloc(SECTOR_SIZE);
c00064e7:	83 ec 0c             	sub    $0xc,%esp
c00064ea:	68 00 02 00 00       	push   $0x200
c00064ef:	e8 30 cb ff ff       	call   c0003024 <sys_malloc>
c00064f4:	83 c4 10             	add    $0x10,%esp
c00064f7:	89 45 e8             	mov    %eax,-0x18(%ebp)

    // 在内存中创建cur_part分区的超级块
    cur_part->sb = (struct super_block *)sys_malloc(sizeof(struct super_block));
c00064fa:	8b 1d d8 29 01 c0    	mov    0xc00129d8,%ebx
c0006500:	83 ec 0c             	sub    $0xc,%esp
c0006503:	68 00 02 00 00       	push   $0x200
c0006508:	e8 17 cb ff ff       	call   c0003024 <sys_malloc>
c000650d:	83 c4 10             	add    $0x10,%esp
c0006510:	89 43 1c             	mov    %eax,0x1c(%ebx)
    if (cur_part->sb == NULL) {
c0006513:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0006518:	8b 40 1c             	mov    0x1c(%eax),%eax
c000651b:	85 c0                	test   %eax,%eax
c000651d:	75 19                	jne    c0006538 <mount_partition+0x97>
      PANIC("alloc memory failed!");
c000651f:	68 c8 d0 00 c0       	push   $0xc000d0c8
c0006524:	68 d4 d8 00 c0       	push   $0xc000d8d4
c0006529:	6a 23                	push   $0x23
c000652b:	68 dd d0 00 c0       	push   $0xc000d0dd
c0006530:	e8 a3 bd ff ff       	call   c00022d8 <panic_spin>
c0006535:	83 c4 10             	add    $0x10,%esp
    }
    memset(sb_buf, 0, SECTOR_SIZE);
c0006538:	83 ec 04             	sub    $0x4,%esp
c000653b:	68 00 02 00 00       	push   $0x200
c0006540:	6a 00                	push   $0x0
c0006542:	ff 75 e8             	push   -0x18(%ebp)
c0006545:	e8 64 be ff ff       	call   c00023ae <memset>
c000654a:	83 c4 10             	add    $0x10,%esp
    ide_read(hd, cur_part->start_lba + 1, sb_buf, 1); // 读超级块到sb_buf
c000654d:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0006552:	8b 00                	mov    (%eax),%eax
c0006554:	83 c0 01             	add    $0x1,%eax
c0006557:	6a 01                	push   $0x1
c0006559:	ff 75 e8             	push   -0x18(%ebp)
c000655c:	50                   	push   %eax
c000655d:	ff 75 ec             	push   -0x14(%ebp)
c0006560:	e8 c6 f4 ff ff       	call   c0005a2b <ide_read>
c0006565:	83 c4 10             	add    $0x10,%esp
    memcpy(cur_part->sb, sb_buf,
c0006568:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000656d:	8b 40 1c             	mov    0x1c(%eax),%eax
c0006570:	83 ec 04             	sub    $0x4,%esp
c0006573:	68 00 02 00 00       	push   $0x200
c0006578:	ff 75 e8             	push   -0x18(%ebp)
c000657b:	50                   	push   %eax
c000657c:	e8 80 be ff ff       	call   c0002401 <memcpy>
c0006581:	83 c4 10             	add    $0x10,%esp
           sizeof(struct super_block)); // 复制到分区超级块sb中

    // 把磁盘上的块位图读入内存
    cur_part->block_bitmap.bits =
        (uint8_t *)sys_malloc(sb_buf->block_bitmap_sects * SECTOR_SIZE);
c0006584:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0006587:	8b 40 14             	mov    0x14(%eax),%eax
c000658a:	c1 e0 09             	shl    $0x9,%eax
    cur_part->block_bitmap.bits =
c000658d:	8b 1d d8 29 01 c0    	mov    0xc00129d8,%ebx
        (uint8_t *)sys_malloc(sb_buf->block_bitmap_sects * SECTOR_SIZE);
c0006593:	83 ec 0c             	sub    $0xc,%esp
c0006596:	50                   	push   %eax
c0006597:	e8 88 ca ff ff       	call   c0003024 <sys_malloc>
c000659c:	83 c4 10             	add    $0x10,%esp
    cur_part->block_bitmap.bits =
c000659f:	89 43 24             	mov    %eax,0x24(%ebx)
    if (cur_part->block_bitmap.bits == NULL) {
c00065a2:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c00065a7:	8b 40 24             	mov    0x24(%eax),%eax
c00065aa:	85 c0                	test   %eax,%eax
c00065ac:	75 19                	jne    c00065c7 <mount_partition+0x126>
      PANIC("alloc memeory failed!");
c00065ae:	68 e5 d0 00 c0       	push   $0xc000d0e5
c00065b3:	68 d4 d8 00 c0       	push   $0xc000d8d4
c00065b8:	6a 2e                	push   $0x2e
c00065ba:	68 dd d0 00 c0       	push   $0xc000d0dd
c00065bf:	e8 14 bd ff ff       	call   c00022d8 <panic_spin>
c00065c4:	83 c4 10             	add    $0x10,%esp
    }
    cur_part->block_bitmap.btmp_bytes_len =
        sb_buf->block_bitmap_sects * SECTOR_SIZE;
c00065c7:	8b 45 e8             	mov    -0x18(%ebp),%eax
c00065ca:	8b 50 14             	mov    0x14(%eax),%edx
    cur_part->block_bitmap.btmp_bytes_len =
c00065cd:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
        sb_buf->block_bitmap_sects * SECTOR_SIZE;
c00065d2:	c1 e2 09             	shl    $0x9,%edx
    cur_part->block_bitmap.btmp_bytes_len =
c00065d5:	89 50 20             	mov    %edx,0x20(%eax)
    ide_read(hd, sb_buf->block_bitmap_lba, cur_part->block_bitmap.bits,
c00065d8:	8b 45 e8             	mov    -0x18(%ebp),%eax
c00065db:	8b 48 14             	mov    0x14(%eax),%ecx
c00065de:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c00065e3:	8b 50 24             	mov    0x24(%eax),%edx
c00065e6:	8b 45 e8             	mov    -0x18(%ebp),%eax
c00065e9:	8b 40 10             	mov    0x10(%eax),%eax
c00065ec:	51                   	push   %ecx
c00065ed:	52                   	push   %edx
c00065ee:	50                   	push   %eax
c00065ef:	ff 75 ec             	push   -0x14(%ebp)
c00065f2:	e8 34 f4 ff ff       	call   c0005a2b <ide_read>
c00065f7:	83 c4 10             	add    $0x10,%esp
             sb_buf->block_bitmap_sects);

    // 将磁盘上的inode位图读入到内存
    cur_part->inode_bitmap.bits =
        (uint8_t *)sys_malloc(sb_buf->inode_bitmap_sects * SECTOR_SIZE);
c00065fa:	8b 45 e8             	mov    -0x18(%ebp),%eax
c00065fd:	8b 40 1c             	mov    0x1c(%eax),%eax
c0006600:	c1 e0 09             	shl    $0x9,%eax
    cur_part->inode_bitmap.bits =
c0006603:	8b 1d d8 29 01 c0    	mov    0xc00129d8,%ebx
        (uint8_t *)sys_malloc(sb_buf->inode_bitmap_sects * SECTOR_SIZE);
c0006609:	83 ec 0c             	sub    $0xc,%esp
c000660c:	50                   	push   %eax
c000660d:	e8 12 ca ff ff       	call   c0003024 <sys_malloc>
c0006612:	83 c4 10             	add    $0x10,%esp
    cur_part->inode_bitmap.bits =
c0006615:	89 43 2c             	mov    %eax,0x2c(%ebx)
    if (cur_part->inode_bitmap.bits == NULL) {
c0006618:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000661d:	8b 40 2c             	mov    0x2c(%eax),%eax
c0006620:	85 c0                	test   %eax,%eax
c0006622:	75 19                	jne    c000663d <mount_partition+0x19c>
      PANIC("alloc memory failed!");
c0006624:	68 c8 d0 00 c0       	push   $0xc000d0c8
c0006629:	68 d4 d8 00 c0       	push   $0xc000d8d4
c000662e:	6a 39                	push   $0x39
c0006630:	68 dd d0 00 c0       	push   $0xc000d0dd
c0006635:	e8 9e bc ff ff       	call   c00022d8 <panic_spin>
c000663a:	83 c4 10             	add    $0x10,%esp
    }
    cur_part->inode_bitmap.btmp_bytes_len =
        sb_buf->inode_bitmap_sects * SECTOR_SIZE;
c000663d:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0006640:	8b 50 1c             	mov    0x1c(%eax),%edx
    cur_part->inode_bitmap.btmp_bytes_len =
c0006643:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
        sb_buf->inode_bitmap_sects * SECTOR_SIZE;
c0006648:	c1 e2 09             	shl    $0x9,%edx
    cur_part->inode_bitmap.btmp_bytes_len =
c000664b:	89 50 28             	mov    %edx,0x28(%eax)
    ide_read(hd, sb_buf->inode_bitmap_lba, cur_part->inode_bitmap.bits,
c000664e:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0006651:	8b 48 1c             	mov    0x1c(%eax),%ecx
c0006654:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0006659:	8b 50 2c             	mov    0x2c(%eax),%edx
c000665c:	8b 45 e8             	mov    -0x18(%ebp),%eax
c000665f:	8b 40 18             	mov    0x18(%eax),%eax
c0006662:	51                   	push   %ecx
c0006663:	52                   	push   %edx
c0006664:	50                   	push   %eax
c0006665:	ff 75 ec             	push   -0x14(%ebp)
c0006668:	e8 be f3 ff ff       	call   c0005a2b <ide_read>
c000666d:	83 c4 10             	add    $0x10,%esp
             sb_buf->inode_bitmap_sects);

    list_init(&cur_part->open_inodes);
c0006670:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0006675:	83 c0 30             	add    $0x30,%eax
c0006678:	83 ec 0c             	sub    $0xc,%esp
c000667b:	50                   	push   %eax
c000667c:	e8 85 db ff ff       	call   c0004206 <list_init>
c0006681:	83 c4 10             	add    $0x10,%esp
    printk("mount %s done!\n", part->name);
c0006684:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0006687:	83 c0 14             	add    $0x14,%eax
c000668a:	83 ec 08             	sub    $0x8,%esp
c000668d:	50                   	push   %eax
c000668e:	68 fb d0 00 c0       	push   $0xc000d0fb
c0006693:	e8 1c f0 ff ff       	call   c00056b4 <printk>
c0006698:	83 c4 10             	add    $0x10,%esp
    return true; // 停止遍历
c000669b:	b8 01 00 00 00       	mov    $0x1,%eax
c00066a0:	eb 05                	jmp    c00066a7 <mount_partition+0x206>
  }
  return false; // 继续遍历
c00066a2:	b8 00 00 00 00       	mov    $0x0,%eax
}
c00066a7:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c00066aa:	c9                   	leave  
c00066ab:	c3                   	ret    

c00066ac <partition_format>:

// 初始化分区元信息（一个块大小是一扇区
static void partition_format(struct disk *hd, struct partition *part) {
c00066ac:	55                   	push   %ebp
c00066ad:	89 e5                	mov    %esp,%ebp
c00066af:	57                   	push   %edi
c00066b0:	56                   	push   %esi
c00066b1:	53                   	push   %ebx
c00066b2:	81 ec 6c 02 00 00    	sub    $0x26c,%esp
  uint32_t boot_sector_sects = 1;
c00066b8:	c7 45 e0 01 00 00 00 	movl   $0x1,-0x20(%ebp)
  uint32_t super_block_sects = 1;
c00066bf:	c7 45 dc 01 00 00 00 	movl   $0x1,-0x24(%ebp)
  uint32_t inode_bitmap_sects = // inode位图占扇区数1（最多支持4096个文件
c00066c6:	c7 45 d8 01 00 00 00 	movl   $0x1,-0x28(%ebp)
      DIV_ROUND_UP(MAX_FILES_PER_PART, BITS_PER_SECTOR);
  uint32_t inode_table_sects = // inode数组占扇区数
c00066cd:	c7 45 d4 60 02 00 00 	movl   $0x260,-0x2c(%ebp)
      DIV_ROUND_UP(((sizeof(struct inode) * MAX_FILES_PER_PART)), SECTOR_SIZE);
  uint32_t used_sects = boot_sector_sects + super_block_sects +
c00066d4:	8b 55 e0             	mov    -0x20(%ebp),%edx
c00066d7:	8b 45 dc             	mov    -0x24(%ebp),%eax
c00066da:	01 c2                	add    %eax,%edx
c00066dc:	8b 45 d8             	mov    -0x28(%ebp),%eax
c00066df:	01 c2                	add    %eax,%edx
c00066e1:	8b 45 d4             	mov    -0x2c(%ebp),%eax
c00066e4:	01 d0                	add    %edx,%eax
c00066e6:	89 45 d0             	mov    %eax,-0x30(%ebp)
                        inode_bitmap_sects + inode_table_sects;
  uint32_t free_sects = part->sec_cnt - used_sects;
c00066e9:	8b 45 0c             	mov    0xc(%ebp),%eax
c00066ec:	8b 40 04             	mov    0x4(%eax),%eax
c00066ef:	2b 45 d0             	sub    -0x30(%ebp),%eax
c00066f2:	89 45 cc             	mov    %eax,-0x34(%ebp)

  // 处理块位图占的扇区数【动态规划】
  uint32_t block_bitmap_sects = DIV_ROUND_UP(free_sects, BITS_PER_SECTOR);
c00066f5:	8b 45 cc             	mov    -0x34(%ebp),%eax
c00066f8:	05 ff 0f 00 00       	add    $0xfff,%eax
c00066fd:	c1 e8 0c             	shr    $0xc,%eax
c0006700:	89 45 c8             	mov    %eax,-0x38(%ebp)
  uint32_t block_bitmap_bit_len =
c0006703:	8b 45 cc             	mov    -0x34(%ebp),%eax
c0006706:	2b 45 c8             	sub    -0x38(%ebp),%eax
c0006709:	89 45 c4             	mov    %eax,-0x3c(%ebp)
      free_sects - block_bitmap_sects; // 位图中位的个数（真正的空闲块数）
  block_bitmap_sects = DIV_ROUND_UP(block_bitmap_bit_len, BITS_PER_SECTOR);
c000670c:	8b 45 c4             	mov    -0x3c(%ebp),%eax
c000670f:	05 ff 0f 00 00       	add    $0xfff,%eax
c0006714:	c1 e8 0c             	shr    $0xc,%eax
c0006717:	89 45 c8             	mov    %eax,-0x38(%ebp)

  // 超级块初始化
  struct super_block sb;
  sb.magic = 0x20021112;
c000671a:	c7 85 a8 fd ff ff 12 	movl   $0x20021112,-0x258(%ebp)
c0006721:	11 02 20 
  sb.sec_cnt = part->sec_cnt;
c0006724:	8b 45 0c             	mov    0xc(%ebp),%eax
c0006727:	8b 40 04             	mov    0x4(%eax),%eax
c000672a:	89 85 ac fd ff ff    	mov    %eax,-0x254(%ebp)
  sb.inode_cnt = MAX_FILES_PER_PART;
c0006730:	c7 85 b0 fd ff ff 00 	movl   $0x1000,-0x250(%ebp)
c0006737:	10 00 00 
  sb.part_lba_base = part->start_lba;
c000673a:	8b 45 0c             	mov    0xc(%ebp),%eax
c000673d:	8b 00                	mov    (%eax),%eax
c000673f:	89 85 b4 fd ff ff    	mov    %eax,-0x24c(%ebp)

  sb.block_bitmap_lba = sb.part_lba_base + 2; // 第0块是引导块，第1块是超级块
c0006745:	8b 85 b4 fd ff ff    	mov    -0x24c(%ebp),%eax
c000674b:	83 c0 02             	add    $0x2,%eax
c000674e:	89 85 b8 fd ff ff    	mov    %eax,-0x248(%ebp)
  sb.block_bitmap_sects = block_bitmap_sects;
c0006754:	8b 45 c8             	mov    -0x38(%ebp),%eax
c0006757:	89 85 bc fd ff ff    	mov    %eax,-0x244(%ebp)

  sb.inode_bitmap_lba = sb.block_bitmap_lba + sb.block_bitmap_sects;
c000675d:	8b 95 b8 fd ff ff    	mov    -0x248(%ebp),%edx
c0006763:	8b 85 bc fd ff ff    	mov    -0x244(%ebp),%eax
c0006769:	01 d0                	add    %edx,%eax
c000676b:	89 85 c0 fd ff ff    	mov    %eax,-0x240(%ebp)
  sb.inode_bitmap_sects = inode_bitmap_sects;
c0006771:	8b 45 d8             	mov    -0x28(%ebp),%eax
c0006774:	89 85 c4 fd ff ff    	mov    %eax,-0x23c(%ebp)

  sb.inode_table_lba = sb.inode_bitmap_lba + sb.inode_bitmap_sects;
c000677a:	8b 95 c0 fd ff ff    	mov    -0x240(%ebp),%edx
c0006780:	8b 85 c4 fd ff ff    	mov    -0x23c(%ebp),%eax
c0006786:	01 d0                	add    %edx,%eax
c0006788:	89 85 c8 fd ff ff    	mov    %eax,-0x238(%ebp)
  sb.inode_table_sects = inode_table_sects;
c000678e:	8b 45 d4             	mov    -0x2c(%ebp),%eax
c0006791:	89 85 cc fd ff ff    	mov    %eax,-0x234(%ebp)

  sb.data_start_lba = sb.inode_table_lba + sb.inode_table_sects;
c0006797:	8b 95 c8 fd ff ff    	mov    -0x238(%ebp),%edx
c000679d:	8b 85 cc fd ff ff    	mov    -0x234(%ebp),%eax
c00067a3:	01 d0                	add    %edx,%eax
c00067a5:	89 85 d0 fd ff ff    	mov    %eax,-0x230(%ebp)
  sb.root_inode_no = 0; // inode数组中第0个留给根目录
c00067ab:	c7 85 d4 fd ff ff 00 	movl   $0x0,-0x22c(%ebp)
c00067b2:	00 00 00 
  sb.dir_entry_size = sizeof(struct dir_entry);
c00067b5:	c7 85 d8 fd ff ff 18 	movl   $0x18,-0x228(%ebp)
c00067bc:	00 00 00 

  printk("%s info:\n", part->name);
c00067bf:	8b 45 0c             	mov    0xc(%ebp),%eax
c00067c2:	83 c0 14             	add    $0x14,%eax
c00067c5:	83 ec 08             	sub    $0x8,%esp
c00067c8:	50                   	push   %eax
c00067c9:	68 0b d1 00 c0       	push   $0xc000d10b
c00067ce:	e8 e1 ee ff ff       	call   c00056b4 <printk>
c00067d3:	83 c4 10             	add    $0x10,%esp
  printk("      magic : 0x%x\n      part_lba_base : 0x%x\n      all_sectors : "
c00067d6:	8b 95 d0 fd ff ff    	mov    -0x230(%ebp),%edx
c00067dc:	8b 9d cc fd ff ff    	mov    -0x234(%ebp),%ebx
c00067e2:	8b bd c8 fd ff ff    	mov    -0x238(%ebp),%edi
c00067e8:	8b 85 c4 fd ff ff    	mov    -0x23c(%ebp),%eax
c00067ee:	89 85 a4 fd ff ff    	mov    %eax,-0x25c(%ebp)
c00067f4:	8b b5 c0 fd ff ff    	mov    -0x240(%ebp),%esi
c00067fa:	89 b5 a0 fd ff ff    	mov    %esi,-0x260(%ebp)
c0006800:	8b 8d bc fd ff ff    	mov    -0x244(%ebp),%ecx
c0006806:	89 8d 9c fd ff ff    	mov    %ecx,-0x264(%ebp)
c000680c:	8b 85 b8 fd ff ff    	mov    -0x248(%ebp),%eax
c0006812:	89 85 98 fd ff ff    	mov    %eax,-0x268(%ebp)
c0006818:	8b b5 b0 fd ff ff    	mov    -0x250(%ebp),%esi
c000681e:	89 b5 94 fd ff ff    	mov    %esi,-0x26c(%ebp)
c0006824:	8b b5 ac fd ff ff    	mov    -0x254(%ebp),%esi
c000682a:	8b 8d b4 fd ff ff    	mov    -0x24c(%ebp),%ecx
c0006830:	8b 85 a8 fd ff ff    	mov    -0x258(%ebp),%eax
c0006836:	52                   	push   %edx
c0006837:	53                   	push   %ebx
c0006838:	57                   	push   %edi
c0006839:	ff b5 a4 fd ff ff    	push   -0x25c(%ebp)
c000683f:	ff b5 a0 fd ff ff    	push   -0x260(%ebp)
c0006845:	ff b5 9c fd ff ff    	push   -0x264(%ebp)
c000684b:	ff b5 98 fd ff ff    	push   -0x268(%ebp)
c0006851:	ff b5 94 fd ff ff    	push   -0x26c(%ebp)
c0006857:	56                   	push   %esi
c0006858:	51                   	push   %ecx
c0006859:	50                   	push   %eax
c000685a:	68 18 d1 00 c0       	push   $0xc000d118
c000685f:	e8 50 ee ff ff       	call   c00056b4 <printk>
c0006864:	83 c4 30             	add    $0x30,%esp
         sb.magic, sb.part_lba_base, sb.sec_cnt, sb.inode_cnt,
         sb.block_bitmap_lba, sb.block_bitmap_sects, sb.inode_bitmap_lba,
         sb.inode_bitmap_sects, sb.inode_table_lba, sb.inode_table_sects,
         sb.data_start_lba);

  hd = part->my_disk;
c0006867:	8b 45 0c             	mov    0xc(%ebp),%eax
c000686a:	8b 40 08             	mov    0x8(%eax),%eax
c000686d:	89 45 08             	mov    %eax,0x8(%ebp)
  /* 1、将超级块写入本分区的1扇区 */
  ide_write(hd, part->start_lba + 1, &sb, 1);
c0006870:	8b 45 0c             	mov    0xc(%ebp),%eax
c0006873:	8b 00                	mov    (%eax),%eax
c0006875:	8d 50 01             	lea    0x1(%eax),%edx
c0006878:	6a 01                	push   $0x1
c000687a:	8d 85 a8 fd ff ff    	lea    -0x258(%ebp),%eax
c0006880:	50                   	push   %eax
c0006881:	52                   	push   %edx
c0006882:	ff 75 08             	push   0x8(%ebp)
c0006885:	e8 15 f3 ff ff       	call   c0005b9f <ide_write>
c000688a:	83 c4 10             	add    $0x10,%esp
  printk("      super_block_lba : 0x%x\n", part->start_lba + 1);
c000688d:	8b 45 0c             	mov    0xc(%ebp),%eax
c0006890:	8b 00                	mov    (%eax),%eax
c0006892:	83 c0 01             	add    $0x1,%eax
c0006895:	83 ec 08             	sub    $0x8,%esp
c0006898:	50                   	push   %eax
c0006899:	68 48 d2 00 c0       	push   $0xc000d248
c000689e:	e8 11 ee ff ff       	call   c00056b4 <printk>
c00068a3:	83 c4 10             	add    $0x10,%esp

  // 用数据量最大的元信息尺寸做存储缓冲区
  uint32_t buf_size =
      (sb.block_bitmap_sects >= sb.inode_bitmap_sects ? sb.block_bitmap_sects
c00068a6:	8b 95 bc fd ff ff    	mov    -0x244(%ebp),%edx
c00068ac:	8b 85 c4 fd ff ff    	mov    -0x23c(%ebp),%eax
  uint32_t buf_size =
c00068b2:	39 c2                	cmp    %eax,%edx
c00068b4:	0f 43 c2             	cmovae %edx,%eax
c00068b7:	89 45 c0             	mov    %eax,-0x40(%ebp)
                                                      : sb.inode_bitmap_sects);
  buf_size =
      (buf_size >= sb.inode_table_sects ? buf_size : sb.inode_table_sects) *
c00068ba:	8b 95 cc fd ff ff    	mov    -0x234(%ebp),%edx
c00068c0:	8b 45 c0             	mov    -0x40(%ebp),%eax
c00068c3:	39 c2                	cmp    %eax,%edx
c00068c5:	0f 43 c2             	cmovae %edx,%eax
  buf_size =
c00068c8:	c1 e0 09             	shl    $0x9,%eax
c00068cb:	89 45 c0             	mov    %eax,-0x40(%ebp)
      SECTOR_SIZE;
  uint8_t *buf =
      (uint8_t *)sys_malloc(buf_size); // 申请的内存由内存管理系统清0后返回
c00068ce:	83 ec 0c             	sub    $0xc,%esp
c00068d1:	ff 75 c0             	push   -0x40(%ebp)
c00068d4:	e8 4b c7 ff ff       	call   c0003024 <sys_malloc>
c00068d9:	83 c4 10             	add    $0x10,%esp
c00068dc:	89 45 bc             	mov    %eax,-0x44(%ebp)

  /* 2、块位图初始化并写入磁盘 */
  buf[0] = 0x01; // （占位）第0个块预留给根目录
c00068df:	8b 45 bc             	mov    -0x44(%ebp),%eax
c00068e2:	c6 00 01             	movb   $0x1,(%eax)
  uint32_t block_bitmap_last_byte = block_bitmap_bit_len / 8;
c00068e5:	8b 45 c4             	mov    -0x3c(%ebp),%eax
c00068e8:	c1 e8 03             	shr    $0x3,%eax
c00068eb:	89 45 b8             	mov    %eax,-0x48(%ebp)
  uint8_t block_bitmap_last_bit = block_bitmap_bit_len % 8;
c00068ee:	8b 45 c4             	mov    -0x3c(%ebp),%eax
c00068f1:	83 e0 07             	and    $0x7,%eax
c00068f4:	88 45 b7             	mov    %al,-0x49(%ebp)
  uint32_t last_size = // 位图所在最后一个扇区中不足一扇区的其余部分
      SECTOR_SIZE - (block_bitmap_last_byte % SECTOR_SIZE);
c00068f7:	8b 45 b8             	mov    -0x48(%ebp),%eax
c00068fa:	25 ff 01 00 00       	and    $0x1ff,%eax
c00068ff:	89 c2                	mov    %eax,%edx
  uint32_t last_size = // 位图所在最后一个扇区中不足一扇区的其余部分
c0006901:	b8 00 02 00 00       	mov    $0x200,%eax
c0006906:	29 d0                	sub    %edx,%eax
c0006908:	89 45 b0             	mov    %eax,-0x50(%ebp)

  // 先将超出实际块数部分置为1已占用,再将覆盖的最后一字节内的有效位重新置0
  memset(&buf[block_bitmap_last_byte], 0xff, last_size);
c000690b:	8b 55 bc             	mov    -0x44(%ebp),%edx
c000690e:	8b 45 b8             	mov    -0x48(%ebp),%eax
c0006911:	01 d0                	add    %edx,%eax
c0006913:	83 ec 04             	sub    $0x4,%esp
c0006916:	ff 75 b0             	push   -0x50(%ebp)
c0006919:	68 ff 00 00 00       	push   $0xff
c000691e:	50                   	push   %eax
c000691f:	e8 8a ba ff ff       	call   c00023ae <memset>
c0006924:	83 c4 10             	add    $0x10,%esp
  uint8_t bit_idx = 0;
c0006927:	c6 45 e7 00          	movb   $0x0,-0x19(%ebp)
  while (bit_idx <= block_bitmap_last_bit) {
c000692b:	eb 3b                	jmp    c0006968 <partition_format+0x2bc>
    buf[block_bitmap_last_byte] &= ~(1 << bit_idx++);
c000692d:	0f b6 45 e7          	movzbl -0x19(%ebp),%eax
c0006931:	8d 50 01             	lea    0x1(%eax),%edx
c0006934:	88 55 e7             	mov    %dl,-0x19(%ebp)
c0006937:	0f b6 c0             	movzbl %al,%eax
c000693a:	ba 01 00 00 00       	mov    $0x1,%edx
c000693f:	89 c1                	mov    %eax,%ecx
c0006941:	d3 e2                	shl    %cl,%edx
c0006943:	89 d0                	mov    %edx,%eax
c0006945:	f7 d0                	not    %eax
c0006947:	89 c1                	mov    %eax,%ecx
c0006949:	8b 55 bc             	mov    -0x44(%ebp),%edx
c000694c:	8b 45 b8             	mov    -0x48(%ebp),%eax
c000694f:	01 d0                	add    %edx,%eax
c0006951:	0f b6 00             	movzbl (%eax),%eax
c0006954:	89 c2                	mov    %eax,%edx
c0006956:	89 c8                	mov    %ecx,%eax
c0006958:	89 d1                	mov    %edx,%ecx
c000695a:	21 c1                	and    %eax,%ecx
c000695c:	8b 55 bc             	mov    -0x44(%ebp),%edx
c000695f:	8b 45 b8             	mov    -0x48(%ebp),%eax
c0006962:	01 d0                	add    %edx,%eax
c0006964:	89 ca                	mov    %ecx,%edx
c0006966:	88 10                	mov    %dl,(%eax)
  while (bit_idx <= block_bitmap_last_bit) {
c0006968:	0f b6 45 e7          	movzbl -0x19(%ebp),%eax
c000696c:	3a 45 b7             	cmp    -0x49(%ebp),%al
c000696f:	76 bc                	jbe    c000692d <partition_format+0x281>
  }
  ide_write(hd, sb.block_bitmap_lba, buf, sb.block_bitmap_sects);
c0006971:	8b 95 bc fd ff ff    	mov    -0x244(%ebp),%edx
c0006977:	8b 85 b8 fd ff ff    	mov    -0x248(%ebp),%eax
c000697d:	52                   	push   %edx
c000697e:	ff 75 bc             	push   -0x44(%ebp)
c0006981:	50                   	push   %eax
c0006982:	ff 75 08             	push   0x8(%ebp)
c0006985:	e8 15 f2 ff ff       	call   c0005b9f <ide_write>
c000698a:	83 c4 10             	add    $0x10,%esp

  /* 3、inode位图初始化并写入磁盘 */
  memset(buf, 0, buf_size);
c000698d:	83 ec 04             	sub    $0x4,%esp
c0006990:	ff 75 c0             	push   -0x40(%ebp)
c0006993:	6a 00                	push   $0x0
c0006995:	ff 75 bc             	push   -0x44(%ebp)
c0006998:	e8 11 ba ff ff       	call   c00023ae <memset>
c000699d:	83 c4 10             	add    $0x10,%esp
  buf[0] |= 0x1; // 第0个inode给根目录
c00069a0:	8b 45 bc             	mov    -0x44(%ebp),%eax
c00069a3:	0f b6 00             	movzbl (%eax),%eax
c00069a6:	83 c8 01             	or     $0x1,%eax
c00069a9:	89 c2                	mov    %eax,%edx
c00069ab:	8b 45 bc             	mov    -0x44(%ebp),%eax
c00069ae:	88 10                	mov    %dl,(%eax)
  ide_write(hd, sb.inode_bitmap_lba, buf, sb.inode_bitmap_sects);
c00069b0:	8b 95 c4 fd ff ff    	mov    -0x23c(%ebp),%edx
c00069b6:	8b 85 c0 fd ff ff    	mov    -0x240(%ebp),%eax
c00069bc:	52                   	push   %edx
c00069bd:	ff 75 bc             	push   -0x44(%ebp)
c00069c0:	50                   	push   %eax
c00069c1:	ff 75 08             	push   0x8(%ebp)
c00069c4:	e8 d6 f1 ff ff       	call   c0005b9f <ide_write>
c00069c9:	83 c4 10             	add    $0x10,%esp

  /* 4、inode数组初始化并写入磁盘 */
  memset(buf, 0, buf_size);
c00069cc:	83 ec 04             	sub    $0x4,%esp
c00069cf:	ff 75 c0             	push   -0x40(%ebp)
c00069d2:	6a 00                	push   $0x0
c00069d4:	ff 75 bc             	push   -0x44(%ebp)
c00069d7:	e8 d2 b9 ff ff       	call   c00023ae <memset>
c00069dc:	83 c4 10             	add    $0x10,%esp
  struct inode *i = (struct inode *)buf;
c00069df:	8b 45 bc             	mov    -0x44(%ebp),%eax
c00069e2:	89 45 ac             	mov    %eax,-0x54(%ebp)
  i->i_size = sb.dir_entry_size * 2; // .和..
c00069e5:	8b 85 d8 fd ff ff    	mov    -0x228(%ebp),%eax
c00069eb:	8d 14 00             	lea    (%eax,%eax,1),%edx
c00069ee:	8b 45 ac             	mov    -0x54(%ebp),%eax
c00069f1:	89 50 04             	mov    %edx,0x4(%eax)
  i->i_no = 0;
c00069f4:	8b 45 ac             	mov    -0x54(%ebp),%eax
c00069f7:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
  i->i_sectors[0] = sb.data_start_lba;
c00069fd:	8b 95 d0 fd ff ff    	mov    -0x230(%ebp),%edx
c0006a03:	8b 45 ac             	mov    -0x54(%ebp),%eax
c0006a06:	89 50 10             	mov    %edx,0x10(%eax)
  ide_write(hd, sb.inode_table_lba, buf, sb.inode_table_sects);
c0006a09:	8b 95 cc fd ff ff    	mov    -0x234(%ebp),%edx
c0006a0f:	8b 85 c8 fd ff ff    	mov    -0x238(%ebp),%eax
c0006a15:	52                   	push   %edx
c0006a16:	ff 75 bc             	push   -0x44(%ebp)
c0006a19:	50                   	push   %eax
c0006a1a:	ff 75 08             	push   0x8(%ebp)
c0006a1d:	e8 7d f1 ff ff       	call   c0005b9f <ide_write>
c0006a22:	83 c4 10             	add    $0x10,%esp

  /* 5、把根目录（两个目录项.和..）写入磁盘 */
  memset(buf, 0, buf_size);
c0006a25:	83 ec 04             	sub    $0x4,%esp
c0006a28:	ff 75 c0             	push   -0x40(%ebp)
c0006a2b:	6a 00                	push   $0x0
c0006a2d:	ff 75 bc             	push   -0x44(%ebp)
c0006a30:	e8 79 b9 ff ff       	call   c00023ae <memset>
c0006a35:	83 c4 10             	add    $0x10,%esp
  struct dir_entry *p_de = (struct dir_entry *)buf;
c0006a38:	8b 45 bc             	mov    -0x44(%ebp),%eax
c0006a3b:	89 45 a8             	mov    %eax,-0x58(%ebp)

  // 初始化当前目录.
  memcpy(p_de->filename, ".", 1);
c0006a3e:	8b 45 a8             	mov    -0x58(%ebp),%eax
c0006a41:	83 ec 04             	sub    $0x4,%esp
c0006a44:	6a 01                	push   $0x1
c0006a46:	68 66 d2 00 c0       	push   $0xc000d266
c0006a4b:	50                   	push   %eax
c0006a4c:	e8 b0 b9 ff ff       	call   c0002401 <memcpy>
c0006a51:	83 c4 10             	add    $0x10,%esp
  p_de->i_no = 0;
c0006a54:	8b 45 a8             	mov    -0x58(%ebp),%eax
c0006a57:	c7 40 10 00 00 00 00 	movl   $0x0,0x10(%eax)
  p_de->f_type = FT_DIRECTORY;
c0006a5e:	8b 45 a8             	mov    -0x58(%ebp),%eax
c0006a61:	c7 40 14 02 00 00 00 	movl   $0x2,0x14(%eax)
  p_de++;
c0006a68:	83 45 a8 18          	addl   $0x18,-0x58(%ebp)

  // 初始化当前目录父目录..
  memcpy(p_de->filename, "..", 2);
c0006a6c:	8b 45 a8             	mov    -0x58(%ebp),%eax
c0006a6f:	83 ec 04             	sub    $0x4,%esp
c0006a72:	6a 02                	push   $0x2
c0006a74:	68 68 d2 00 c0       	push   $0xc000d268
c0006a79:	50                   	push   %eax
c0006a7a:	e8 82 b9 ff ff       	call   c0002401 <memcpy>
c0006a7f:	83 c4 10             	add    $0x10,%esp
  p_de->i_no = 0;
c0006a82:	8b 45 a8             	mov    -0x58(%ebp),%eax
c0006a85:	c7 40 10 00 00 00 00 	movl   $0x0,0x10(%eax)
  p_de->f_type = FT_DIRECTORY;
c0006a8c:	8b 45 a8             	mov    -0x58(%ebp),%eax
c0006a8f:	c7 40 14 02 00 00 00 	movl   $0x2,0x14(%eax)
  ide_write(hd, sb.data_start_lba, buf, 1);
c0006a96:	8b 85 d0 fd ff ff    	mov    -0x230(%ebp),%eax
c0006a9c:	6a 01                	push   $0x1
c0006a9e:	ff 75 bc             	push   -0x44(%ebp)
c0006aa1:	50                   	push   %eax
c0006aa2:	ff 75 08             	push   0x8(%ebp)
c0006aa5:	e8 f5 f0 ff ff       	call   c0005b9f <ide_write>
c0006aaa:	83 c4 10             	add    $0x10,%esp

  printk("root_dir_lba : 0x%x\n", sb.data_start_lba);
c0006aad:	8b 85 d0 fd ff ff    	mov    -0x230(%ebp),%eax
c0006ab3:	83 ec 08             	sub    $0x8,%esp
c0006ab6:	50                   	push   %eax
c0006ab7:	68 6b d2 00 c0       	push   $0xc000d26b
c0006abc:	e8 f3 eb ff ff       	call   c00056b4 <printk>
c0006ac1:	83 c4 10             	add    $0x10,%esp
  printk("%s format done\n", part->name);
c0006ac4:	8b 45 0c             	mov    0xc(%ebp),%eax
c0006ac7:	83 c0 14             	add    $0x14,%eax
c0006aca:	83 ec 08             	sub    $0x8,%esp
c0006acd:	50                   	push   %eax
c0006ace:	68 80 d2 00 c0       	push   $0xc000d280
c0006ad3:	e8 dc eb ff ff       	call   c00056b4 <printk>
c0006ad8:	83 c4 10             	add    $0x10,%esp

  sys_free(buf); // 释放缓冲区
c0006adb:	83 ec 0c             	sub    $0xc,%esp
c0006ade:	ff 75 bc             	push   -0x44(%ebp)
c0006ae1:	e8 5d cb ff ff       	call   c0003643 <sys_free>
c0006ae6:	83 c4 10             	add    $0x10,%esp
}
c0006ae9:	90                   	nop
c0006aea:	8d 65 f4             	lea    -0xc(%ebp),%esp
c0006aed:	5b                   	pop    %ebx
c0006aee:	5e                   	pop    %esi
c0006aef:	5f                   	pop    %edi
c0006af0:	5d                   	pop    %ebp
c0006af1:	c3                   	ret    

c0006af2 <path_parse>:

// 将最上层路径名解析出来（类似pop
static char *path_parse(char *pathname, char *name_store) {
c0006af2:	55                   	push   %ebp
c0006af3:	89 e5                	mov    %esp,%ebp
  if (pathname[0] == '/') { // 跳过'/'
c0006af5:	8b 45 08             	mov    0x8(%ebp),%eax
c0006af8:	0f b6 00             	movzbl (%eax),%eax
c0006afb:	3c 2f                	cmp    $0x2f,%al
c0006afd:	75 28                	jne    c0006b27 <path_parse+0x35>
    while (*(++pathname) == '/') {
c0006aff:	90                   	nop
c0006b00:	83 45 08 01          	addl   $0x1,0x8(%ebp)
c0006b04:	8b 45 08             	mov    0x8(%ebp),%eax
c0006b07:	0f b6 00             	movzbl (%eax),%eax
c0006b0a:	3c 2f                	cmp    $0x2f,%al
c0006b0c:	74 f2                	je     c0006b00 <path_parse+0xe>
    }
  }

  // 一般路径解析
  while (*pathname != '/' && *pathname != 0) {
c0006b0e:	eb 17                	jmp    c0006b27 <path_parse+0x35>
    *name_store++ = *pathname++;
c0006b10:	8b 55 08             	mov    0x8(%ebp),%edx
c0006b13:	8d 42 01             	lea    0x1(%edx),%eax
c0006b16:	89 45 08             	mov    %eax,0x8(%ebp)
c0006b19:	8b 45 0c             	mov    0xc(%ebp),%eax
c0006b1c:	8d 48 01             	lea    0x1(%eax),%ecx
c0006b1f:	89 4d 0c             	mov    %ecx,0xc(%ebp)
c0006b22:	0f b6 12             	movzbl (%edx),%edx
c0006b25:	88 10                	mov    %dl,(%eax)
  while (*pathname != '/' && *pathname != 0) {
c0006b27:	8b 45 08             	mov    0x8(%ebp),%eax
c0006b2a:	0f b6 00             	movzbl (%eax),%eax
c0006b2d:	3c 2f                	cmp    $0x2f,%al
c0006b2f:	74 0a                	je     c0006b3b <path_parse+0x49>
c0006b31:	8b 45 08             	mov    0x8(%ebp),%eax
c0006b34:	0f b6 00             	movzbl (%eax),%eax
c0006b37:	84 c0                	test   %al,%al
c0006b39:	75 d5                	jne    c0006b10 <path_parse+0x1e>
  }
  if (pathname[0] == 0) { // 路径字符串为空
c0006b3b:	8b 45 08             	mov    0x8(%ebp),%eax
c0006b3e:	0f b6 00             	movzbl (%eax),%eax
c0006b41:	84 c0                	test   %al,%al
c0006b43:	75 07                	jne    c0006b4c <path_parse+0x5a>
    return NULL;
c0006b45:	b8 00 00 00 00       	mov    $0x0,%eax
c0006b4a:	eb 03                	jmp    c0006b4f <path_parse+0x5d>
  }
  return pathname;
c0006b4c:	8b 45 08             	mov    0x8(%ebp),%eax
}
c0006b4f:	5d                   	pop    %ebp
c0006b50:	c3                   	ret    

c0006b51 <path_depth_cnt>:

// 返回路径深度
int32_t path_depth_cnt(char *pathname) {
c0006b51:	55                   	push   %ebp
c0006b52:	89 e5                	mov    %esp,%ebp
c0006b54:	83 ec 28             	sub    $0x28,%esp
  ASSERT(pathname != NULL);
c0006b57:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c0006b5b:	75 1c                	jne    c0006b79 <path_depth_cnt+0x28>
c0006b5d:	68 90 d2 00 c0       	push   $0xc000d290
c0006b62:	68 e4 d8 00 c0       	push   $0xc000d8e4
c0006b67:	68 cc 00 00 00       	push   $0xcc
c0006b6c:	68 dd d0 00 c0       	push   $0xc000d0dd
c0006b71:	e8 62 b7 ff ff       	call   c00022d8 <panic_spin>
c0006b76:	83 c4 10             	add    $0x10,%esp
  char *p = pathname;
c0006b79:	8b 45 08             	mov    0x8(%ebp),%eax
c0006b7c:	89 45 f4             	mov    %eax,-0xc(%ebp)
  char name[MAX_FILE_NAME_LEN];
  uint32_t depth = 0;
c0006b7f:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)

  // 解析路径，从中拆分出各级名称
  p = path_parse(p, name);
c0006b86:	83 ec 08             	sub    $0x8,%esp
c0006b89:	8d 45 e0             	lea    -0x20(%ebp),%eax
c0006b8c:	50                   	push   %eax
c0006b8d:	ff 75 f4             	push   -0xc(%ebp)
c0006b90:	e8 5d ff ff ff       	call   c0006af2 <path_parse>
c0006b95:	83 c4 10             	add    $0x10,%esp
c0006b98:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while (name[0]) {
c0006b9b:	eb 32                	jmp    c0006bcf <path_depth_cnt+0x7e>
    depth++;
c0006b9d:	83 45 f0 01          	addl   $0x1,-0x10(%ebp)
    memset(name, 0, MAX_FILE_NAME_LEN);
c0006ba1:	83 ec 04             	sub    $0x4,%esp
c0006ba4:	6a 10                	push   $0x10
c0006ba6:	6a 00                	push   $0x0
c0006ba8:	8d 45 e0             	lea    -0x20(%ebp),%eax
c0006bab:	50                   	push   %eax
c0006bac:	e8 fd b7 ff ff       	call   c00023ae <memset>
c0006bb1:	83 c4 10             	add    $0x10,%esp
    if (p) { // p非空就继续分析路径
c0006bb4:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
c0006bb8:	74 15                	je     c0006bcf <path_depth_cnt+0x7e>
      p = path_parse(p, name);
c0006bba:	83 ec 08             	sub    $0x8,%esp
c0006bbd:	8d 45 e0             	lea    -0x20(%ebp),%eax
c0006bc0:	50                   	push   %eax
c0006bc1:	ff 75 f4             	push   -0xc(%ebp)
c0006bc4:	e8 29 ff ff ff       	call   c0006af2 <path_parse>
c0006bc9:	83 c4 10             	add    $0x10,%esp
c0006bcc:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while (name[0]) {
c0006bcf:	0f b6 45 e0          	movzbl -0x20(%ebp),%eax
c0006bd3:	84 c0                	test   %al,%al
c0006bd5:	75 c6                	jne    c0006b9d <path_depth_cnt+0x4c>
    }
  }
  return depth;
c0006bd7:	8b 45 f0             	mov    -0x10(%ebp),%eax
}
c0006bda:	c9                   	leave  
c0006bdb:	c3                   	ret    

c0006bdc <search_file>:

// 搜索文件,找到返回inode号,保证父目录打开
static int search_file(const char *pathname,
                       struct path_search_record *searched_record) {
c0006bdc:	55                   	push   %ebp
c0006bdd:	89 e5                	mov    %esp,%ebp
c0006bdf:	83 ec 48             	sub    $0x48,%esp
  // 待查找的是根目录
  if (!strcmp(pathname, "/") || !strcmp(pathname, "/.") ||
c0006be2:	83 ec 08             	sub    $0x8,%esp
c0006be5:	68 a1 d2 00 c0       	push   $0xc000d2a1
c0006bea:	ff 75 08             	push   0x8(%ebp)
c0006bed:	e8 8f b9 ff ff       	call   c0002581 <strcmp>
c0006bf2:	83 c4 10             	add    $0x10,%esp
c0006bf5:	84 c0                	test   %al,%al
c0006bf7:	74 2e                	je     c0006c27 <search_file+0x4b>
c0006bf9:	83 ec 08             	sub    $0x8,%esp
c0006bfc:	68 a3 d2 00 c0       	push   $0xc000d2a3
c0006c01:	ff 75 08             	push   0x8(%ebp)
c0006c04:	e8 78 b9 ff ff       	call   c0002581 <strcmp>
c0006c09:	83 c4 10             	add    $0x10,%esp
c0006c0c:	84 c0                	test   %al,%al
c0006c0e:	74 17                	je     c0006c27 <search_file+0x4b>
      !strcmp(pathname, "/..")) {
c0006c10:	83 ec 08             	sub    $0x8,%esp
c0006c13:	68 a6 d2 00 c0       	push   $0xc000d2a6
c0006c18:	ff 75 08             	push   0x8(%ebp)
c0006c1b:	e8 61 b9 ff ff       	call   c0002581 <strcmp>
c0006c20:	83 c4 10             	add    $0x10,%esp
  if (!strcmp(pathname, "/") || !strcmp(pathname, "/.") ||
c0006c23:	84 c0                	test   %al,%al
c0006c25:	75 2a                	jne    c0006c51 <search_file+0x75>
    searched_record->parent_dir = &root_dir;
c0006c27:	8b 45 0c             	mov    0xc(%ebp),%eax
c0006c2a:	c7 80 00 02 00 00 e0 	movl   $0xc00129e0,0x200(%eax)
c0006c31:	29 01 c0 
    searched_record->file_type = FT_DIRECTORY;
c0006c34:	8b 45 0c             	mov    0xc(%ebp),%eax
c0006c37:	c7 80 04 02 00 00 02 	movl   $0x2,0x204(%eax)
c0006c3e:	00 00 00 
    searched_record->searched_path[0] = 0; // 搜索路径置空
c0006c41:	8b 45 0c             	mov    0xc(%ebp),%eax
c0006c44:	c6 00 00             	movb   $0x0,(%eax)
    return 0;
c0006c47:	b8 00 00 00 00       	mov    $0x0,%eax
c0006c4c:	e9 06 02 00 00       	jmp    c0006e57 <search_file+0x27b>
  }

  uint32_t path_len = strlen(pathname);
c0006c51:	83 ec 0c             	sub    $0xc,%esp
c0006c54:	ff 75 08             	push   0x8(%ebp)
c0006c57:	e8 de b8 ff ff       	call   c000253a <strlen>
c0006c5c:	83 c4 10             	add    $0x10,%esp
c0006c5f:	89 45 e8             	mov    %eax,-0x18(%ebp)
  ASSERT(pathname[0] == '/' && path_len > 1 && path_len < MAX_PATH_LEN);
c0006c62:	8b 45 08             	mov    0x8(%ebp),%eax
c0006c65:	0f b6 00             	movzbl (%eax),%eax
c0006c68:	3c 2f                	cmp    $0x2f,%al
c0006c6a:	75 0f                	jne    c0006c7b <search_file+0x9f>
c0006c6c:	83 7d e8 01          	cmpl   $0x1,-0x18(%ebp)
c0006c70:	76 09                	jbe    c0006c7b <search_file+0x9f>
c0006c72:	81 7d e8 ff 01 00 00 	cmpl   $0x1ff,-0x18(%ebp)
c0006c79:	76 1c                	jbe    c0006c97 <search_file+0xbb>
c0006c7b:	68 ac d2 00 c0       	push   $0xc000d2ac
c0006c80:	68 f4 d8 00 c0       	push   $0xc000d8f4
c0006c85:	68 ea 00 00 00       	push   $0xea
c0006c8a:	68 dd d0 00 c0       	push   $0xc000d0dd
c0006c8f:	e8 44 b6 ff ff       	call   c00022d8 <panic_spin>
c0006c94:	83 c4 10             	add    $0x10,%esp
  char *sub_path = (char *)pathname;
c0006c97:	8b 45 08             	mov    0x8(%ebp),%eax
c0006c9a:	89 45 f4             	mov    %eax,-0xc(%ebp)
  struct dir *parent_dir = &root_dir;
c0006c9d:	c7 45 f0 e0 29 01 c0 	movl   $0xc00129e0,-0x10(%ebp)
  struct dir_entry dir_e;
  char name[MAX_FILE_NAME_LEN] = {0}; // 记录路径解析出来的各级名称
c0006ca4:	c7 45 c0 00 00 00 00 	movl   $0x0,-0x40(%ebp)
c0006cab:	c7 45 c4 00 00 00 00 	movl   $0x0,-0x3c(%ebp)
c0006cb2:	c7 45 c8 00 00 00 00 	movl   $0x0,-0x38(%ebp)
c0006cb9:	c7 45 cc 00 00 00 00 	movl   $0x0,-0x34(%ebp)

  searched_record->parent_dir = parent_dir;
c0006cc0:	8b 45 0c             	mov    0xc(%ebp),%eax
c0006cc3:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0006cc6:	89 90 00 02 00 00    	mov    %edx,0x200(%eax)
  searched_record->file_type = FT_UNKNOWN;
c0006ccc:	8b 45 0c             	mov    0xc(%ebp),%eax
c0006ccf:	c7 80 04 02 00 00 00 	movl   $0x0,0x204(%eax)
c0006cd6:	00 00 00 
  uint32_t parent_inode_no = 0;
c0006cd9:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%ebp)
  /*
   * input->/a/b/c  output->  [name]a; [sub_path]/b/c
   */
  sub_path = path_parse(sub_path, name);
c0006ce0:	83 ec 08             	sub    $0x8,%esp
c0006ce3:	8d 45 c0             	lea    -0x40(%ebp),%eax
c0006ce6:	50                   	push   %eax
c0006ce7:	ff 75 f4             	push   -0xc(%ebp)
c0006cea:	e8 03 fe ff ff       	call   c0006af2 <path_parse>
c0006cef:	83 c4 10             	add    $0x10,%esp
c0006cf2:	89 45 f4             	mov    %eax,-0xc(%ebp)

  while (name[0]) {
c0006cf5:	e9 0f 01 00 00       	jmp    c0006e09 <search_file+0x22d>
    ASSERT(strlen(searched_record->searched_path) < 512);
c0006cfa:	8b 45 0c             	mov    0xc(%ebp),%eax
c0006cfd:	83 ec 0c             	sub    $0xc,%esp
c0006d00:	50                   	push   %eax
c0006d01:	e8 34 b8 ff ff       	call   c000253a <strlen>
c0006d06:	83 c4 10             	add    $0x10,%esp
c0006d09:	3d ff 01 00 00       	cmp    $0x1ff,%eax
c0006d0e:	76 1c                	jbe    c0006d2c <search_file+0x150>
c0006d10:	68 ec d2 00 c0       	push   $0xc000d2ec
c0006d15:	68 f4 d8 00 c0       	push   $0xc000d8f4
c0006d1a:	68 f9 00 00 00       	push   $0xf9
c0006d1f:	68 dd d0 00 c0       	push   $0xc000d0dd
c0006d24:	e8 af b5 ff ff       	call   c00022d8 <panic_spin>
c0006d29:	83 c4 10             	add    $0x10,%esp

    // 记录已存在的父目录
    strcat(searched_record->searched_path, "/");
c0006d2c:	8b 45 0c             	mov    0xc(%ebp),%eax
c0006d2f:	83 ec 08             	sub    $0x8,%esp
c0006d32:	68 a1 d2 00 c0       	push   $0xc000d2a1
c0006d37:	50                   	push   %eax
c0006d38:	e8 73 b9 ff ff       	call   c00026b0 <strcat>
c0006d3d:	83 c4 10             	add    $0x10,%esp
    strcat(searched_record->searched_path, name);
c0006d40:	8b 45 0c             	mov    0xc(%ebp),%eax
c0006d43:	83 ec 08             	sub    $0x8,%esp
c0006d46:	8d 55 c0             	lea    -0x40(%ebp),%edx
c0006d49:	52                   	push   %edx
c0006d4a:	50                   	push   %eax
c0006d4b:	e8 60 b9 ff ff       	call   c00026b0 <strcat>
c0006d50:	83 c4 10             	add    $0x10,%esp

    // 在所给目录中查找文件
    if (search_dir_entry(cur_part, parent_dir, name, &dir_e)) {
c0006d53:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0006d58:	8d 55 d0             	lea    -0x30(%ebp),%edx
c0006d5b:	52                   	push   %edx
c0006d5c:	8d 55 c0             	lea    -0x40(%ebp),%edx
c0006d5f:	52                   	push   %edx
c0006d60:	ff 75 f0             	push   -0x10(%ebp)
c0006d63:	50                   	push   %eax
c0006d64:	e8 eb 1e 00 00       	call   c0008c54 <search_dir_entry>
c0006d69:	83 c4 10             	add    $0x10,%esp
c0006d6c:	85 c0                	test   %eax,%eax
c0006d6e:	0f 84 8e 00 00 00    	je     c0006e02 <search_file+0x226>
      memset(name, 0, MAX_FILE_NAME_LEN);
c0006d74:	83 ec 04             	sub    $0x4,%esp
c0006d77:	6a 10                	push   $0x10
c0006d79:	6a 00                	push   $0x0
c0006d7b:	8d 45 c0             	lea    -0x40(%ebp),%eax
c0006d7e:	50                   	push   %eax
c0006d7f:	e8 2a b6 ff ff       	call   c00023ae <memset>
c0006d84:	83 c4 10             	add    $0x10,%esp
      if (sub_path) { // sub_path不为空，未结束，继续拆分
c0006d87:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
c0006d8b:	74 15                	je     c0006da2 <search_file+0x1c6>
        sub_path = path_parse(sub_path, name);
c0006d8d:	83 ec 08             	sub    $0x8,%esp
c0006d90:	8d 45 c0             	lea    -0x40(%ebp),%eax
c0006d93:	50                   	push   %eax
c0006d94:	ff 75 f4             	push   -0xc(%ebp)
c0006d97:	e8 56 fd ff ff       	call   c0006af2 <path_parse>
c0006d9c:	83 c4 10             	add    $0x10,%esp
c0006d9f:	89 45 f4             	mov    %eax,-0xc(%ebp)
      }

      if (FT_DIRECTORY == dir_e.f_type) { // 目录
c0006da2:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0006da5:	83 f8 02             	cmp    $0x2,%eax
c0006da8:	75 3e                	jne    c0006de8 <search_file+0x20c>
        parent_inode_no = parent_dir->inode->i_no;
c0006daa:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0006dad:	8b 00                	mov    (%eax),%eax
c0006daf:	8b 00                	mov    (%eax),%eax
c0006db1:	89 45 ec             	mov    %eax,-0x14(%ebp)
        dir_close(parent_dir);
c0006db4:	83 ec 0c             	sub    $0xc,%esp
c0006db7:	ff 75 f0             	push   -0x10(%ebp)
c0006dba:	e8 6d 20 00 00       	call   c0008e2c <dir_close>
c0006dbf:	83 c4 10             	add    $0x10,%esp
        parent_dir = dir_open(cur_part, dir_e.i_no); // 更新父目录
c0006dc2:	8b 55 e0             	mov    -0x20(%ebp),%edx
c0006dc5:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0006dca:	83 ec 08             	sub    $0x8,%esp
c0006dcd:	52                   	push   %edx
c0006dce:	50                   	push   %eax
c0006dcf:	e8 42 1e 00 00       	call   c0008c16 <dir_open>
c0006dd4:	83 c4 10             	add    $0x10,%esp
c0006dd7:	89 45 f0             	mov    %eax,-0x10(%ebp)
        searched_record->parent_dir = parent_dir;
c0006dda:	8b 45 0c             	mov    0xc(%ebp),%eax
c0006ddd:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0006de0:	89 90 00 02 00 00    	mov    %edx,0x200(%eax)
        continue;
c0006de6:	eb 21                	jmp    c0006e09 <search_file+0x22d>
      } else if (FT_REGULAR == dir_e.f_type) { // 普通文件
c0006de8:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0006deb:	83 f8 01             	cmp    $0x1,%eax
c0006dee:	75 19                	jne    c0006e09 <search_file+0x22d>
        searched_record->file_type = FT_REGULAR;
c0006df0:	8b 45 0c             	mov    0xc(%ebp),%eax
c0006df3:	c7 80 04 02 00 00 01 	movl   $0x1,0x204(%eax)
c0006dfa:	00 00 00 
        return dir_e.i_no;
c0006dfd:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0006e00:	eb 55                	jmp    c0006e57 <search_file+0x27b>
      }
    } else { // 找不到目录项也要留着parent_dir不要关闭，创建新文件需要在parent_dir中创
      return -1;
c0006e02:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c0006e07:	eb 4e                	jmp    c0006e57 <search_file+0x27b>
  while (name[0]) {
c0006e09:	0f b6 45 c0          	movzbl -0x40(%ebp),%eax
c0006e0d:	84 c0                	test   %al,%al
c0006e0f:	0f 85 e5 fe ff ff    	jne    c0006cfa <search_file+0x11e>
    }
  }

  // 执行到此，必然是遍历了完整路径，且查找的文件/目录存在
  dir_close(searched_record->parent_dir);
c0006e15:	8b 45 0c             	mov    0xc(%ebp),%eax
c0006e18:	8b 80 00 02 00 00    	mov    0x200(%eax),%eax
c0006e1e:	83 ec 0c             	sub    $0xc,%esp
c0006e21:	50                   	push   %eax
c0006e22:	e8 05 20 00 00       	call   c0008e2c <dir_close>
c0006e27:	83 c4 10             	add    $0x10,%esp
  // 保存被查找目录的直接父目录
  searched_record->parent_dir = dir_open(cur_part, parent_inode_no);
c0006e2a:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0006e2f:	83 ec 08             	sub    $0x8,%esp
c0006e32:	ff 75 ec             	push   -0x14(%ebp)
c0006e35:	50                   	push   %eax
c0006e36:	e8 db 1d 00 00       	call   c0008c16 <dir_open>
c0006e3b:	83 c4 10             	add    $0x10,%esp
c0006e3e:	8b 55 0c             	mov    0xc(%ebp),%edx
c0006e41:	89 82 00 02 00 00    	mov    %eax,0x200(%edx)
  searched_record->file_type = FT_DIRECTORY;
c0006e47:	8b 45 0c             	mov    0xc(%ebp),%eax
c0006e4a:	c7 80 04 02 00 00 02 	movl   $0x2,0x204(%eax)
c0006e51:	00 00 00 
  return dir_e.i_no;
c0006e54:	8b 45 e0             	mov    -0x20(%ebp),%eax
}
c0006e57:	c9                   	leave  
c0006e58:	c3                   	ret    

c0006e59 <sys_create>:

// 创建文件
int32_t sys_create(const char *pathname) {
c0006e59:	55                   	push   %ebp
c0006e5a:	89 e5                	mov    %esp,%ebp
  // TODO：sys_create创建文件后文件需保持关闭状态
  return 0;
c0006e5c:	b8 00 00 00 00       	mov    $0x0,%eax
}
c0006e61:	5d                   	pop    %ebp
c0006e62:	c3                   	ret    

c0006e63 <sys_open>:

// 打开/创建文件，成功返回文件描述符fd
int32_t sys_open(const char *pathname, uint8_t flags) {
c0006e63:	55                   	push   %ebp
c0006e64:	89 e5                	mov    %esp,%ebp
c0006e66:	53                   	push   %ebx
c0006e67:	81 ec 34 02 00 00    	sub    $0x234,%esp
c0006e6d:	8b 45 0c             	mov    0xc(%ebp),%eax
c0006e70:	88 85 d4 fd ff ff    	mov    %al,-0x22c(%ebp)
  if (pathname[strlen(pathname) - 1] == '/') { // 目录不行
c0006e76:	83 ec 0c             	sub    $0xc,%esp
c0006e79:	ff 75 08             	push   0x8(%ebp)
c0006e7c:	e8 b9 b6 ff ff       	call   c000253a <strlen>
c0006e81:	83 c4 10             	add    $0x10,%esp
c0006e84:	8d 50 ff             	lea    -0x1(%eax),%edx
c0006e87:	8b 45 08             	mov    0x8(%ebp),%eax
c0006e8a:	01 d0                	add    %edx,%eax
c0006e8c:	0f b6 00             	movzbl (%eax),%eax
c0006e8f:	3c 2f                	cmp    $0x2f,%al
c0006e91:	75 1d                	jne    c0006eb0 <sys_open+0x4d>
    printk("can`t open a directory %s\n", pathname);
c0006e93:	83 ec 08             	sub    $0x8,%esp
c0006e96:	ff 75 08             	push   0x8(%ebp)
c0006e99:	68 19 d3 00 c0       	push   $0xc000d319
c0006e9e:	e8 11 e8 ff ff       	call   c00056b4 <printk>
c0006ea3:	83 c4 10             	add    $0x10,%esp
    return -1;
c0006ea6:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c0006eab:	e9 10 02 00 00       	jmp    c00070c0 <sys_open+0x25d>
  }
  ASSERT(flags <= 7);
c0006eb0:	80 bd d4 fd ff ff 07 	cmpb   $0x7,-0x22c(%ebp)
c0006eb7:	76 1c                	jbe    c0006ed5 <sys_open+0x72>
c0006eb9:	68 34 d3 00 c0       	push   $0xc000d334
c0006ebe:	68 00 d9 00 c0       	push   $0xc000d900
c0006ec3:	68 29 01 00 00       	push   $0x129
c0006ec8:	68 dd d0 00 c0       	push   $0xc000d0dd
c0006ecd:	e8 06 b4 ff ff       	call   c00022d8 <panic_spin>
c0006ed2:	83 c4 10             	add    $0x10,%esp
  int32_t fd = -1;
c0006ed5:	c7 45 f4 ff ff ff ff 	movl   $0xffffffff,-0xc(%ebp)

  struct path_search_record searched_record;
  memset(&searched_record, 0, sizeof(struct path_search_record));
c0006edc:	83 ec 04             	sub    $0x4,%esp
c0006edf:	68 08 02 00 00       	push   $0x208
c0006ee4:	6a 00                	push   $0x0
c0006ee6:	8d 85 dc fd ff ff    	lea    -0x224(%ebp),%eax
c0006eec:	50                   	push   %eax
c0006eed:	e8 bc b4 ff ff       	call   c00023ae <memset>
c0006ef2:	83 c4 10             	add    $0x10,%esp
  uint32_t pathname_depth = path_depth_cnt((char *)pathname); // 总目录深度
c0006ef5:	83 ec 0c             	sub    $0xc,%esp
c0006ef8:	ff 75 08             	push   0x8(%ebp)
c0006efb:	e8 51 fc ff ff       	call   c0006b51 <path_depth_cnt>
c0006f00:	83 c4 10             	add    $0x10,%esp
c0006f03:	89 45 f0             	mov    %eax,-0x10(%ebp)

  // 检查文件是否存在
  int inode_no = search_file(pathname, &searched_record);
c0006f06:	83 ec 08             	sub    $0x8,%esp
c0006f09:	8d 85 dc fd ff ff    	lea    -0x224(%ebp),%eax
c0006f0f:	50                   	push   %eax
c0006f10:	ff 75 08             	push   0x8(%ebp)
c0006f13:	e8 c4 fc ff ff       	call   c0006bdc <search_file>
c0006f18:	83 c4 10             	add    $0x10,%esp
c0006f1b:	89 45 ec             	mov    %eax,-0x14(%ebp)
  bool found = inode_no != -1 ? true : false;
c0006f1e:	83 7d ec ff          	cmpl   $0xffffffff,-0x14(%ebp)
c0006f22:	0f 95 c0             	setne  %al
c0006f25:	0f b6 c0             	movzbl %al,%eax
c0006f28:	89 45 e8             	mov    %eax,-0x18(%ebp)

  if (searched_record.file_type == FT_DIRECTORY) {
c0006f2b:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0006f2e:	83 f8 02             	cmp    $0x2,%eax
c0006f31:	75 29                	jne    c0006f5c <sys_open+0xf9>
    printk("can`t open a direcotry with open(), use opendir() to instead\n");
c0006f33:	83 ec 0c             	sub    $0xc,%esp
c0006f36:	68 40 d3 00 c0       	push   $0xc000d340
c0006f3b:	e8 74 e7 ff ff       	call   c00056b4 <printk>
c0006f40:	83 c4 10             	add    $0x10,%esp
    dir_close(searched_record.parent_dir);
c0006f43:	8b 45 dc             	mov    -0x24(%ebp),%eax
c0006f46:	83 ec 0c             	sub    $0xc,%esp
c0006f49:	50                   	push   %eax
c0006f4a:	e8 dd 1e 00 00       	call   c0008e2c <dir_close>
c0006f4f:	83 c4 10             	add    $0x10,%esp
    return -1;
c0006f52:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c0006f57:	e9 64 01 00 00       	jmp    c00070c0 <sys_open+0x25d>
  }

  uint32_t path_searched_depth = path_depth_cnt(searched_record.searched_path);
c0006f5c:	83 ec 0c             	sub    $0xc,%esp
c0006f5f:	8d 85 dc fd ff ff    	lea    -0x224(%ebp),%eax
c0006f65:	50                   	push   %eax
c0006f66:	e8 e6 fb ff ff       	call   c0006b51 <path_depth_cnt>
c0006f6b:	83 c4 10             	add    $0x10,%esp
c0006f6e:	89 45 e4             	mov    %eax,-0x1c(%ebp)

  // 是否在某个中间目录就失败了
  if (pathname_depth != path_searched_depth) {
c0006f71:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0006f74:	3b 45 e4             	cmp    -0x1c(%ebp),%eax
c0006f77:	74 33                	je     c0006fac <sys_open+0x149>
    printk("cannot access %s: Not a directory, subpath %s is’t exist\n",
c0006f79:	83 ec 04             	sub    $0x4,%esp
c0006f7c:	8d 85 dc fd ff ff    	lea    -0x224(%ebp),%eax
c0006f82:	50                   	push   %eax
c0006f83:	ff 75 08             	push   0x8(%ebp)
c0006f86:	68 80 d3 00 c0       	push   $0xc000d380
c0006f8b:	e8 24 e7 ff ff       	call   c00056b4 <printk>
c0006f90:	83 c4 10             	add    $0x10,%esp
           pathname, searched_record.searched_path);
    dir_close(searched_record.parent_dir);
c0006f93:	8b 45 dc             	mov    -0x24(%ebp),%eax
c0006f96:	83 ec 0c             	sub    $0xc,%esp
c0006f99:	50                   	push   %eax
c0006f9a:	e8 8d 1e 00 00       	call   c0008e2c <dir_close>
c0006f9f:	83 c4 10             	add    $0x10,%esp
    return -1;
c0006fa2:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c0006fa7:	e9 14 01 00 00       	jmp    c00070c0 <sys_open+0x25d>
  }

  // 在最后一个路径上没找到且不创建文件
  if (!found && !(flags & O_CREAT)) {
c0006fac:	83 7d e8 00          	cmpl   $0x0,-0x18(%ebp)
c0006fb0:	75 56                	jne    c0007008 <sys_open+0x1a5>
c0006fb2:	0f b6 85 d4 fd ff ff 	movzbl -0x22c(%ebp),%eax
c0006fb9:	83 e0 04             	and    $0x4,%eax
c0006fbc:	85 c0                	test   %eax,%eax
c0006fbe:	75 48                	jne    c0007008 <sys_open+0x1a5>
    printk("in path %s, file %s is`t exist\n", searched_record.searched_path,
           (strrchr(searched_record.searched_path, '/') + 1));
c0006fc0:	83 ec 08             	sub    $0x8,%esp
c0006fc3:	6a 2f                	push   $0x2f
c0006fc5:	8d 85 dc fd ff ff    	lea    -0x224(%ebp),%eax
c0006fcb:	50                   	push   %eax
c0006fcc:	e8 81 b6 ff ff       	call   c0002652 <strrchr>
c0006fd1:	83 c4 10             	add    $0x10,%esp
    printk("in path %s, file %s is`t exist\n", searched_record.searched_path,
c0006fd4:	83 c0 01             	add    $0x1,%eax
c0006fd7:	83 ec 04             	sub    $0x4,%esp
c0006fda:	50                   	push   %eax
c0006fdb:	8d 85 dc fd ff ff    	lea    -0x224(%ebp),%eax
c0006fe1:	50                   	push   %eax
c0006fe2:	68 bc d3 00 c0       	push   $0xc000d3bc
c0006fe7:	e8 c8 e6 ff ff       	call   c00056b4 <printk>
c0006fec:	83 c4 10             	add    $0x10,%esp
    dir_close(searched_record.parent_dir);
c0006fef:	8b 45 dc             	mov    -0x24(%ebp),%eax
c0006ff2:	83 ec 0c             	sub    $0xc,%esp
c0006ff5:	50                   	push   %eax
c0006ff6:	e8 31 1e 00 00       	call   c0008e2c <dir_close>
c0006ffb:	83 c4 10             	add    $0x10,%esp
    return -1;
c0006ffe:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c0007003:	e9 b8 00 00 00       	jmp    c00070c0 <sys_open+0x25d>
  } else if (found &&
c0007008:	83 7d e8 00          	cmpl   $0x0,-0x18(%ebp)
c000700c:	74 37                	je     c0007045 <sys_open+0x1e2>
             flags &
c000700e:	0f b6 85 d4 fd ff ff 	movzbl -0x22c(%ebp),%eax
c0007015:	83 e0 04             	and    $0x4,%eax
  } else if (found &&
c0007018:	85 c0                	test   %eax,%eax
c000701a:	74 29                	je     c0007045 <sys_open+0x1e2>
                 O_CREAT) { // TODO
                            // FIX：若要创建的文件已存在，Linux选择open该文件
    printk("%s has already exist!\n", pathname);
c000701c:	83 ec 08             	sub    $0x8,%esp
c000701f:	ff 75 08             	push   0x8(%ebp)
c0007022:	68 dc d3 00 c0       	push   $0xc000d3dc
c0007027:	e8 88 e6 ff ff       	call   c00056b4 <printk>
c000702c:	83 c4 10             	add    $0x10,%esp
    dir_close(searched_record.parent_dir);
c000702f:	8b 45 dc             	mov    -0x24(%ebp),%eax
c0007032:	83 ec 0c             	sub    $0xc,%esp
c0007035:	50                   	push   %eax
c0007036:	e8 f1 1d 00 00       	call   c0008e2c <dir_close>
c000703b:	83 c4 10             	add    $0x10,%esp
    return -1;
c000703e:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c0007043:	eb 7b                	jmp    c00070c0 <sys_open+0x25d>
  }

  /*
   * create用法：sys_open(“xxx”,O_CREAT|O_XXX)
   */
  switch (flags & O_CREAT) {
c0007045:	0f b6 85 d4 fd ff ff 	movzbl -0x22c(%ebp),%eax
c000704c:	83 e0 04             	and    $0x4,%eax
c000704f:	83 f8 04             	cmp    $0x4,%eax
c0007052:	75 4f                	jne    c00070a3 <sys_open+0x240>
  case O_CREAT:
    printk("creating file\n");
c0007054:	83 ec 0c             	sub    $0xc,%esp
c0007057:	68 f3 d3 00 c0       	push   $0xc000d3f3
c000705c:	e8 53 e6 ff ff       	call   c00056b4 <printk>
c0007061:	83 c4 10             	add    $0x10,%esp
    fd = file_create(searched_record.parent_dir, (strrchr(pathname, '/') + 1),
c0007064:	0f b6 9d d4 fd ff ff 	movzbl -0x22c(%ebp),%ebx
c000706b:	83 ec 08             	sub    $0x8,%esp
c000706e:	6a 2f                	push   $0x2f
c0007070:	ff 75 08             	push   0x8(%ebp)
c0007073:	e8 da b5 ff ff       	call   c0002652 <strrchr>
c0007078:	83 c4 10             	add    $0x10,%esp
c000707b:	8d 50 01             	lea    0x1(%eax),%edx
c000707e:	8b 45 dc             	mov    -0x24(%ebp),%eax
c0007081:	83 ec 04             	sub    $0x4,%esp
c0007084:	53                   	push   %ebx
c0007085:	52                   	push   %edx
c0007086:	50                   	push   %eax
c0007087:	e8 cb 2b 00 00       	call   c0009c57 <file_create>
c000708c:	83 c4 10             	add    $0x10,%esp
c000708f:	89 45 f4             	mov    %eax,-0xc(%ebp)
                     flags);
    dir_close(searched_record.parent_dir);
c0007092:	8b 45 dc             	mov    -0x24(%ebp),%eax
c0007095:	83 ec 0c             	sub    $0xc,%esp
c0007098:	50                   	push   %eax
c0007099:	e8 8e 1d 00 00       	call   c0008e2c <dir_close>
c000709e:	83 c4 10             	add    $0x10,%esp
    break;
c00070a1:	eb 1a                	jmp    c00070bd <sys_open+0x25a>
  default: // 其余情况均为打开已存在文件O_RDONLY,O_WRONLY,O_RDWR
    fd = file_open(inode_no, flags);
c00070a3:	0f b6 95 d4 fd ff ff 	movzbl -0x22c(%ebp),%edx
c00070aa:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00070ad:	83 ec 08             	sub    $0x8,%esp
c00070b0:	52                   	push   %edx
c00070b1:	50                   	push   %eax
c00070b2:	e8 67 2e 00 00       	call   c0009f1e <file_open>
c00070b7:	83 c4 10             	add    $0x10,%esp
c00070ba:	89 45 f4             	mov    %eax,-0xc(%ebp)
  }
  return fd; // 此fd是任务pcb->fd_table数组中的元素下标
c00070bd:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c00070c0:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c00070c3:	c9                   	leave  
c00070c4:	c3                   	ret    

c00070c5 <fd_local2global>:

// 将文件描述符转化为文件表的下标
static uint32_t fd_local2global(uint32_t local_fd) {
c00070c5:	55                   	push   %ebp
c00070c6:	89 e5                	mov    %esp,%ebp
c00070c8:	83 ec 18             	sub    $0x18,%esp
  struct task_struct *cur = running_thread();
c00070cb:	e8 3f ca ff ff       	call   c0003b0f <running_thread>
c00070d0:	89 45 f4             	mov    %eax,-0xc(%ebp)
  int32_t global_fd = cur->fd_table[local_fd];
c00070d3:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00070d6:	8b 55 08             	mov    0x8(%ebp),%edx
c00070d9:	83 c2 38             	add    $0x38,%edx
c00070dc:	8b 44 90 0c          	mov    0xc(%eax,%edx,4),%eax
c00070e0:	89 45 f0             	mov    %eax,-0x10(%ebp)
  ASSERT(global_fd >= 0 && global_fd < MAX_FILE_OPEN);
c00070e3:	83 7d f0 00          	cmpl   $0x0,-0x10(%ebp)
c00070e7:	78 06                	js     c00070ef <fd_local2global+0x2a>
c00070e9:	83 7d f0 1f          	cmpl   $0x1f,-0x10(%ebp)
c00070ed:	7e 1c                	jle    c000710b <fd_local2global+0x46>
c00070ef:	68 04 d4 00 c0       	push   $0xc000d404
c00070f4:	68 0c d9 00 c0       	push   $0xc000d90c
c00070f9:	68 67 01 00 00       	push   $0x167
c00070fe:	68 dd d0 00 c0       	push   $0xc000d0dd
c0007103:	e8 d0 b1 ff ff       	call   c00022d8 <panic_spin>
c0007108:	83 c4 10             	add    $0x10,%esp
  return (uint32_t)global_fd;
c000710b:	8b 45 f0             	mov    -0x10(%ebp),%eax
}
c000710e:	c9                   	leave  
c000710f:	c3                   	ret    

c0007110 <sys_close>:

// 关闭文件描述符fd指向的文件，成功返0否则返-1
int32_t sys_close(int32_t fd) {
c0007110:	55                   	push   %ebp
c0007111:	89 e5                	mov    %esp,%ebp
c0007113:	83 ec 18             	sub    $0x18,%esp
  int32_t ret = -1;
c0007116:	c7 45 f4 ff ff ff ff 	movl   $0xffffffff,-0xc(%ebp)
  if (fd > 2) {
c000711d:	83 7d 08 02          	cmpl   $0x2,0x8(%ebp)
c0007121:	7e 45                	jle    c0007168 <sys_close+0x58>
    uint32_t _fd = fd_local2global(fd);
c0007123:	8b 45 08             	mov    0x8(%ebp),%eax
c0007126:	83 ec 0c             	sub    $0xc,%esp
c0007129:	50                   	push   %eax
c000712a:	e8 96 ff ff ff       	call   c00070c5 <fd_local2global>
c000712f:	83 c4 10             	add    $0x10,%esp
c0007132:	89 45 f0             	mov    %eax,-0x10(%ebp)
    ret = file_close(&file_table[_fd]);
c0007135:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0007138:	89 d0                	mov    %edx,%eax
c000713a:	01 c0                	add    %eax,%eax
c000713c:	01 d0                	add    %edx,%eax
c000713e:	c1 e0 02             	shl    $0x2,%eax
c0007141:	05 00 2c 01 c0       	add    $0xc0012c00,%eax
c0007146:	83 ec 0c             	sub    $0xc,%esp
c0007149:	50                   	push   %eax
c000714a:	e8 e8 2e 00 00       	call   c000a037 <file_close>
c000714f:	83 c4 10             	add    $0x10,%esp
c0007152:	89 45 f4             	mov    %eax,-0xc(%ebp)
    running_thread()->fd_table[fd] = -1; // 使该文件描述符位可用
c0007155:	e8 b5 c9 ff ff       	call   c0003b0f <running_thread>
c000715a:	8b 55 08             	mov    0x8(%ebp),%edx
c000715d:	83 c2 38             	add    $0x38,%edx
c0007160:	c7 44 90 0c ff ff ff 	movl   $0xffffffff,0xc(%eax,%edx,4)
c0007167:	ff 
  }
  return ret;
c0007168:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c000716b:	c9                   	leave  
c000716c:	c3                   	ret    

c000716d <sys_write>:

// 将buf中连续count个字节写入文件描述符fd，成功返回写入字节数
uint32_t sys_write(int32_t fd, const void *buf, uint32_t count) {
c000716d:	55                   	push   %ebp
c000716e:	89 e5                	mov    %esp,%ebp
c0007170:	57                   	push   %edi
c0007171:	81 ec 14 04 00 00    	sub    $0x414,%esp
  if (fd < 0) {
c0007177:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c000717b:	79 1a                	jns    c0007197 <sys_write+0x2a>
    printk("sys_write: fd error\n");
c000717d:	83 ec 0c             	sub    $0xc,%esp
c0007180:	68 30 d4 00 c0       	push   $0xc000d430
c0007185:	e8 2a e5 ff ff       	call   c00056b4 <printk>
c000718a:	83 c4 10             	add    $0x10,%esp
    return -1;
c000718d:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c0007192:	e9 c4 00 00 00       	jmp    c000725b <sys_write+0xee>
  }
  if (fd == stdout_no) { // 往屏幕上打印信息
c0007197:	83 7d 08 01          	cmpl   $0x1,0x8(%ebp)
c000719b:	75 4d                	jne    c00071ea <sys_write+0x7d>
    char tmp_buf[1024] = {0};
c000719d:	c7 85 ec fb ff ff 00 	movl   $0x0,-0x414(%ebp)
c00071a4:	00 00 00 
c00071a7:	8d 95 f0 fb ff ff    	lea    -0x410(%ebp),%edx
c00071ad:	b8 00 00 00 00       	mov    $0x0,%eax
c00071b2:	b9 ff 00 00 00       	mov    $0xff,%ecx
c00071b7:	89 d7                	mov    %edx,%edi
c00071b9:	f3 ab                	rep stos %eax,%es:(%edi)
    memcpy(tmp_buf, buf, count);
c00071bb:	83 ec 04             	sub    $0x4,%esp
c00071be:	ff 75 10             	push   0x10(%ebp)
c00071c1:	ff 75 0c             	push   0xc(%ebp)
c00071c4:	8d 85 ec fb ff ff    	lea    -0x414(%ebp),%eax
c00071ca:	50                   	push   %eax
c00071cb:	e8 31 b2 ff ff       	call   c0002401 <memcpy>
c00071d0:	83 c4 10             	add    $0x10,%esp
    console_put_str(tmp_buf);
c00071d3:	83 ec 0c             	sub    $0xc,%esp
c00071d6:	8d 85 ec fb ff ff    	lea    -0x414(%ebp),%eax
c00071dc:	50                   	push   %eax
c00071dd:	e8 8f d5 ff ff       	call   c0004771 <console_put_str>
c00071e2:	83 c4 10             	add    $0x10,%esp
    return count;
c00071e5:	8b 45 10             	mov    0x10(%ebp),%eax
c00071e8:	eb 71                	jmp    c000725b <sys_write+0xee>
  }
  // 往文件中写数据
  uint32_t _fd = fd_local2global(fd);
c00071ea:	8b 45 08             	mov    0x8(%ebp),%eax
c00071ed:	83 ec 0c             	sub    $0xc,%esp
c00071f0:	50                   	push   %eax
c00071f1:	e8 cf fe ff ff       	call   c00070c5 <fd_local2global>
c00071f6:	83 c4 10             	add    $0x10,%esp
c00071f9:	89 45 f4             	mov    %eax,-0xc(%ebp)
  struct file *wr_file = &file_table[_fd];
c00071fc:	8b 55 f4             	mov    -0xc(%ebp),%edx
c00071ff:	89 d0                	mov    %edx,%eax
c0007201:	01 c0                	add    %eax,%eax
c0007203:	01 d0                	add    %edx,%eax
c0007205:	c1 e0 02             	shl    $0x2,%eax
c0007208:	05 00 2c 01 c0       	add    $0xc0012c00,%eax
c000720d:	89 45 f0             	mov    %eax,-0x10(%ebp)
  if (wr_file->fd_flag & O_WRONLY || wr_file->fd_flag & O_RDWR) {
c0007210:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0007213:	8b 40 04             	mov    0x4(%eax),%eax
c0007216:	83 e0 01             	and    $0x1,%eax
c0007219:	85 c0                	test   %eax,%eax
c000721b:	75 0d                	jne    c000722a <sys_write+0xbd>
c000721d:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0007220:	8b 40 04             	mov    0x4(%eax),%eax
c0007223:	83 e0 02             	and    $0x2,%eax
c0007226:	85 c0                	test   %eax,%eax
c0007228:	74 1c                	je     c0007246 <sys_write+0xd9>
    uint32_t bytes_written = file_write(wr_file, buf, count);
c000722a:	83 ec 04             	sub    $0x4,%esp
c000722d:	ff 75 10             	push   0x10(%ebp)
c0007230:	ff 75 0c             	push   0xc(%ebp)
c0007233:	ff 75 f0             	push   -0x10(%ebp)
c0007236:	e8 3f 2e 00 00       	call   c000a07a <file_write>
c000723b:	83 c4 10             	add    $0x10,%esp
c000723e:	89 45 ec             	mov    %eax,-0x14(%ebp)
    return bytes_written;
c0007241:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0007244:	eb 15                	jmp    c000725b <sys_write+0xee>
  } else {
    console_put_str("sys_write: not allowed to write file without flag O_RDWR "
c0007246:	83 ec 0c             	sub    $0xc,%esp
c0007249:	68 48 d4 00 c0       	push   $0xc000d448
c000724e:	e8 1e d5 ff ff       	call   c0004771 <console_put_str>
c0007253:	83 c4 10             	add    $0x10,%esp
                    "or O_WRONLY\n");
    return -1;
c0007256:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  }
}
c000725b:	8b 7d fc             	mov    -0x4(%ebp),%edi
c000725e:	c9                   	leave  
c000725f:	c3                   	ret    

c0007260 <sys_read>:

// 从文件描述符fd指向文件中读count个字节到buf，成功返回读出字节数
int32_t sys_read(int32_t fd, void *buf, uint32_t count) {
c0007260:	55                   	push   %ebp
c0007261:	89 e5                	mov    %esp,%ebp
c0007263:	83 ec 18             	sub    $0x18,%esp
  ASSERT(buf != NULL);
c0007266:	83 7d 0c 00          	cmpl   $0x0,0xc(%ebp)
c000726a:	75 1c                	jne    c0007288 <sys_read+0x28>
c000726c:	68 8e d4 00 c0       	push   $0xc000d48e
c0007271:	68 1c d9 00 c0       	push   $0xc000d91c
c0007276:	68 91 01 00 00       	push   $0x191
c000727b:	68 dd d0 00 c0       	push   $0xc000d0dd
c0007280:	e8 53 b0 ff ff       	call   c00022d8 <panic_spin>
c0007285:	83 c4 10             	add    $0x10,%esp
  int32_t ret = -1;
c0007288:	c7 45 f4 ff ff ff ff 	movl   $0xffffffff,-0xc(%ebp)
  
  if (fd < 0 || fd == stdout_no || fd == stderr_no) {
c000728f:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c0007293:	78 0c                	js     c00072a1 <sys_read+0x41>
c0007295:	83 7d 08 01          	cmpl   $0x1,0x8(%ebp)
c0007299:	74 06                	je     c00072a1 <sys_read+0x41>
c000729b:	83 7d 08 02          	cmpl   $0x2,0x8(%ebp)
c000729f:	75 15                	jne    c00072b6 <sys_read+0x56>
    printk("sys_read: fd error\n");
c00072a1:	83 ec 0c             	sub    $0xc,%esp
c00072a4:	68 9a d4 00 c0       	push   $0xc000d49a
c00072a9:	e8 06 e4 ff ff       	call   c00056b4 <printk>
c00072ae:	83 c4 10             	add    $0x10,%esp
c00072b1:	e9 87 00 00 00       	jmp    c000733d <sys_read+0xdd>
  } else if (fd == stdin_no) {
c00072b6:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c00072ba:	75 49                	jne    c0007305 <sys_read+0xa5>
    char *buffer = buf;
c00072bc:	8b 45 0c             	mov    0xc(%ebp),%eax
c00072bf:	89 45 f0             	mov    %eax,-0x10(%ebp)
    uint32_t bytes_read = 0;
c00072c2:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%ebp)
    while (bytes_read < count) { // 每次从键盘缓冲区中获取1个字符
c00072c9:	eb 1d                	jmp    c00072e8 <sys_read+0x88>
      *buffer = ioq_getchar(&kbd_buf);
c00072cb:	83 ec 0c             	sub    $0xc,%esp
c00072ce:	68 60 1b 01 c0       	push   $0xc0011b60
c00072d3:	e8 7a d9 ff ff       	call   c0004c52 <ioq_getchar>
c00072d8:	83 c4 10             	add    $0x10,%esp
c00072db:	8b 55 f0             	mov    -0x10(%ebp),%edx
c00072de:	88 02                	mov    %al,(%edx)
      bytes_read++;
c00072e0:	83 45 ec 01          	addl   $0x1,-0x14(%ebp)
      buffer++;
c00072e4:	83 45 f0 01          	addl   $0x1,-0x10(%ebp)
    while (bytes_read < count) { // 每次从键盘缓冲区中获取1个字符
c00072e8:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00072eb:	3b 45 10             	cmp    0x10(%ebp),%eax
c00072ee:	72 db                	jb     c00072cb <sys_read+0x6b>
    }
    ret = (bytes_read == 0 ? -1 : (int32_t)bytes_read);
c00072f0:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c00072f4:	74 05                	je     c00072fb <sys_read+0x9b>
c00072f6:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00072f9:	eb 05                	jmp    c0007300 <sys_read+0xa0>
c00072fb:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c0007300:	89 45 f4             	mov    %eax,-0xc(%ebp)
c0007303:	eb 38                	jmp    c000733d <sys_read+0xdd>
  } else {
    uint32_t _fd = fd_local2global(fd);
c0007305:	8b 45 08             	mov    0x8(%ebp),%eax
c0007308:	83 ec 0c             	sub    $0xc,%esp
c000730b:	50                   	push   %eax
c000730c:	e8 b4 fd ff ff       	call   c00070c5 <fd_local2global>
c0007311:	83 c4 10             	add    $0x10,%esp
c0007314:	89 45 e8             	mov    %eax,-0x18(%ebp)
    ret = file_read(&file_table[_fd], buf, count);
c0007317:	8b 55 e8             	mov    -0x18(%ebp),%edx
c000731a:	89 d0                	mov    %edx,%eax
c000731c:	01 c0                	add    %eax,%eax
c000731e:	01 d0                	add    %edx,%eax
c0007320:	c1 e0 02             	shl    $0x2,%eax
c0007323:	05 00 2c 01 c0       	add    $0xc0012c00,%eax
c0007328:	83 ec 04             	sub    $0x4,%esp
c000732b:	ff 75 10             	push   0x10(%ebp)
c000732e:	ff 75 0c             	push   0xc(%ebp)
c0007331:	50                   	push   %eax
c0007332:	e8 12 35 00 00       	call   c000a849 <file_read>
c0007337:	83 c4 10             	add    $0x10,%esp
c000733a:	89 45 f4             	mov    %eax,-0xc(%ebp)
  }
  return ret;
c000733d:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0007340:	c9                   	leave  
c0007341:	c3                   	ret    

c0007342 <sys_lseek>:

// 重置用于文件读写操作的偏移指针，成功返回新偏移量（whence + offset-> fd_pos
int32_t sys_lseek(int32_t fd, int32_t offset, uint8_t whence) {
c0007342:	55                   	push   %ebp
c0007343:	89 e5                	mov    %esp,%ebp
c0007345:	83 ec 28             	sub    $0x28,%esp
c0007348:	8b 45 10             	mov    0x10(%ebp),%eax
c000734b:	88 45 e4             	mov    %al,-0x1c(%ebp)
  if (fd < 0) {
c000734e:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c0007352:	79 1a                	jns    c000736e <sys_lseek+0x2c>
    printk("sys_lseek: fd error\n");
c0007354:	83 ec 0c             	sub    $0xc,%esp
c0007357:	68 ae d4 00 c0       	push   $0xc000d4ae
c000735c:	e8 53 e3 ff ff       	call   c00056b4 <printk>
c0007361:	83 c4 10             	add    $0x10,%esp
    return -1;
c0007364:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c0007369:	e9 c1 00 00 00       	jmp    c000742f <sys_lseek+0xed>
  }
  ASSERT(whence > 0 && whence < 4);
c000736e:	80 7d e4 00          	cmpb   $0x0,-0x1c(%ebp)
c0007372:	74 06                	je     c000737a <sys_lseek+0x38>
c0007374:	80 7d e4 03          	cmpb   $0x3,-0x1c(%ebp)
c0007378:	76 1c                	jbe    c0007396 <sys_lseek+0x54>
c000737a:	68 c3 d4 00 c0       	push   $0xc000d4c3
c000737f:	68 28 d9 00 c0       	push   $0xc000d928
c0007384:	68 ac 01 00 00       	push   $0x1ac
c0007389:	68 dd d0 00 c0       	push   $0xc000d0dd
c000738e:	e8 45 af ff ff       	call   c00022d8 <panic_spin>
c0007393:	83 c4 10             	add    $0x10,%esp
  int32_t new_pos = 0;
c0007396:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  uint32_t _fd = fd_local2global(fd);
c000739d:	8b 45 08             	mov    0x8(%ebp),%eax
c00073a0:	83 ec 0c             	sub    $0xc,%esp
c00073a3:	50                   	push   %eax
c00073a4:	e8 1c fd ff ff       	call   c00070c5 <fd_local2global>
c00073a9:	83 c4 10             	add    $0x10,%esp
c00073ac:	89 45 f0             	mov    %eax,-0x10(%ebp)
  struct file *pf = &file_table[_fd];
c00073af:	8b 55 f0             	mov    -0x10(%ebp),%edx
c00073b2:	89 d0                	mov    %edx,%eax
c00073b4:	01 c0                	add    %eax,%eax
c00073b6:	01 d0                	add    %edx,%eax
c00073b8:	c1 e0 02             	shl    $0x2,%eax
c00073bb:	05 00 2c 01 c0       	add    $0xc0012c00,%eax
c00073c0:	89 45 ec             	mov    %eax,-0x14(%ebp)
  int32_t file_size = (int32_t)pf->fd_inode->i_size;
c00073c3:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00073c6:	8b 40 08             	mov    0x8(%eax),%eax
c00073c9:	8b 40 04             	mov    0x4(%eax),%eax
c00073cc:	89 45 e8             	mov    %eax,-0x18(%ebp)

  switch (whence) {
c00073cf:	0f b6 45 e4          	movzbl -0x1c(%ebp),%eax
c00073d3:	83 f8 03             	cmp    $0x3,%eax
c00073d6:	74 2a                	je     c0007402 <sys_lseek+0xc0>
c00073d8:	83 f8 03             	cmp    $0x3,%eax
c00073db:	7f 30                	jg     c000740d <sys_lseek+0xcb>
c00073dd:	83 f8 01             	cmp    $0x1,%eax
c00073e0:	74 07                	je     c00073e9 <sys_lseek+0xa7>
c00073e2:	83 f8 02             	cmp    $0x2,%eax
c00073e5:	74 0a                	je     c00073f1 <sys_lseek+0xaf>
c00073e7:	eb 24                	jmp    c000740d <sys_lseek+0xcb>
  case SEEK_SET:
    new_pos = offset;
c00073e9:	8b 45 0c             	mov    0xc(%ebp),%eax
c00073ec:	89 45 f4             	mov    %eax,-0xc(%ebp)
    break;
c00073ef:	eb 1c                	jmp    c000740d <sys_lseek+0xcb>
  case SEEK_CUR: // offse可正可负
    new_pos = (int32_t)pf->fd_pos + offset;
c00073f1:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00073f4:	8b 00                	mov    (%eax),%eax
c00073f6:	89 c2                	mov    %eax,%edx
c00073f8:	8b 45 0c             	mov    0xc(%ebp),%eax
c00073fb:	01 d0                	add    %edx,%eax
c00073fd:	89 45 f4             	mov    %eax,-0xc(%ebp)
    break;
c0007400:	eb 0b                	jmp    c000740d <sys_lseek+0xcb>
  case SEEK_END: // offset为负
    new_pos = file_size + offset;
c0007402:	8b 55 e8             	mov    -0x18(%ebp),%edx
c0007405:	8b 45 0c             	mov    0xc(%ebp),%eax
c0007408:	01 d0                	add    %edx,%eax
c000740a:	89 45 f4             	mov    %eax,-0xc(%ebp)
  }
  if (new_pos < 0 || new_pos > (file_size - 1)) {
c000740d:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
c0007411:	78 08                	js     c000741b <sys_lseek+0xd9>
c0007413:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0007416:	3b 45 f4             	cmp    -0xc(%ebp),%eax
c0007419:	7f 07                	jg     c0007422 <sys_lseek+0xe0>
    return -1;
c000741b:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c0007420:	eb 0d                	jmp    c000742f <sys_lseek+0xed>
  }
  pf->fd_pos = new_pos;
c0007422:	8b 55 f4             	mov    -0xc(%ebp),%edx
c0007425:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0007428:	89 10                	mov    %edx,(%eax)
  return pf->fd_pos;
c000742a:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000742d:	8b 00                	mov    (%eax),%eax
}
c000742f:	c9                   	leave  
c0007430:	c3                   	ret    

c0007431 <sys_unlink>:

// 删除文件（目录），成功返回0
int32_t sys_unlink(const char *pathname) {
c0007431:	55                   	push   %ebp
c0007432:	89 e5                	mov    %esp,%ebp
c0007434:	81 ec 28 02 00 00    	sub    $0x228,%esp
  ASSERT(strlen(pathname) < MAX_PATH_LEN);
c000743a:	83 ec 0c             	sub    $0xc,%esp
c000743d:	ff 75 08             	push   0x8(%ebp)
c0007440:	e8 f5 b0 ff ff       	call   c000253a <strlen>
c0007445:	83 c4 10             	add    $0x10,%esp
c0007448:	3d ff 01 00 00       	cmp    $0x1ff,%eax
c000744d:	76 1c                	jbe    c000746b <sys_unlink+0x3a>
c000744f:	68 dc d4 00 c0       	push   $0xc000d4dc
c0007454:	68 34 d9 00 c0       	push   $0xc000d934
c0007459:	68 c5 01 00 00       	push   $0x1c5
c000745e:	68 dd d0 00 c0       	push   $0xc000d0dd
c0007463:	e8 70 ae ff ff       	call   c00022d8 <panic_spin>
c0007468:	83 c4 10             	add    $0x10,%esp
  struct path_search_record searched_record;
  memset(&searched_record, 0, sizeof(struct path_search_record));
c000746b:	83 ec 04             	sub    $0x4,%esp
c000746e:	68 08 02 00 00       	push   $0x208
c0007473:	6a 00                	push   $0x0
c0007475:	8d 85 e0 fd ff ff    	lea    -0x220(%ebp),%eax
c000747b:	50                   	push   %eax
c000747c:	e8 2d af ff ff       	call   c00023ae <memset>
c0007481:	83 c4 10             	add    $0x10,%esp
  int inode_no =
      search_file(pathname, &searched_record); // 检查待删除文件是否存在
c0007484:	83 ec 08             	sub    $0x8,%esp
c0007487:	8d 85 e0 fd ff ff    	lea    -0x220(%ebp),%eax
c000748d:	50                   	push   %eax
c000748e:	ff 75 08             	push   0x8(%ebp)
c0007491:	e8 46 f7 ff ff       	call   c0006bdc <search_file>
c0007496:	83 c4 10             	add    $0x10,%esp
c0007499:	89 45 f0             	mov    %eax,-0x10(%ebp)
  ASSERT(inode_no != 0);
c000749c:	83 7d f0 00          	cmpl   $0x0,-0x10(%ebp)
c00074a0:	75 1c                	jne    c00074be <sys_unlink+0x8d>
c00074a2:	68 fc d4 00 c0       	push   $0xc000d4fc
c00074a7:	68 34 d9 00 c0       	push   $0xc000d934
c00074ac:	68 ca 01 00 00       	push   $0x1ca
c00074b1:	68 dd d0 00 c0       	push   $0xc000d0dd
c00074b6:	e8 1d ae ff ff       	call   c00022d8 <panic_spin>
c00074bb:	83 c4 10             	add    $0x10,%esp
  if (inode_no == -1) {
c00074be:	83 7d f0 ff          	cmpl   $0xffffffff,-0x10(%ebp)
c00074c2:	75 2c                	jne    c00074f0 <sys_unlink+0xbf>
    printk("file %s not found!\n", pathname);
c00074c4:	83 ec 08             	sub    $0x8,%esp
c00074c7:	ff 75 08             	push   0x8(%ebp)
c00074ca:	68 0a d5 00 c0       	push   $0xc000d50a
c00074cf:	e8 e0 e1 ff ff       	call   c00056b4 <printk>
c00074d4:	83 c4 10             	add    $0x10,%esp
    dir_close(searched_record.parent_dir);
c00074d7:	8b 45 e0             	mov    -0x20(%ebp),%eax
c00074da:	83 ec 0c             	sub    $0xc,%esp
c00074dd:	50                   	push   %eax
c00074de:	e8 49 19 00 00       	call   c0008e2c <dir_close>
c00074e3:	83 c4 10             	add    $0x10,%esp
    return -1;
c00074e6:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c00074eb:	e9 31 01 00 00       	jmp    c0007621 <sys_unlink+0x1f0>
  }

  uint32_t file_idx = 0;
c00074f0:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  while (file_idx < MAX_FILE_OPEN) {
c00074f7:	eb 37                	jmp    c0007530 <sys_unlink+0xff>
    if (file_table[file_idx].fd_inode != NULL &&
c00074f9:	8b 55 f4             	mov    -0xc(%ebp),%edx
c00074fc:	89 d0                	mov    %edx,%eax
c00074fe:	01 c0                	add    %eax,%eax
c0007500:	01 d0                	add    %edx,%eax
c0007502:	c1 e0 02             	shl    $0x2,%eax
c0007505:	05 08 2c 01 c0       	add    $0xc0012c08,%eax
c000750a:	8b 00                	mov    (%eax),%eax
c000750c:	85 c0                	test   %eax,%eax
c000750e:	74 1c                	je     c000752c <sys_unlink+0xfb>
        (uint32_t)inode_no == file_table[file_idx].fd_inode->i_no) {
c0007510:	8b 55 f4             	mov    -0xc(%ebp),%edx
c0007513:	89 d0                	mov    %edx,%eax
c0007515:	01 c0                	add    %eax,%eax
c0007517:	01 d0                	add    %edx,%eax
c0007519:	c1 e0 02             	shl    $0x2,%eax
c000751c:	05 08 2c 01 c0       	add    $0xc0012c08,%eax
c0007521:	8b 00                	mov    (%eax),%eax
c0007523:	8b 10                	mov    (%eax),%edx
c0007525:	8b 45 f0             	mov    -0x10(%ebp),%eax
    if (file_table[file_idx].fd_inode != NULL &&
c0007528:	39 c2                	cmp    %eax,%edx
c000752a:	74 0c                	je     c0007538 <sys_unlink+0x107>
      break;
    }
    file_idx++;
c000752c:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
  while (file_idx < MAX_FILE_OPEN) {
c0007530:	83 7d f4 1f          	cmpl   $0x1f,-0xc(%ebp)
c0007534:	76 c3                	jbe    c00074f9 <sys_unlink+0xc8>
c0007536:	eb 01                	jmp    c0007539 <sys_unlink+0x108>
      break;
c0007538:	90                   	nop
  }

  // 判断是否在已打开文件表file_table中
  if (file_idx < MAX_FILE_OPEN) {
c0007539:	83 7d f4 1f          	cmpl   $0x1f,-0xc(%ebp)
c000753d:	77 2c                	ja     c000756b <sys_unlink+0x13a>
    // 父目录是在search_file时打开的，所以退出时需关闭
    dir_close(searched_record.parent_dir);
c000753f:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0007542:	83 ec 0c             	sub    $0xc,%esp
c0007545:	50                   	push   %eax
c0007546:	e8 e1 18 00 00       	call   c0008e2c <dir_close>
c000754b:	83 c4 10             	add    $0x10,%esp
    printk("file %s is in use, not allow to delete!\n", pathname);
c000754e:	83 ec 08             	sub    $0x8,%esp
c0007551:	ff 75 08             	push   0x8(%ebp)
c0007554:	68 20 d5 00 c0       	push   $0xc000d520
c0007559:	e8 56 e1 ff ff       	call   c00056b4 <printk>
c000755e:	83 c4 10             	add    $0x10,%esp
    return -1;
c0007561:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c0007566:	e9 b6 00 00 00       	jmp    c0007621 <sys_unlink+0x1f0>
  }
  ASSERT(file_idx == MAX_FILE_OPEN);
c000756b:	83 7d f4 20          	cmpl   $0x20,-0xc(%ebp)
c000756f:	74 1c                	je     c000758d <sys_unlink+0x15c>
c0007571:	68 49 d5 00 c0       	push   $0xc000d549
c0007576:	68 34 d9 00 c0       	push   $0xc000d934
c000757b:	68 e1 01 00 00       	push   $0x1e1
c0007580:	68 dd d0 00 c0       	push   $0xc000d0dd
c0007585:	e8 4e ad ff ff       	call   c00022d8 <panic_spin>
c000758a:	83 c4 10             	add    $0x10,%esp

  // 为delete_dir_entry申请缓冲区
  void *io_buf = sys_malloc(SECTOR_SIZE + SECTOR_SIZE);
c000758d:	83 ec 0c             	sub    $0xc,%esp
c0007590:	68 00 04 00 00       	push   $0x400
c0007595:	e8 8a ba ff ff       	call   c0003024 <sys_malloc>
c000759a:	83 c4 10             	add    $0x10,%esp
c000759d:	89 45 ec             	mov    %eax,-0x14(%ebp)
  if (io_buf == NULL) {
c00075a0:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c00075a4:	75 26                	jne    c00075cc <sys_unlink+0x19b>
    dir_close(searched_record.parent_dir);
c00075a6:	8b 45 e0             	mov    -0x20(%ebp),%eax
c00075a9:	83 ec 0c             	sub    $0xc,%esp
c00075ac:	50                   	push   %eax
c00075ad:	e8 7a 18 00 00       	call   c0008e2c <dir_close>
c00075b2:	83 c4 10             	add    $0x10,%esp
    printk("sys_unlink: malloc for io_buf failed\n");
c00075b5:	83 ec 0c             	sub    $0xc,%esp
c00075b8:	68 64 d5 00 c0       	push   $0xc000d564
c00075bd:	e8 f2 e0 ff ff       	call   c00056b4 <printk>
c00075c2:	83 c4 10             	add    $0x10,%esp
    return -1;
c00075c5:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c00075ca:	eb 55                	jmp    c0007621 <sys_unlink+0x1f0>
  }
  struct dir *parent_dir = searched_record.parent_dir;
c00075cc:	8b 45 e0             	mov    -0x20(%ebp),%eax
c00075cf:	89 45 e8             	mov    %eax,-0x18(%ebp)
  delete_dir_entry(cur_part, parent_dir, inode_no, io_buf);
c00075d2:	8b 55 f0             	mov    -0x10(%ebp),%edx
c00075d5:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c00075da:	ff 75 ec             	push   -0x14(%ebp)
c00075dd:	52                   	push   %edx
c00075de:	ff 75 e8             	push   -0x18(%ebp)
c00075e1:	50                   	push   %eax
c00075e2:	e8 48 1d 00 00       	call   c000932f <delete_dir_entry>
c00075e7:	83 c4 10             	add    $0x10,%esp
  inode_release(cur_part, inode_no);
c00075ea:	8b 55 f0             	mov    -0x10(%ebp),%edx
c00075ed:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c00075f2:	83 ec 08             	sub    $0x8,%esp
c00075f5:	52                   	push   %edx
c00075f6:	50                   	push   %eax
c00075f7:	e8 5a 13 00 00       	call   c0008956 <inode_release>
c00075fc:	83 c4 10             	add    $0x10,%esp
  sys_free(io_buf);
c00075ff:	83 ec 0c             	sub    $0xc,%esp
c0007602:	ff 75 ec             	push   -0x14(%ebp)
c0007605:	e8 39 c0 ff ff       	call   c0003643 <sys_free>
c000760a:	83 c4 10             	add    $0x10,%esp
  dir_close(searched_record.parent_dir);
c000760d:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0007610:	83 ec 0c             	sub    $0xc,%esp
c0007613:	50                   	push   %eax
c0007614:	e8 13 18 00 00       	call   c0008e2c <dir_close>
c0007619:	83 c4 10             	add    $0x10,%esp
  return 0; // 成功删除文件
c000761c:	b8 00 00 00 00       	mov    $0x0,%eax
}
c0007621:	c9                   	leave  
c0007622:	c3                   	ret    

c0007623 <sys_mkdir>:

// TODO：此mkdir未支持权限参数mode：int mkdir(const char *pathname, mode_t mode)
// 创建目录pathname，成功返回0
int32_t sys_mkdir(const char *pathname) {
c0007623:	55                   	push   %ebp
c0007624:	89 e5                	mov    %esp,%ebp
c0007626:	81 ec a8 02 00 00    	sub    $0x2a8,%esp
  uint8_t rollback_step = 0; // 失败时回滚各资源状态
c000762c:	c6 45 f7 00          	movb   $0x0,-0x9(%ebp)
  void *io_buf = sys_malloc(SECTOR_SIZE * 2);
c0007630:	83 ec 0c             	sub    $0xc,%esp
c0007633:	68 00 04 00 00       	push   $0x400
c0007638:	e8 e7 b9 ff ff       	call   c0003024 <sys_malloc>
c000763d:	83 c4 10             	add    $0x10,%esp
c0007640:	89 45 ec             	mov    %eax,-0x14(%ebp)
  if (io_buf == NULL) {
c0007643:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c0007647:	75 1a                	jne    c0007663 <sys_mkdir+0x40>
    printk("sys_mkdir: sys_malloc for io_buf failed\n");
c0007649:	83 ec 0c             	sub    $0xc,%esp
c000764c:	68 8c d5 00 c0       	push   $0xc000d58c
c0007651:	e8 5e e0 ff ff       	call   c00056b4 <printk>
c0007656:	83 c4 10             	add    $0x10,%esp
    return -1;
c0007659:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000765e:	e9 ae 03 00 00       	jmp    c0007a11 <sys_mkdir+0x3ee>
  }

  struct path_search_record searched_record;
  memset(&searched_record, 0, sizeof(struct path_search_record));
c0007663:	83 ec 04             	sub    $0x4,%esp
c0007666:	68 08 02 00 00       	push   $0x208
c000766b:	6a 00                	push   $0x0
c000766d:	8d 85 c8 fd ff ff    	lea    -0x238(%ebp),%eax
c0007673:	50                   	push   %eax
c0007674:	e8 35 ad ff ff       	call   c00023ae <memset>
c0007679:	83 c4 10             	add    $0x10,%esp
  int inode_no = -1;
c000767c:	c7 45 f0 ff ff ff ff 	movl   $0xffffffff,-0x10(%ebp)

  inode_no = search_file(pathname, &searched_record);
c0007683:	83 ec 08             	sub    $0x8,%esp
c0007686:	8d 85 c8 fd ff ff    	lea    -0x238(%ebp),%eax
c000768c:	50                   	push   %eax
c000768d:	ff 75 08             	push   0x8(%ebp)
c0007690:	e8 47 f5 ff ff       	call   c0006bdc <search_file>
c0007695:	83 c4 10             	add    $0x10,%esp
c0007698:	89 45 f0             	mov    %eax,-0x10(%ebp)
  if (inode_no != -1) { // 找到同名目录/文件，失败
c000769b:	83 7d f0 ff          	cmpl   $0xffffffff,-0x10(%ebp)
c000769f:	74 1c                	je     c00076bd <sys_mkdir+0x9a>
    printk("sys_mkdir: file or directory %s exist!\n", pathname);
c00076a1:	83 ec 08             	sub    $0x8,%esp
c00076a4:	ff 75 08             	push   0x8(%ebp)
c00076a7:	68 b8 d5 00 c0       	push   $0xc000d5b8
c00076ac:	e8 03 e0 ff ff       	call   c00056b4 <printk>
c00076b1:	83 c4 10             	add    $0x10,%esp
    rollback_step = 1;
c00076b4:	c6 45 f7 01          	movb   $0x1,-0x9(%ebp)
    goto rollback;
c00076b8:	e9 08 03 00 00       	jmp    c00079c5 <sys_mkdir+0x3a2>
  } else { // 未找到，判断是在最终目录没找到，还是某个中间目录不存在
    uint32_t pathname_depth = path_depth_cnt((char *)pathname);
c00076bd:	83 ec 0c             	sub    $0xc,%esp
c00076c0:	ff 75 08             	push   0x8(%ebp)
c00076c3:	e8 89 f4 ff ff       	call   c0006b51 <path_depth_cnt>
c00076c8:	83 c4 10             	add    $0x10,%esp
c00076cb:	89 45 e8             	mov    %eax,-0x18(%ebp)
    uint32_t path_searched_depth =
        path_depth_cnt(searched_record.searched_path);
c00076ce:	83 ec 0c             	sub    $0xc,%esp
c00076d1:	8d 85 c8 fd ff ff    	lea    -0x238(%ebp),%eax
c00076d7:	50                   	push   %eax
c00076d8:	e8 74 f4 ff ff       	call   c0006b51 <path_depth_cnt>
c00076dd:	83 c4 10             	add    $0x10,%esp
    uint32_t path_searched_depth =
c00076e0:	89 45 e4             	mov    %eax,-0x1c(%ebp)
    if (pathname_depth != path_searched_depth) { // 说明没有访问到全部路径
c00076e3:	8b 45 e8             	mov    -0x18(%ebp),%eax
c00076e6:	3b 45 e4             	cmp    -0x1c(%ebp),%eax
c00076e9:	74 23                	je     c000770e <sys_mkdir+0xeb>
      printk("sys_mkdir: cannot access %s: Not a directory, subpath %s is`t "
c00076eb:	83 ec 04             	sub    $0x4,%esp
c00076ee:	8d 85 c8 fd ff ff    	lea    -0x238(%ebp),%eax
c00076f4:	50                   	push   %eax
c00076f5:	ff 75 08             	push   0x8(%ebp)
c00076f8:	68 e0 d5 00 c0       	push   $0xc000d5e0
c00076fd:	e8 b2 df ff ff       	call   c00056b4 <printk>
c0007702:	83 c4 10             	add    $0x10,%esp
             "exist\n",
             pathname, searched_record.searched_path);
      rollback_step = 1;
c0007705:	c6 45 f7 01          	movb   $0x1,-0x9(%ebp)
      goto rollback;
c0007709:	e9 b7 02 00 00       	jmp    c00079c5 <sys_mkdir+0x3a2>
    }
  }

  struct dir *parent_dir = searched_record.parent_dir;
c000770e:	8b 45 c8             	mov    -0x38(%ebp),%eax
c0007711:	89 45 e0             	mov    %eax,-0x20(%ebp)
  // 获取pathname最后一级目录名
  char *dirname = strrchr(searched_record.searched_path, '/') + 1;
c0007714:	83 ec 08             	sub    $0x8,%esp
c0007717:	6a 2f                	push   $0x2f
c0007719:	8d 85 c8 fd ff ff    	lea    -0x238(%ebp),%eax
c000771f:	50                   	push   %eax
c0007720:	e8 2d af ff ff       	call   c0002652 <strrchr>
c0007725:	83 c4 10             	add    $0x10,%esp
c0007728:	83 c0 01             	add    $0x1,%eax
c000772b:	89 45 dc             	mov    %eax,-0x24(%ebp)
  inode_no = inode_bitmap_malloc(cur_part); // 在inode位图中分配inode
c000772e:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0007733:	83 ec 0c             	sub    $0xc,%esp
c0007736:	50                   	push   %eax
c0007737:	e8 fa 23 00 00       	call   c0009b36 <inode_bitmap_malloc>
c000773c:	83 c4 10             	add    $0x10,%esp
c000773f:	89 45 f0             	mov    %eax,-0x10(%ebp)
  if (inode_no == -1) {
c0007742:	83 7d f0 ff          	cmpl   $0xffffffff,-0x10(%ebp)
c0007746:	75 19                	jne    c0007761 <sys_mkdir+0x13e>
    printk("sys_mkdir: allocate inode failed\n");
c0007748:	83 ec 0c             	sub    $0xc,%esp
c000774b:	68 28 d6 00 c0       	push   $0xc000d628
c0007750:	e8 5f df ff ff       	call   c00056b4 <printk>
c0007755:	83 c4 10             	add    $0x10,%esp
    rollback_step = 1;
c0007758:	c6 45 f7 01          	movb   $0x1,-0x9(%ebp)
    goto rollback;
c000775c:	e9 64 02 00 00       	jmp    c00079c5 <sys_mkdir+0x3a2>
  }
  struct inode new_dir_inode;
  inode_init(inode_no, &new_dir_inode);
c0007761:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0007764:	83 ec 08             	sub    $0x8,%esp
c0007767:	8d 95 7c fd ff ff    	lea    -0x284(%ebp),%edx
c000776d:	52                   	push   %edx
c000776e:	50                   	push   %eax
c000776f:	e8 1b 14 00 00       	call   c0008b8f <inode_init>
c0007774:	83 c4 10             	add    $0x10,%esp

  uint32_t block_bitmap_idx = 0;
c0007777:	c7 45 d8 00 00 00 00 	movl   $0x0,-0x28(%ebp)
  int32_t block_lba = -1;
c000777e:	c7 45 d4 ff ff ff ff 	movl   $0xffffffff,-0x2c(%ebp)
  block_lba =
      block_bitmap_malloc(cur_part); // 为目录分配一个块用来写入目录.和..
c0007785:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000778a:	83 ec 0c             	sub    $0xc,%esp
c000778d:	50                   	push   %eax
c000778e:	e8 ea 23 00 00       	call   c0009b7d <block_bitmap_malloc>
c0007793:	83 c4 10             	add    $0x10,%esp
c0007796:	89 45 d4             	mov    %eax,-0x2c(%ebp)
  if (block_lba == -1) {
c0007799:	83 7d d4 ff          	cmpl   $0xffffffff,-0x2c(%ebp)
c000779d:	75 19                	jne    c00077b8 <sys_mkdir+0x195>
    printk("sys_mkdir: block_bitmap_malloc for create directory failed\n");
c000779f:	83 ec 0c             	sub    $0xc,%esp
c00077a2:	68 4c d6 00 c0       	push   $0xc000d64c
c00077a7:	e8 08 df ff ff       	call   c00056b4 <printk>
c00077ac:	83 c4 10             	add    $0x10,%esp
    rollback_step = 2;
c00077af:	c6 45 f7 02          	movb   $0x2,-0x9(%ebp)
    goto rollback;
c00077b3:	e9 0d 02 00 00       	jmp    c00079c5 <sys_mkdir+0x3a2>
  }
  new_dir_inode.i_sectors[0] = block_lba;
c00077b8:	8b 45 d4             	mov    -0x2c(%ebp),%eax
c00077bb:	89 85 8c fd ff ff    	mov    %eax,-0x274(%ebp)
  block_bitmap_idx = block_lba - cur_part->sb->data_start_lba;
c00077c1:	8b 55 d4             	mov    -0x2c(%ebp),%edx
c00077c4:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c00077c9:	8b 40 1c             	mov    0x1c(%eax),%eax
c00077cc:	8b 48 28             	mov    0x28(%eax),%ecx
c00077cf:	89 d0                	mov    %edx,%eax
c00077d1:	29 c8                	sub    %ecx,%eax
c00077d3:	89 45 d8             	mov    %eax,-0x28(%ebp)
  ASSERT(block_bitmap_idx != 0);
c00077d6:	83 7d d8 00          	cmpl   $0x0,-0x28(%ebp)
c00077da:	75 1c                	jne    c00077f8 <sys_mkdir+0x1d5>
c00077dc:	68 88 d6 00 c0       	push   $0xc000d688
c00077e1:	68 40 d9 00 c0       	push   $0xc000d940
c00077e6:	68 29 02 00 00       	push   $0x229
c00077eb:	68 dd d0 00 c0       	push   $0xc000d0dd
c00077f0:	e8 e3 aa ff ff       	call   c00022d8 <panic_spin>
c00077f5:	83 c4 10             	add    $0x10,%esp
  bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
c00077f8:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c00077fd:	83 ec 04             	sub    $0x4,%esp
c0007800:	6a 01                	push   $0x1
c0007802:	ff 75 d8             	push   -0x28(%ebp)
c0007805:	50                   	push   %eax
c0007806:	e8 c4 23 00 00       	call   c0009bcf <bitmap_sync>
c000780b:	83 c4 10             	add    $0x10,%esp

  /* 写入目录项.和.. */
  memset(io_buf, 0, SECTOR_SIZE * 2);
c000780e:	83 ec 04             	sub    $0x4,%esp
c0007811:	68 00 04 00 00       	push   $0x400
c0007816:	6a 00                	push   $0x0
c0007818:	ff 75 ec             	push   -0x14(%ebp)
c000781b:	e8 8e ab ff ff       	call   c00023ae <memset>
c0007820:	83 c4 10             	add    $0x10,%esp
  struct dir_entry *p_de = (struct dir_entry *)io_buf;
c0007823:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0007826:	89 45 d0             	mov    %eax,-0x30(%ebp)
  memcpy(p_de->filename, ".", 1); // 初始化 .
c0007829:	8b 45 d0             	mov    -0x30(%ebp),%eax
c000782c:	83 ec 04             	sub    $0x4,%esp
c000782f:	6a 01                	push   $0x1
c0007831:	68 66 d2 00 c0       	push   $0xc000d266
c0007836:	50                   	push   %eax
c0007837:	e8 c5 ab ff ff       	call   c0002401 <memcpy>
c000783c:	83 c4 10             	add    $0x10,%esp
  p_de->i_no = inode_no;
c000783f:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0007842:	8b 45 d0             	mov    -0x30(%ebp),%eax
c0007845:	89 50 10             	mov    %edx,0x10(%eax)
  p_de->f_type = FT_DIRECTORY;
c0007848:	8b 45 d0             	mov    -0x30(%ebp),%eax
c000784b:	c7 40 14 02 00 00 00 	movl   $0x2,0x14(%eax)
  p_de++;
c0007852:	83 45 d0 18          	addl   $0x18,-0x30(%ebp)
  memcpy(p_de->filename, "..", 2); // 初始化 ..
c0007856:	8b 45 d0             	mov    -0x30(%ebp),%eax
c0007859:	83 ec 04             	sub    $0x4,%esp
c000785c:	6a 02                	push   $0x2
c000785e:	68 68 d2 00 c0       	push   $0xc000d268
c0007863:	50                   	push   %eax
c0007864:	e8 98 ab ff ff       	call   c0002401 <memcpy>
c0007869:	83 c4 10             	add    $0x10,%esp
  p_de->i_no = parent_dir->inode->i_no;
c000786c:	8b 45 e0             	mov    -0x20(%ebp),%eax
c000786f:	8b 00                	mov    (%eax),%eax
c0007871:	8b 10                	mov    (%eax),%edx
c0007873:	8b 45 d0             	mov    -0x30(%ebp),%eax
c0007876:	89 50 10             	mov    %edx,0x10(%eax)
  p_de->f_type = FT_DIRECTORY;
c0007879:	8b 45 d0             	mov    -0x30(%ebp),%eax
c000787c:	c7 40 14 02 00 00 00 	movl   $0x2,0x14(%eax)
  ide_write(cur_part->my_disk, new_dir_inode.i_sectors[0], io_buf, 1);
c0007883:	8b 95 8c fd ff ff    	mov    -0x274(%ebp),%edx
c0007889:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000788e:	8b 40 08             	mov    0x8(%eax),%eax
c0007891:	6a 01                	push   $0x1
c0007893:	ff 75 ec             	push   -0x14(%ebp)
c0007896:	52                   	push   %edx
c0007897:	50                   	push   %eax
c0007898:	e8 02 e3 ff ff       	call   c0005b9f <ide_write>
c000789d:	83 c4 10             	add    $0x10,%esp
  new_dir_inode.i_size = 2 * cur_part->sb->dir_entry_size;
c00078a0:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c00078a5:	8b 40 1c             	mov    0x1c(%eax),%eax
c00078a8:	8b 40 30             	mov    0x30(%eax),%eax
c00078ab:	01 c0                	add    %eax,%eax
c00078ad:	89 85 80 fd ff ff    	mov    %eax,-0x280(%ebp)

  struct dir_entry new_dir_entry;
  memset(&new_dir_entry, 0, sizeof(struct dir_entry));
c00078b3:	83 ec 04             	sub    $0x4,%esp
c00078b6:	6a 18                	push   $0x18
c00078b8:	6a 00                	push   $0x0
c00078ba:	8d 85 64 fd ff ff    	lea    -0x29c(%ebp),%eax
c00078c0:	50                   	push   %eax
c00078c1:	e8 e8 aa ff ff       	call   c00023ae <memset>
c00078c6:	83 c4 10             	add    $0x10,%esp
  create_dir_entry(dirname, inode_no, FT_DIRECTORY,
c00078c9:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00078cc:	8d 95 64 fd ff ff    	lea    -0x29c(%ebp),%edx
c00078d2:	52                   	push   %edx
c00078d3:	6a 02                	push   $0x2
c00078d5:	50                   	push   %eax
c00078d6:	ff 75 dc             	push   -0x24(%ebp)
c00078d9:	e8 81 15 00 00       	call   c0008e5f <create_dir_entry>
c00078de:	83 c4 10             	add    $0x10,%esp
                   &new_dir_entry); // 初始化目录项内容到new_dir_entry中
  memset(io_buf, 0, SECTOR_SIZE * 2);
c00078e1:	83 ec 04             	sub    $0x4,%esp
c00078e4:	68 00 04 00 00       	push   $0x400
c00078e9:	6a 00                	push   $0x0
c00078eb:	ff 75 ec             	push   -0x14(%ebp)
c00078ee:	e8 bb aa ff ff       	call   c00023ae <memset>
c00078f3:	83 c4 10             	add    $0x10,%esp
  if (!sync_dir_entry(
c00078f6:	83 ec 04             	sub    $0x4,%esp
c00078f9:	ff 75 ec             	push   -0x14(%ebp)
c00078fc:	8d 85 64 fd ff ff    	lea    -0x29c(%ebp),%eax
c0007902:	50                   	push   %eax
c0007903:	ff 75 e0             	push   -0x20(%ebp)
c0007906:	e8 c3 15 00 00       	call   c0008ece <sync_dir_entry>
c000790b:	83 c4 10             	add    $0x10,%esp
c000790e:	85 c0                	test   %eax,%eax
c0007910:	75 19                	jne    c000792b <sys_mkdir+0x308>
          parent_dir, &new_dir_entry,
          io_buf)) { // 在父目录中添加自己的目录项，将block_bitmap同步到磁盘
    printk("sys_mkdir: sync_dir_entry to disk failed!\n");
c0007912:	83 ec 0c             	sub    $0xc,%esp
c0007915:	68 a0 d6 00 c0       	push   $0xc000d6a0
c000791a:	e8 95 dd ff ff       	call   c00056b4 <printk>
c000791f:	83 c4 10             	add    $0x10,%esp
    rollback_step = 2;
c0007922:	c6 45 f7 02          	movb   $0x2,-0x9(%ebp)
    goto rollback;
c0007926:	e9 9a 00 00 00       	jmp    c00079c5 <sys_mkdir+0x3a2>
  }

  memset(io_buf, 0, SECTOR_SIZE * 2);
c000792b:	83 ec 04             	sub    $0x4,%esp
c000792e:	68 00 04 00 00       	push   $0x400
c0007933:	6a 00                	push   $0x0
c0007935:	ff 75 ec             	push   -0x14(%ebp)
c0007938:	e8 71 aa ff ff       	call   c00023ae <memset>
c000793d:	83 c4 10             	add    $0x10,%esp
  inode_sync(cur_part, parent_dir->inode, io_buf); // 父目录inode同步到磁盘
c0007940:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0007943:	8b 10                	mov    (%eax),%edx
c0007945:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000794a:	83 ec 04             	sub    $0x4,%esp
c000794d:	ff 75 ec             	push   -0x14(%ebp)
c0007950:	52                   	push   %edx
c0007951:	50                   	push   %eax
c0007952:	e8 07 0c 00 00       	call   c000855e <inode_sync>
c0007957:	83 c4 10             	add    $0x10,%esp
  memset(io_buf, 0, SECTOR_SIZE * 2);
c000795a:	83 ec 04             	sub    $0x4,%esp
c000795d:	68 00 04 00 00       	push   $0x400
c0007962:	6a 00                	push   $0x0
c0007964:	ff 75 ec             	push   -0x14(%ebp)
c0007967:	e8 42 aa ff ff       	call   c00023ae <memset>
c000796c:	83 c4 10             	add    $0x10,%esp
  inode_sync(cur_part, &new_dir_inode, io_buf); // 新创建目录inode同步到磁盘
c000796f:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0007974:	83 ec 04             	sub    $0x4,%esp
c0007977:	ff 75 ec             	push   -0x14(%ebp)
c000797a:	8d 95 7c fd ff ff    	lea    -0x284(%ebp),%edx
c0007980:	52                   	push   %edx
c0007981:	50                   	push   %eax
c0007982:	e8 d7 0b 00 00       	call   c000855e <inode_sync>
c0007987:	83 c4 10             	add    $0x10,%esp
  bitmap_sync(cur_part, inode_no, INODE_BITMAP); // inode_bitmap同步到磁盘
c000798a:	8b 55 f0             	mov    -0x10(%ebp),%edx
c000798d:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0007992:	83 ec 04             	sub    $0x4,%esp
c0007995:	6a 00                	push   $0x0
c0007997:	52                   	push   %edx
c0007998:	50                   	push   %eax
c0007999:	e8 31 22 00 00       	call   c0009bcf <bitmap_sync>
c000799e:	83 c4 10             	add    $0x10,%esp
  sys_free(io_buf);
c00079a1:	83 ec 0c             	sub    $0xc,%esp
c00079a4:	ff 75 ec             	push   -0x14(%ebp)
c00079a7:	e8 97 bc ff ff       	call   c0003643 <sys_free>
c00079ac:	83 c4 10             	add    $0x10,%esp
  dir_close(searched_record.parent_dir); // 关闭所创建目录的父目录
c00079af:	8b 45 c8             	mov    -0x38(%ebp),%eax
c00079b2:	83 ec 0c             	sub    $0xc,%esp
c00079b5:	50                   	push   %eax
c00079b6:	e8 71 14 00 00       	call   c0008e2c <dir_close>
c00079bb:	83 c4 10             	add    $0x10,%esp
  return 0;
c00079be:	b8 00 00 00 00       	mov    $0x0,%eax
c00079c3:	eb 4c                	jmp    c0007a11 <sys_mkdir+0x3ee>

rollback:
  switch (rollback_step) {
c00079c5:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c00079c9:	83 f8 01             	cmp    $0x1,%eax
c00079cc:	74 20                	je     c00079ee <sys_mkdir+0x3cb>
c00079ce:	83 f8 02             	cmp    $0x2,%eax
c00079d1:	75 2b                	jne    c00079fe <sys_mkdir+0x3db>
  case 2: // 新文件inode创建失败，之前位图中分配的inode_no要恢复
    bitmap_set(&cur_part->inode_bitmap, inode_no, 0);
c00079d3:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00079d6:	8b 15 d8 29 01 c0    	mov    0xc00129d8,%edx
c00079dc:	83 c2 28             	add    $0x28,%edx
c00079df:	83 ec 04             	sub    $0x4,%esp
c00079e2:	6a 00                	push   $0x0
c00079e4:	50                   	push   %eax
c00079e5:	52                   	push   %edx
c00079e6:	e8 1e af ff ff       	call   c0002909 <bitmap_set>
c00079eb:	83 c4 10             	add    $0x10,%esp
  case 1:
    // 关闭所创建目录的父目录
    dir_close(searched_record.parent_dir);
c00079ee:	8b 45 c8             	mov    -0x38(%ebp),%eax
c00079f1:	83 ec 0c             	sub    $0xc,%esp
c00079f4:	50                   	push   %eax
c00079f5:	e8 32 14 00 00       	call   c0008e2c <dir_close>
c00079fa:	83 c4 10             	add    $0x10,%esp
    break;
c00079fd:	90                   	nop
  }
  sys_free(io_buf);
c00079fe:	83 ec 0c             	sub    $0xc,%esp
c0007a01:	ff 75 ec             	push   -0x14(%ebp)
c0007a04:	e8 3a bc ff ff       	call   c0003643 <sys_free>
c0007a09:	83 c4 10             	add    $0x10,%esp
  return -1;
c0007a0c:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
}
c0007a11:	c9                   	leave  
c0007a12:	c3                   	ret    

c0007a13 <sys_opendir>:

// 打开目录，成功返回目录指针
struct dir *sys_opendir(const char *name) {
c0007a13:	55                   	push   %ebp
c0007a14:	89 e5                	mov    %esp,%ebp
c0007a16:	81 ec 18 02 00 00    	sub    $0x218,%esp
  ASSERT(strlen(name) < MAX_PATH_LEN);
c0007a1c:	83 ec 0c             	sub    $0xc,%esp
c0007a1f:	ff 75 08             	push   0x8(%ebp)
c0007a22:	e8 13 ab ff ff       	call   c000253a <strlen>
c0007a27:	83 c4 10             	add    $0x10,%esp
c0007a2a:	3d ff 01 00 00       	cmp    $0x1ff,%eax
c0007a2f:	76 1c                	jbe    c0007a4d <sys_opendir+0x3a>
c0007a31:	68 cb d6 00 c0       	push   $0xc000d6cb
c0007a36:	68 4c d9 00 c0       	push   $0xc000d94c
c0007a3b:	68 5e 02 00 00       	push   $0x25e
c0007a40:	68 dd d0 00 c0       	push   $0xc000d0dd
c0007a45:	e8 8e a8 ff ff       	call   c00022d8 <panic_spin>
c0007a4a:	83 c4 10             	add    $0x10,%esp
  // 根目录直接返回&root_dir
  if (name[0] == '/' && (name[1] == 0 || name[0] == '.')) {
c0007a4d:	8b 45 08             	mov    0x8(%ebp),%eax
c0007a50:	0f b6 00             	movzbl (%eax),%eax
c0007a53:	3c 2f                	cmp    $0x2f,%al
c0007a55:	75 21                	jne    c0007a78 <sys_opendir+0x65>
c0007a57:	8b 45 08             	mov    0x8(%ebp),%eax
c0007a5a:	83 c0 01             	add    $0x1,%eax
c0007a5d:	0f b6 00             	movzbl (%eax),%eax
c0007a60:	84 c0                	test   %al,%al
c0007a62:	74 0a                	je     c0007a6e <sys_opendir+0x5b>
c0007a64:	8b 45 08             	mov    0x8(%ebp),%eax
c0007a67:	0f b6 00             	movzbl (%eax),%eax
c0007a6a:	3c 2e                	cmp    $0x2e,%al
c0007a6c:	75 0a                	jne    c0007a78 <sys_opendir+0x65>
    return &root_dir;
c0007a6e:	b8 e0 29 01 c0       	mov    $0xc00129e0,%eax
c0007a73:	e9 a9 00 00 00       	jmp    c0007b21 <sys_opendir+0x10e>
  }

  // 检查待打开目录是否存在
  struct path_search_record searched_record;
  memset(&searched_record, 0, sizeof(struct path_search_record));
c0007a78:	83 ec 04             	sub    $0x4,%esp
c0007a7b:	68 08 02 00 00       	push   $0x208
c0007a80:	6a 00                	push   $0x0
c0007a82:	8d 85 e8 fd ff ff    	lea    -0x218(%ebp),%eax
c0007a88:	50                   	push   %eax
c0007a89:	e8 20 a9 ff ff       	call   c00023ae <memset>
c0007a8e:	83 c4 10             	add    $0x10,%esp
  int inode_no = search_file(name, &searched_record);
c0007a91:	83 ec 08             	sub    $0x8,%esp
c0007a94:	8d 85 e8 fd ff ff    	lea    -0x218(%ebp),%eax
c0007a9a:	50                   	push   %eax
c0007a9b:	ff 75 08             	push   0x8(%ebp)
c0007a9e:	e8 39 f1 ff ff       	call   c0006bdc <search_file>
c0007aa3:	83 c4 10             	add    $0x10,%esp
c0007aa6:	89 45 f0             	mov    %eax,-0x10(%ebp)
  struct dir *ret = NULL;
c0007aa9:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  if (inode_no == -1) {
c0007ab0:	83 7d f0 ff          	cmpl   $0xffffffff,-0x10(%ebp)
c0007ab4:	75 1c                	jne    c0007ad2 <sys_opendir+0xbf>
    printk("In %s, sub path %s not exist\n", name,
c0007ab6:	83 ec 04             	sub    $0x4,%esp
c0007ab9:	8d 85 e8 fd ff ff    	lea    -0x218(%ebp),%eax
c0007abf:	50                   	push   %eax
c0007ac0:	ff 75 08             	push   0x8(%ebp)
c0007ac3:	68 e7 d6 00 c0       	push   $0xc000d6e7
c0007ac8:	e8 e7 db ff ff       	call   c00056b4 <printk>
c0007acd:	83 c4 10             	add    $0x10,%esp
c0007ad0:	eb 3d                	jmp    c0007b0f <sys_opendir+0xfc>
           searched_record.searched_path);
  } else {
    if (searched_record.file_type == FT_REGULAR) {
c0007ad2:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0007ad5:	83 f8 01             	cmp    $0x1,%eax
c0007ad8:	75 15                	jne    c0007aef <sys_opendir+0xdc>
      printk("%s is regular file!\n", name);
c0007ada:	83 ec 08             	sub    $0x8,%esp
c0007add:	ff 75 08             	push   0x8(%ebp)
c0007ae0:	68 05 d7 00 c0       	push   $0xc000d705
c0007ae5:	e8 ca db ff ff       	call   c00056b4 <printk>
c0007aea:	83 c4 10             	add    $0x10,%esp
c0007aed:	eb 20                	jmp    c0007b0f <sys_opendir+0xfc>
    } else if (searched_record.file_type == FT_DIRECTORY) {
c0007aef:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0007af2:	83 f8 02             	cmp    $0x2,%eax
c0007af5:	75 18                	jne    c0007b0f <sys_opendir+0xfc>
      ret = dir_open(cur_part, inode_no);
c0007af7:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0007afa:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0007aff:	83 ec 08             	sub    $0x8,%esp
c0007b02:	52                   	push   %edx
c0007b03:	50                   	push   %eax
c0007b04:	e8 0d 11 00 00       	call   c0008c16 <dir_open>
c0007b09:	83 c4 10             	add    $0x10,%esp
c0007b0c:	89 45 f4             	mov    %eax,-0xc(%ebp)
    }
  }
  dir_close(searched_record.parent_dir);
c0007b0f:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0007b12:	83 ec 0c             	sub    $0xc,%esp
c0007b15:	50                   	push   %eax
c0007b16:	e8 11 13 00 00       	call   c0008e2c <dir_close>
c0007b1b:	83 c4 10             	add    $0x10,%esp
  return ret;
c0007b1e:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0007b21:	c9                   	leave  
c0007b22:	c3                   	ret    

c0007b23 <sys_closedir>:

// 关闭目录，成功返回0，失败返回-1
int32_t sys_closedir(struct dir *dir) {
c0007b23:	55                   	push   %ebp
c0007b24:	89 e5                	mov    %esp,%ebp
c0007b26:	83 ec 18             	sub    $0x18,%esp
  int32_t ret = -1;
c0007b29:	c7 45 f4 ff ff ff ff 	movl   $0xffffffff,-0xc(%ebp)
  if (dir != NULL) {
c0007b30:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c0007b34:	74 15                	je     c0007b4b <sys_closedir+0x28>
    dir_close(dir);
c0007b36:	83 ec 0c             	sub    $0xc,%esp
c0007b39:	ff 75 08             	push   0x8(%ebp)
c0007b3c:	e8 eb 12 00 00       	call   c0008e2c <dir_close>
c0007b41:	83 c4 10             	add    $0x10,%esp
    ret = 0;
c0007b44:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  }
  return ret;
c0007b4b:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0007b4e:	c9                   	leave  
c0007b4f:	c3                   	ret    

c0007b50 <sys_readdir>:

// 读取目录dir的1个目录项，成功后返回其目录项地址
struct dir_entry *sys_readdir(struct dir *dir) {
c0007b50:	55                   	push   %ebp
c0007b51:	89 e5                	mov    %esp,%ebp
c0007b53:	83 ec 08             	sub    $0x8,%esp
  ASSERT(dir != NULL);
c0007b56:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c0007b5a:	75 1c                	jne    c0007b78 <sys_readdir+0x28>
c0007b5c:	68 1a d7 00 c0       	push   $0xc000d71a
c0007b61:	68 58 d9 00 c0       	push   $0xc000d958
c0007b66:	68 83 02 00 00       	push   $0x283
c0007b6b:	68 dd d0 00 c0       	push   $0xc000d0dd
c0007b70:	e8 63 a7 ff ff       	call   c00022d8 <panic_spin>
c0007b75:	83 c4 10             	add    $0x10,%esp
  return dir_read(dir);
c0007b78:	83 ec 0c             	sub    $0xc,%esp
c0007b7b:	ff 75 08             	push   0x8(%ebp)
c0007b7e:	e8 14 1c 00 00       	call   c0009797 <dir_read>
c0007b83:	83 c4 10             	add    $0x10,%esp
}
c0007b86:	c9                   	leave  
c0007b87:	c3                   	ret    

c0007b88 <sys_rewinddir>:

// 把目录dir的指针dir_pos置0
void sys_rewinddir(struct dir *dir) { dir->dir_pos = 0; }
c0007b88:	55                   	push   %ebp
c0007b89:	89 e5                	mov    %esp,%ebp
c0007b8b:	8b 45 08             	mov    0x8(%ebp),%eax
c0007b8e:	c7 40 04 00 00 00 00 	movl   $0x0,0x4(%eax)
c0007b95:	90                   	nop
c0007b96:	5d                   	pop    %ebp
c0007b97:	c3                   	ret    

c0007b98 <sys_rmdir>:

// 删除空目录
int32_t sys_rmdir(const char *pathname) {
c0007b98:	55                   	push   %ebp
c0007b99:	89 e5                	mov    %esp,%ebp
c0007b9b:	81 ec 28 02 00 00    	sub    $0x228,%esp
  // 检查待删除文件是否存在
  struct path_search_record searched_record;
  memset(&searched_record, 0, sizeof(struct path_search_record));
c0007ba1:	83 ec 04             	sub    $0x4,%esp
c0007ba4:	68 08 02 00 00       	push   $0x208
c0007ba9:	6a 00                	push   $0x0
c0007bab:	8d 85 e4 fd ff ff    	lea    -0x21c(%ebp),%eax
c0007bb1:	50                   	push   %eax
c0007bb2:	e8 f7 a7 ff ff       	call   c00023ae <memset>
c0007bb7:	83 c4 10             	add    $0x10,%esp
  int inode_no = search_file(pathname, &searched_record);
c0007bba:	83 ec 08             	sub    $0x8,%esp
c0007bbd:	8d 85 e4 fd ff ff    	lea    -0x21c(%ebp),%eax
c0007bc3:	50                   	push   %eax
c0007bc4:	ff 75 08             	push   0x8(%ebp)
c0007bc7:	e8 10 f0 ff ff       	call   c0006bdc <search_file>
c0007bcc:	83 c4 10             	add    $0x10,%esp
c0007bcf:	89 45 f0             	mov    %eax,-0x10(%ebp)
  ASSERT(inode_no != 0);
c0007bd2:	83 7d f0 00          	cmpl   $0x0,-0x10(%ebp)
c0007bd6:	75 1c                	jne    c0007bf4 <sys_rmdir+0x5c>
c0007bd8:	68 fc d4 00 c0       	push   $0xc000d4fc
c0007bdd:	68 64 d9 00 c0       	push   $0xc000d964
c0007be2:	68 90 02 00 00       	push   $0x290
c0007be7:	68 dd d0 00 c0       	push   $0xc000d0dd
c0007bec:	e8 e7 a6 ff ff       	call   c00022d8 <panic_spin>
c0007bf1:	83 c4 10             	add    $0x10,%esp
  int retval = -1; // 默认返回值
c0007bf4:	c7 45 f4 ff ff ff ff 	movl   $0xffffffff,-0xc(%ebp)
  if (inode_no == -1) {
c0007bfb:	83 7d f0 ff          	cmpl   $0xffffffff,-0x10(%ebp)
c0007bff:	75 1f                	jne    c0007c20 <sys_rmdir+0x88>
    printk("In %s, sub path %s not exist\n", pathname,
c0007c01:	83 ec 04             	sub    $0x4,%esp
c0007c04:	8d 85 e4 fd ff ff    	lea    -0x21c(%ebp),%eax
c0007c0a:	50                   	push   %eax
c0007c0b:	ff 75 08             	push   0x8(%ebp)
c0007c0e:	68 e7 d6 00 c0       	push   $0xc000d6e7
c0007c13:	e8 9c da ff ff       	call   c00056b4 <printk>
c0007c18:	83 c4 10             	add    $0x10,%esp
c0007c1b:	e9 87 00 00 00       	jmp    c0007ca7 <sys_rmdir+0x10f>
           searched_record.searched_path);
  } else {
    if (searched_record.file_type == FT_REGULAR) {
c0007c20:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0007c23:	83 f8 01             	cmp    $0x1,%eax
c0007c26:	75 15                	jne    c0007c3d <sys_rmdir+0xa5>
      printk("%s is regular file!\n", pathname);
c0007c28:	83 ec 08             	sub    $0x8,%esp
c0007c2b:	ff 75 08             	push   0x8(%ebp)
c0007c2e:	68 05 d7 00 c0       	push   $0xc000d705
c0007c33:	e8 7c da ff ff       	call   c00056b4 <printk>
c0007c38:	83 c4 10             	add    $0x10,%esp
c0007c3b:	eb 6a                	jmp    c0007ca7 <sys_rmdir+0x10f>
    } else {
      struct dir *dir = dir_open(cur_part, inode_no);
c0007c3d:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0007c40:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0007c45:	83 ec 08             	sub    $0x8,%esp
c0007c48:	52                   	push   %edx
c0007c49:	50                   	push   %eax
c0007c4a:	e8 c7 0f 00 00       	call   c0008c16 <dir_open>
c0007c4f:	83 c4 10             	add    $0x10,%esp
c0007c52:	89 45 ec             	mov    %eax,-0x14(%ebp)
      if (!dir_is_empty(dir)) { // 非空目录不可删除
c0007c55:	83 ec 0c             	sub    $0xc,%esp
c0007c58:	ff 75 ec             	push   -0x14(%ebp)
c0007c5b:	e8 26 1d 00 00       	call   c0009986 <dir_is_empty>
c0007c60:	83 c4 10             	add    $0x10,%esp
c0007c63:	85 c0                	test   %eax,%eax
c0007c65:	75 15                	jne    c0007c7c <sys_rmdir+0xe4>
        printk("dir %s is not empty, it is not allowed to delete a nonempty "
c0007c67:	83 ec 08             	sub    $0x8,%esp
c0007c6a:	ff 75 08             	push   0x8(%ebp)
c0007c6d:	68 28 d7 00 c0       	push   $0xc000d728
c0007c72:	e8 3d da ff ff       	call   c00056b4 <printk>
c0007c77:	83 c4 10             	add    $0x10,%esp
c0007c7a:	eb 1d                	jmp    c0007c99 <sys_rmdir+0x101>
               "directory!\n",
               pathname);
      } else {
        if (!dir_remove(searched_record.parent_dir, dir)) {
c0007c7c:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0007c7f:	83 ec 08             	sub    $0x8,%esp
c0007c82:	ff 75 ec             	push   -0x14(%ebp)
c0007c85:	50                   	push   %eax
c0007c86:	e8 26 1d 00 00       	call   c00099b1 <dir_remove>
c0007c8b:	83 c4 10             	add    $0x10,%esp
c0007c8e:	85 c0                	test   %eax,%eax
c0007c90:	75 07                	jne    c0007c99 <sys_rmdir+0x101>
          retval = 0;
c0007c92:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
        }
      }
      dir_close(dir);
c0007c99:	83 ec 0c             	sub    $0xc,%esp
c0007c9c:	ff 75 ec             	push   -0x14(%ebp)
c0007c9f:	e8 88 11 00 00       	call   c0008e2c <dir_close>
c0007ca4:	83 c4 10             	add    $0x10,%esp
    }
  }
  dir_close(searched_record.parent_dir);
c0007ca7:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0007caa:	83 ec 0c             	sub    $0xc,%esp
c0007cad:	50                   	push   %eax
c0007cae:	e8 79 11 00 00       	call   c0008e2c <dir_close>
c0007cb3:	83 c4 10             	add    $0x10,%esp
  return retval;
c0007cb6:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0007cb9:	c9                   	leave  
c0007cba:	c3                   	ret    

c0007cbb <get_parent_dir_inode_nr>:

// 获得父目录inode编号（..）
static uint32_t get_parent_dir_inode_nr(uint32_t child_inode_nr, void *io_buf) {
c0007cbb:	55                   	push   %ebp
c0007cbc:	89 e5                	mov    %esp,%ebp
c0007cbe:	83 ec 18             	sub    $0x18,%esp
  struct inode *child_dir_inode = inode_open(cur_part, child_inode_nr);
c0007cc1:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0007cc6:	83 ec 08             	sub    $0x8,%esp
c0007cc9:	ff 75 08             	push   0x8(%ebp)
c0007ccc:	50                   	push   %eax
c0007ccd:	e8 b3 09 00 00       	call   c0008685 <inode_open>
c0007cd2:	83 c4 10             	add    $0x10,%esp
c0007cd5:	89 45 f4             	mov    %eax,-0xc(%ebp)
  // 目录项..（位于目录第0块）包括父目录inode编号
  uint32_t block_lba = child_dir_inode->i_sectors[0];
c0007cd8:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0007cdb:	8b 40 10             	mov    0x10(%eax),%eax
c0007cde:	89 45 f0             	mov    %eax,-0x10(%ebp)
  ASSERT(block_lba >= cur_part->sb->data_start_lba);
c0007ce1:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0007ce6:	8b 40 1c             	mov    0x1c(%eax),%eax
c0007ce9:	8b 40 28             	mov    0x28(%eax),%eax
c0007cec:	39 45 f0             	cmp    %eax,-0x10(%ebp)
c0007cef:	73 1c                	jae    c0007d0d <get_parent_dir_inode_nr+0x52>
c0007cf1:	68 70 d7 00 c0       	push   $0xc000d770
c0007cf6:	68 70 d9 00 c0       	push   $0xc000d970
c0007cfb:	68 af 02 00 00       	push   $0x2af
c0007d00:	68 dd d0 00 c0       	push   $0xc000d0dd
c0007d05:	e8 ce a5 ff ff       	call   c00022d8 <panic_spin>
c0007d0a:	83 c4 10             	add    $0x10,%esp
  inode_close(child_dir_inode);
c0007d0d:	83 ec 0c             	sub    $0xc,%esp
c0007d10:	ff 75 f4             	push   -0xc(%ebp)
c0007d13:	e8 b0 0a 00 00       	call   c00087c8 <inode_close>
c0007d18:	83 c4 10             	add    $0x10,%esp
  ide_read(cur_part->my_disk, block_lba, io_buf, 1);
c0007d1b:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0007d20:	8b 40 08             	mov    0x8(%eax),%eax
c0007d23:	6a 01                	push   $0x1
c0007d25:	ff 75 0c             	push   0xc(%ebp)
c0007d28:	ff 75 f0             	push   -0x10(%ebp)
c0007d2b:	50                   	push   %eax
c0007d2c:	e8 fa dc ff ff       	call   c0005a2b <ide_read>
c0007d31:	83 c4 10             	add    $0x10,%esp
  struct dir_entry *dir_e = (struct dir_entry *)io_buf;
c0007d34:	8b 45 0c             	mov    0xc(%ebp),%eax
c0007d37:	89 45 ec             	mov    %eax,-0x14(%ebp)
  /* 第0个目录项是 . ，第1个目录项是 .. */
  ASSERT(dir_e[1].i_no < 4096 && dir_e[1].f_type == FT_DIRECTORY);
c0007d3a:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0007d3d:	83 c0 18             	add    $0x18,%eax
c0007d40:	8b 40 10             	mov    0x10(%eax),%eax
c0007d43:	3d ff 0f 00 00       	cmp    $0xfff,%eax
c0007d48:	77 0e                	ja     c0007d58 <get_parent_dir_inode_nr+0x9d>
c0007d4a:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0007d4d:	83 c0 18             	add    $0x18,%eax
c0007d50:	8b 40 14             	mov    0x14(%eax),%eax
c0007d53:	83 f8 02             	cmp    $0x2,%eax
c0007d56:	74 1c                	je     c0007d74 <get_parent_dir_inode_nr+0xb9>
c0007d58:	68 9c d7 00 c0       	push   $0xc000d79c
c0007d5d:	68 70 d9 00 c0       	push   $0xc000d970
c0007d62:	68 b4 02 00 00       	push   $0x2b4
c0007d67:	68 dd d0 00 c0       	push   $0xc000d0dd
c0007d6c:	e8 67 a5 ff ff       	call   c00022d8 <panic_spin>
c0007d71:	83 c4 10             	add    $0x10,%esp
  return dir_e[1].i_no; // 返回..的inode编号
c0007d74:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0007d77:	83 c0 18             	add    $0x18,%eax
c0007d7a:	8b 40 10             	mov    0x10(%eax),%eax
}
c0007d7d:	c9                   	leave  
c0007d7e:	c3                   	ret    

c0007d7f <get_child_dir_name>:

// 在目录中查找子目录的名字存入缓冲区path
static int get_child_dir_name(uint32_t p_inode_nr, uint32_t c_inode_nr,
                              char *path, void *io_buf) {
c0007d7f:	55                   	push   %ebp
c0007d80:	89 e5                	mov    %esp,%ebp
c0007d82:	57                   	push   %edi
c0007d83:	81 ec 54 02 00 00    	sub    $0x254,%esp
  // 打开父目录inode，填充all_blocks
  struct inode *parent_dir_inode = inode_open(cur_part, p_inode_nr);
c0007d89:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0007d8e:	83 ec 08             	sub    $0x8,%esp
c0007d91:	ff 75 08             	push   0x8(%ebp)
c0007d94:	50                   	push   %eax
c0007d95:	e8 eb 08 00 00       	call   c0008685 <inode_open>
c0007d9a:	83 c4 10             	add    $0x10,%esp
c0007d9d:	89 45 e8             	mov    %eax,-0x18(%ebp)
  uint8_t block_idx = 0;
c0007da0:	c6 45 f7 00          	movb   $0x0,-0x9(%ebp)
  uint32_t all_blocks[140] = {0}, block_cnt = 12;
c0007da4:	8d 95 ac fd ff ff    	lea    -0x254(%ebp),%edx
c0007daa:	b8 00 00 00 00       	mov    $0x0,%eax
c0007daf:	b9 8c 00 00 00       	mov    $0x8c,%ecx
c0007db4:	89 d7                	mov    %edx,%edi
c0007db6:	f3 ab                	rep stos %eax,%es:(%edi)
c0007db8:	c7 45 f0 0c 00 00 00 	movl   $0xc,-0x10(%ebp)
  while (block_idx < 12) {
c0007dbf:	eb 22                	jmp    c0007de3 <get_child_dir_name+0x64>
    all_blocks[block_idx] = parent_dir_inode->i_sectors[block_idx];
c0007dc1:	0f b6 4d f7          	movzbl -0x9(%ebp),%ecx
c0007dc5:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0007dc9:	8b 55 e8             	mov    -0x18(%ebp),%edx
c0007dcc:	83 c1 04             	add    $0x4,%ecx
c0007dcf:	8b 14 8a             	mov    (%edx,%ecx,4),%edx
c0007dd2:	89 94 85 ac fd ff ff 	mov    %edx,-0x254(%ebp,%eax,4)
    block_idx++;
c0007dd9:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0007ddd:	83 c0 01             	add    $0x1,%eax
c0007de0:	88 45 f7             	mov    %al,-0x9(%ebp)
  while (block_idx < 12) {
c0007de3:	80 7d f7 0b          	cmpb   $0xb,-0x9(%ebp)
c0007de7:	76 d8                	jbe    c0007dc1 <get_child_dir_name+0x42>
  }
  if (parent_dir_inode->i_sectors[12]) { // 包含一级间接块表
c0007de9:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0007dec:	8b 40 40             	mov    0x40(%eax),%eax
c0007def:	85 c0                	test   %eax,%eax
c0007df1:	74 2c                	je     c0007e1f <get_child_dir_name+0xa0>
    ide_read(cur_part->my_disk, parent_dir_inode->i_sectors[12],
c0007df3:	8d 85 ac fd ff ff    	lea    -0x254(%ebp),%eax
c0007df9:	83 c0 30             	add    $0x30,%eax
c0007dfc:	8b 55 e8             	mov    -0x18(%ebp),%edx
c0007dff:	8b 4a 40             	mov    0x40(%edx),%ecx
c0007e02:	8b 15 d8 29 01 c0    	mov    0xc00129d8,%edx
c0007e08:	8b 52 08             	mov    0x8(%edx),%edx
c0007e0b:	6a 01                	push   $0x1
c0007e0d:	50                   	push   %eax
c0007e0e:	51                   	push   %ecx
c0007e0f:	52                   	push   %edx
c0007e10:	e8 16 dc ff ff       	call   c0005a2b <ide_read>
c0007e15:	83 c4 10             	add    $0x10,%esp
             all_blocks + 12, 1);
    block_cnt = 140;
c0007e18:	c7 45 f0 8c 00 00 00 	movl   $0x8c,-0x10(%ebp)
  }
  inode_close(parent_dir_inode);
c0007e1f:	83 ec 0c             	sub    $0xc,%esp
c0007e22:	ff 75 e8             	push   -0x18(%ebp)
c0007e25:	e8 9e 09 00 00       	call   c00087c8 <inode_close>
c0007e2a:	83 c4 10             	add    $0x10,%esp

  struct dir_entry *dir_e = (struct dir_entry *)io_buf;
c0007e2d:	8b 45 14             	mov    0x14(%ebp),%eax
c0007e30:	89 45 e4             	mov    %eax,-0x1c(%ebp)
  uint32_t dir_entry_size = cur_part->sb->dir_entry_size;
c0007e33:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0007e38:	8b 40 1c             	mov    0x1c(%eax),%eax
c0007e3b:	8b 40 30             	mov    0x30(%eax),%eax
c0007e3e:	89 45 e0             	mov    %eax,-0x20(%ebp)
  uint32_t dir_entrys_per_sec = (512 / dir_entry_size);
c0007e41:	b8 00 02 00 00       	mov    $0x200,%eax
c0007e46:	ba 00 00 00 00       	mov    $0x0,%edx
c0007e4b:	f7 75 e0             	divl   -0x20(%ebp)
c0007e4e:	89 45 dc             	mov    %eax,-0x24(%ebp)
  block_idx = 0;
c0007e51:	c6 45 f7 00          	movb   $0x0,-0x9(%ebp)

  // 遍历所有块
  while (block_idx < block_cnt) {
c0007e55:	e9 b1 00 00 00       	jmp    c0007f0b <get_child_dir_name+0x18c>
    if (all_blocks[block_idx]) { // 相应块不为空-> 读入相应块
c0007e5a:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0007e5e:	8b 84 85 ac fd ff ff 	mov    -0x254(%ebp,%eax,4),%eax
c0007e65:	85 c0                	test   %eax,%eax
c0007e67:	0f 84 94 00 00 00    	je     c0007f01 <get_child_dir_name+0x182>
      ide_read(cur_part->my_disk, all_blocks[block_idx], io_buf, 1);
c0007e6d:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0007e71:	8b 94 85 ac fd ff ff 	mov    -0x254(%ebp,%eax,4),%edx
c0007e78:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0007e7d:	8b 40 08             	mov    0x8(%eax),%eax
c0007e80:	6a 01                	push   $0x1
c0007e82:	ff 75 14             	push   0x14(%ebp)
c0007e85:	52                   	push   %edx
c0007e86:	50                   	push   %eax
c0007e87:	e8 9f db ff ff       	call   c0005a2b <ide_read>
c0007e8c:	83 c4 10             	add    $0x10,%esp
      uint8_t dir_e_idx = 0;
c0007e8f:	c6 45 ef 00          	movb   $0x0,-0x11(%ebp)
      // 遍历每个目录项
      while (dir_e_idx < dir_entrys_per_sec) {
c0007e93:	eb 63                	jmp    c0007ef8 <get_child_dir_name+0x179>
        if ((dir_e + dir_e_idx)->i_no == c_inode_nr) {
c0007e95:	0f b6 55 ef          	movzbl -0x11(%ebp),%edx
c0007e99:	89 d0                	mov    %edx,%eax
c0007e9b:	01 c0                	add    %eax,%eax
c0007e9d:	01 d0                	add    %edx,%eax
c0007e9f:	c1 e0 03             	shl    $0x3,%eax
c0007ea2:	89 c2                	mov    %eax,%edx
c0007ea4:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0007ea7:	01 d0                	add    %edx,%eax
c0007ea9:	8b 40 10             	mov    0x10(%eax),%eax
c0007eac:	39 45 0c             	cmp    %eax,0xc(%ebp)
c0007eaf:	75 3d                	jne    c0007eee <get_child_dir_name+0x16f>
          strcat(path, "/");
c0007eb1:	83 ec 08             	sub    $0x8,%esp
c0007eb4:	68 a1 d2 00 c0       	push   $0xc000d2a1
c0007eb9:	ff 75 10             	push   0x10(%ebp)
c0007ebc:	e8 ef a7 ff ff       	call   c00026b0 <strcat>
c0007ec1:	83 c4 10             	add    $0x10,%esp
          strcat(path, (dir_e + dir_e_idx)->filename);
c0007ec4:	0f b6 55 ef          	movzbl -0x11(%ebp),%edx
c0007ec8:	89 d0                	mov    %edx,%eax
c0007eca:	01 c0                	add    %eax,%eax
c0007ecc:	01 d0                	add    %edx,%eax
c0007ece:	c1 e0 03             	shl    $0x3,%eax
c0007ed1:	89 c2                	mov    %eax,%edx
c0007ed3:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0007ed6:	01 d0                	add    %edx,%eax
c0007ed8:	83 ec 08             	sub    $0x8,%esp
c0007edb:	50                   	push   %eax
c0007edc:	ff 75 10             	push   0x10(%ebp)
c0007edf:	e8 cc a7 ff ff       	call   c00026b0 <strcat>
c0007ee4:	83 c4 10             	add    $0x10,%esp
          return 0;
c0007ee7:	b8 00 00 00 00       	mov    $0x0,%eax
c0007eec:	eb 2f                	jmp    c0007f1d <get_child_dir_name+0x19e>
        }
        dir_e_idx++;
c0007eee:	0f b6 45 ef          	movzbl -0x11(%ebp),%eax
c0007ef2:	83 c0 01             	add    $0x1,%eax
c0007ef5:	88 45 ef             	mov    %al,-0x11(%ebp)
      while (dir_e_idx < dir_entrys_per_sec) {
c0007ef8:	0f b6 45 ef          	movzbl -0x11(%ebp),%eax
c0007efc:	39 45 dc             	cmp    %eax,-0x24(%ebp)
c0007eff:	77 94                	ja     c0007e95 <get_child_dir_name+0x116>
      }
    }
    block_idx++;
c0007f01:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0007f05:	83 c0 01             	add    $0x1,%eax
c0007f08:	88 45 f7             	mov    %al,-0x9(%ebp)
  while (block_idx < block_cnt) {
c0007f0b:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0007f0f:	39 45 f0             	cmp    %eax,-0x10(%ebp)
c0007f12:	0f 87 42 ff ff ff    	ja     c0007e5a <get_child_dir_name+0xdb>
  }
  return -1;
c0007f18:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
}
c0007f1d:	8b 7d fc             	mov    -0x4(%ebp),%edi
c0007f20:	c9                   	leave  
c0007f21:	c3                   	ret    

c0007f22 <sys_getcwd>:

// 把当前工作目录绝对路径写入buf（size是buf的大小
char *sys_getcwd(char *buf, uint32_t size) {
c0007f22:	55                   	push   %ebp
c0007f23:	89 e5                	mov    %esp,%ebp
c0007f25:	57                   	push   %edi
c0007f26:	53                   	push   %ebx
c0007f27:	81 ec 20 02 00 00    	sub    $0x220,%esp
  ASSERT(buf != NULL);
c0007f2d:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c0007f31:	75 1c                	jne    c0007f4f <sys_getcwd+0x2d>
c0007f33:	68 8e d4 00 c0       	push   $0xc000d48e
c0007f38:	68 88 d9 00 c0       	push   $0xc000d988
c0007f3d:	68 e5 02 00 00       	push   $0x2e5
c0007f42:	68 dd d0 00 c0       	push   $0xc000d0dd
c0007f47:	e8 8c a3 ff ff       	call   c00022d8 <panic_spin>
c0007f4c:	83 c4 10             	add    $0x10,%esp
  void *io_buf = sys_malloc(SECTOR_SIZE);
c0007f4f:	83 ec 0c             	sub    $0xc,%esp
c0007f52:	68 00 02 00 00       	push   $0x200
c0007f57:	e8 c8 b0 ff ff       	call   c0003024 <sys_malloc>
c0007f5c:	83 c4 10             	add    $0x10,%esp
c0007f5f:	89 45 f0             	mov    %eax,-0x10(%ebp)
  if (io_buf == NULL) {
c0007f62:	83 7d f0 00          	cmpl   $0x0,-0x10(%ebp)
c0007f66:	75 0a                	jne    c0007f72 <sys_getcwd+0x50>
    return NULL;
c0007f68:	b8 00 00 00 00       	mov    $0x0,%eax
c0007f6d:	e9 99 01 00 00       	jmp    c000810b <sys_getcwd+0x1e9>
  }
  struct task_struct *cur_thread = running_thread();
c0007f72:	e8 98 bb ff ff       	call   c0003b0f <running_thread>
c0007f77:	89 45 ec             	mov    %eax,-0x14(%ebp)
  int32_t parent_inode_nr = 0;
c0007f7a:	c7 45 e8 00 00 00 00 	movl   $0x0,-0x18(%ebp)
  int32_t child_inode_nr = cur_thread->cwd_inode_nr;
c0007f81:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0007f84:	8b 80 0c 01 00 00    	mov    0x10c(%eax),%eax
c0007f8a:	89 45 f4             	mov    %eax,-0xc(%ebp)
  ASSERT(child_inode_nr >= 0 && child_inode_nr < 4096); // 最大支持4096个inode
c0007f8d:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
c0007f91:	78 09                	js     c0007f9c <sys_getcwd+0x7a>
c0007f93:	81 7d f4 ff 0f 00 00 	cmpl   $0xfff,-0xc(%ebp)
c0007f9a:	7e 1c                	jle    c0007fb8 <sys_getcwd+0x96>
c0007f9c:	68 d4 d7 00 c0       	push   $0xc000d7d4
c0007fa1:	68 88 d9 00 c0       	push   $0xc000d988
c0007fa6:	68 ed 02 00 00       	push   $0x2ed
c0007fab:	68 dd d0 00 c0       	push   $0xc000d0dd
c0007fb0:	e8 23 a3 ff ff       	call   c00022d8 <panic_spin>
c0007fb5:	83 c4 10             	add    $0x10,%esp
  if (child_inode_nr == 0) { // 当前目录是根目录
c0007fb8:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
c0007fbc:	75 17                	jne    c0007fd5 <sys_getcwd+0xb3>
    buf[0] = '/';
c0007fbe:	8b 45 08             	mov    0x8(%ebp),%eax
c0007fc1:	c6 00 2f             	movb   $0x2f,(%eax)
    buf[1] = 0;
c0007fc4:	8b 45 08             	mov    0x8(%ebp),%eax
c0007fc7:	83 c0 01             	add    $0x1,%eax
c0007fca:	c6 00 00             	movb   $0x0,(%eax)
    return buf;
c0007fcd:	8b 45 08             	mov    0x8(%ebp),%eax
c0007fd0:	e9 36 01 00 00       	jmp    c000810b <sys_getcwd+0x1e9>
  }
  memset(buf, 0, size);
c0007fd5:	83 ec 04             	sub    $0x4,%esp
c0007fd8:	ff 75 0c             	push   0xc(%ebp)
c0007fdb:	6a 00                	push   $0x0
c0007fdd:	ff 75 08             	push   0x8(%ebp)
c0007fe0:	e8 c9 a3 ff ff       	call   c00023ae <memset>
c0007fe5:	83 c4 10             	add    $0x10,%esp
  char full_path_reverse[MAX_PATH_LEN] = {0}; // 用来做全路径缓冲区
c0007fe8:	c7 85 e2 fd ff ff 00 	movl   $0x0,-0x21e(%ebp)
c0007fef:	00 00 00 
c0007ff2:	8d 85 e6 fd ff ff    	lea    -0x21a(%ebp),%eax
c0007ff8:	b9 fc 01 00 00       	mov    $0x1fc,%ecx
c0007ffd:	bb 00 00 00 00       	mov    $0x0,%ebx
c0008002:	89 18                	mov    %ebx,(%eax)
c0008004:	89 5c 08 fc          	mov    %ebx,-0x4(%eax,%ecx,1)
c0008008:	8d 50 04             	lea    0x4(%eax),%edx
c000800b:	83 e2 fc             	and    $0xfffffffc,%edx
c000800e:	29 d0                	sub    %edx,%eax
c0008010:	01 c1                	add    %eax,%ecx
c0008012:	83 e1 fc             	and    $0xfffffffc,%ecx
c0008015:	c1 e9 02             	shr    $0x2,%ecx
c0008018:	89 d7                	mov    %edx,%edi
c000801a:	89 d8                	mov    %ebx,%eax
c000801c:	f3 ab                	rep stos %eax,%es:(%edi)
  /* 从下往上逐层找父目录，直到找到根目录为止 */
  while ((child_inode_nr)) {
c000801e:	eb 52                	jmp    c0008072 <sys_getcwd+0x150>
    parent_inode_nr = get_parent_dir_inode_nr(child_inode_nr, io_buf);
c0008020:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0008023:	83 ec 08             	sub    $0x8,%esp
c0008026:	ff 75 f0             	push   -0x10(%ebp)
c0008029:	50                   	push   %eax
c000802a:	e8 8c fc ff ff       	call   c0007cbb <get_parent_dir_inode_nr>
c000802f:	83 c4 10             	add    $0x10,%esp
c0008032:	89 45 e8             	mov    %eax,-0x18(%ebp)
    if (get_child_dir_name(parent_inode_nr, child_inode_nr, full_path_reverse,
c0008035:	8b 55 f4             	mov    -0xc(%ebp),%edx
c0008038:	8b 45 e8             	mov    -0x18(%ebp),%eax
c000803b:	ff 75 f0             	push   -0x10(%ebp)
c000803e:	8d 8d e2 fd ff ff    	lea    -0x21e(%ebp),%ecx
c0008044:	51                   	push   %ecx
c0008045:	52                   	push   %edx
c0008046:	50                   	push   %eax
c0008047:	e8 33 fd ff ff       	call   c0007d7f <get_child_dir_name>
c000804c:	83 c4 10             	add    $0x10,%esp
c000804f:	83 f8 ff             	cmp    $0xffffffff,%eax
c0008052:	75 18                	jne    c000806c <sys_getcwd+0x14a>
                           io_buf) == -1) { // 或未找到名字，失败退出
      sys_free(io_buf);
c0008054:	83 ec 0c             	sub    $0xc,%esp
c0008057:	ff 75 f0             	push   -0x10(%ebp)
c000805a:	e8 e4 b5 ff ff       	call   c0003643 <sys_free>
c000805f:	83 c4 10             	add    $0x10,%esp
      return NULL;
c0008062:	b8 00 00 00 00       	mov    $0x0,%eax
c0008067:	e9 9f 00 00 00       	jmp    c000810b <sys_getcwd+0x1e9>
    }
    child_inode_nr = parent_inode_nr;
c000806c:	8b 45 e8             	mov    -0x18(%ebp),%eax
c000806f:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while ((child_inode_nr)) {
c0008072:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
c0008076:	75 a8                	jne    c0008020 <sys_getcwd+0xfe>
  }
  ASSERT(strlen(full_path_reverse) <= size);
c0008078:	83 ec 0c             	sub    $0xc,%esp
c000807b:	8d 85 e2 fd ff ff    	lea    -0x21e(%ebp),%eax
c0008081:	50                   	push   %eax
c0008082:	e8 b3 a4 ff ff       	call   c000253a <strlen>
c0008087:	83 c4 10             	add    $0x10,%esp
c000808a:	39 45 0c             	cmp    %eax,0xc(%ebp)
c000808d:	73 4e                	jae    c00080dd <sys_getcwd+0x1bb>
c000808f:	68 04 d8 00 c0       	push   $0xc000d804
c0008094:	68 88 d9 00 c0       	push   $0xc000d988
c0008099:	68 ff 02 00 00       	push   $0x2ff
c000809e:	68 dd d0 00 c0       	push   $0xc000d0dd
c00080a3:	e8 30 a2 ff ff       	call   c00022d8 <panic_spin>
c00080a8:	83 c4 10             	add    $0x10,%esp
  /* 至此full_path_reverse中的路径是反着的，
   * 即子目录在前（左），父目录在后（右），现将full_path_reverse中的路径反置
   */
  char *last_slash; // 记录字符串中最后一个斜杠地址
  while ((last_slash = strrchr(full_path_reverse, '/'))) {
c00080ab:	eb 30                	jmp    c00080dd <sys_getcwd+0x1bb>
    uint16_t len = strlen(buf);
c00080ad:	83 ec 0c             	sub    $0xc,%esp
c00080b0:	ff 75 08             	push   0x8(%ebp)
c00080b3:	e8 82 a4 ff ff       	call   c000253a <strlen>
c00080b8:	83 c4 10             	add    $0x10,%esp
c00080bb:	66 89 45 e2          	mov    %ax,-0x1e(%ebp)
    strcpy(buf + len, last_slash);
c00080bf:	0f b7 55 e2          	movzwl -0x1e(%ebp),%edx
c00080c3:	8b 45 08             	mov    0x8(%ebp),%eax
c00080c6:	01 d0                	add    %edx,%eax
c00080c8:	83 ec 08             	sub    $0x8,%esp
c00080cb:	ff 75 e4             	push   -0x1c(%ebp)
c00080ce:	50                   	push   %eax
c00080cf:	e8 11 a4 ff ff       	call   c00024e5 <strcpy>
c00080d4:	83 c4 10             	add    $0x10,%esp
    // 在full_path_reverse中添加结束字符，作为下次执行strcpy中last_slash的边界
    *last_slash = 0;
c00080d7:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c00080da:	c6 00 00             	movb   $0x0,(%eax)
  while ((last_slash = strrchr(full_path_reverse, '/'))) {
c00080dd:	83 ec 08             	sub    $0x8,%esp
c00080e0:	6a 2f                	push   $0x2f
c00080e2:	8d 85 e2 fd ff ff    	lea    -0x21e(%ebp),%eax
c00080e8:	50                   	push   %eax
c00080e9:	e8 64 a5 ff ff       	call   c0002652 <strrchr>
c00080ee:	83 c4 10             	add    $0x10,%esp
c00080f1:	89 45 e4             	mov    %eax,-0x1c(%ebp)
c00080f4:	83 7d e4 00          	cmpl   $0x0,-0x1c(%ebp)
c00080f8:	75 b3                	jne    c00080ad <sys_getcwd+0x18b>
  }
  sys_free(io_buf);
c00080fa:	83 ec 0c             	sub    $0xc,%esp
c00080fd:	ff 75 f0             	push   -0x10(%ebp)
c0008100:	e8 3e b5 ff ff       	call   c0003643 <sys_free>
c0008105:	83 c4 10             	add    $0x10,%esp
  return buf;
c0008108:	8b 45 08             	mov    0x8(%ebp),%eax
}
c000810b:	8d 65 f8             	lea    -0x8(%ebp),%esp
c000810e:	5b                   	pop    %ebx
c000810f:	5f                   	pop    %edi
c0008110:	5d                   	pop    %ebp
c0008111:	c3                   	ret    

c0008112 <sys_chdir>:

// 修改当前工作目录为绝对路径path
int32_t sys_chdir(const char *path) {
c0008112:	55                   	push   %ebp
c0008113:	89 e5                	mov    %esp,%ebp
c0008115:	81 ec 18 02 00 00    	sub    $0x218,%esp
  int32_t ret = -1;
c000811b:	c7 45 f4 ff ff ff ff 	movl   $0xffffffff,-0xc(%ebp)
  struct path_search_record searched_record;
  memset(&searched_record, 0, sizeof(struct path_search_record));
c0008122:	83 ec 04             	sub    $0x4,%esp
c0008125:	68 08 02 00 00       	push   $0x208
c000812a:	6a 00                	push   $0x0
c000812c:	8d 85 e8 fd ff ff    	lea    -0x218(%ebp),%eax
c0008132:	50                   	push   %eax
c0008133:	e8 76 a2 ff ff       	call   c00023ae <memset>
c0008138:	83 c4 10             	add    $0x10,%esp
  int inode_no = search_file(path, &searched_record);
c000813b:	83 ec 08             	sub    $0x8,%esp
c000813e:	8d 85 e8 fd ff ff    	lea    -0x218(%ebp),%eax
c0008144:	50                   	push   %eax
c0008145:	ff 75 08             	push   0x8(%ebp)
c0008148:	e8 8f ea ff ff       	call   c0006bdc <search_file>
c000814d:	83 c4 10             	add    $0x10,%esp
c0008150:	89 45 f0             	mov    %eax,-0x10(%ebp)
  if (inode_no != -1) {
c0008153:	83 7d f0 ff          	cmpl   $0xffffffff,-0x10(%ebp)
c0008157:	74 32                	je     c000818b <sys_chdir+0x79>
    // 找到path并且要为目录
    if (searched_record.file_type == FT_DIRECTORY) {
c0008159:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000815c:	83 f8 02             	cmp    $0x2,%eax
c000815f:	75 17                	jne    c0008178 <sys_chdir+0x66>
      running_thread()->cwd_inode_nr = inode_no;
c0008161:	e8 a9 b9 ff ff       	call   c0003b0f <running_thread>
c0008166:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0008169:	89 90 0c 01 00 00    	mov    %edx,0x10c(%eax)
      ret = 0;
c000816f:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
c0008176:	eb 13                	jmp    c000818b <sys_chdir+0x79>
    } else {
      printk("sys_chdir: %s is regular file or other!\n", path);
c0008178:	83 ec 08             	sub    $0x8,%esp
c000817b:	ff 75 08             	push   0x8(%ebp)
c000817e:	68 28 d8 00 c0       	push   $0xc000d828
c0008183:	e8 2c d5 ff ff       	call   c00056b4 <printk>
c0008188:	83 c4 10             	add    $0x10,%esp
    }
  }
  dir_close(searched_record.parent_dir);
c000818b:	8b 45 e8             	mov    -0x18(%ebp),%eax
c000818e:	83 ec 0c             	sub    $0xc,%esp
c0008191:	50                   	push   %eax
c0008192:	e8 95 0c 00 00       	call   c0008e2c <dir_close>
c0008197:	83 c4 10             	add    $0x10,%esp
  return ret;
c000819a:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c000819d:	c9                   	leave  
c000819e:	c3                   	ret    

c000819f <sys_stat>:

// 将文件属性填充到buf中
int32_t sys_stat(const char *path, struct stat *buf) {
c000819f:	55                   	push   %ebp
c00081a0:	89 e5                	mov    %esp,%ebp
c00081a2:	81 ec 28 02 00 00    	sub    $0x228,%esp
  // path是否为根目录
  if (!strcmp(path, "/") || !strcmp(path, "/.") || !strcmp(path, "/..")) {
c00081a8:	83 ec 08             	sub    $0x8,%esp
c00081ab:	68 a1 d2 00 c0       	push   $0xc000d2a1
c00081b0:	ff 75 08             	push   0x8(%ebp)
c00081b3:	e8 c9 a3 ff ff       	call   c0002581 <strcmp>
c00081b8:	83 c4 10             	add    $0x10,%esp
c00081bb:	84 c0                	test   %al,%al
c00081bd:	74 2e                	je     c00081ed <sys_stat+0x4e>
c00081bf:	83 ec 08             	sub    $0x8,%esp
c00081c2:	68 a3 d2 00 c0       	push   $0xc000d2a3
c00081c7:	ff 75 08             	push   0x8(%ebp)
c00081ca:	e8 b2 a3 ff ff       	call   c0002581 <strcmp>
c00081cf:	83 c4 10             	add    $0x10,%esp
c00081d2:	84 c0                	test   %al,%al
c00081d4:	74 17                	je     c00081ed <sys_stat+0x4e>
c00081d6:	83 ec 08             	sub    $0x8,%esp
c00081d9:	68 a6 d2 00 c0       	push   $0xc000d2a6
c00081de:	ff 75 08             	push   0x8(%ebp)
c00081e1:	e8 9b a3 ff ff       	call   c0002581 <strcmp>
c00081e6:	83 c4 10             	add    $0x10,%esp
c00081e9:	84 c0                	test   %al,%al
c00081eb:	75 2b                	jne    c0008218 <sys_stat+0x79>
    buf->st_filetype = FT_DIRECTORY;
c00081ed:	8b 45 0c             	mov    0xc(%ebp),%eax
c00081f0:	c7 40 08 02 00 00 00 	movl   $0x2,0x8(%eax)
    buf->st_ino = 0;
c00081f7:	8b 45 0c             	mov    0xc(%ebp),%eax
c00081fa:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
    buf->st_size = root_dir.inode->i_size;
c0008200:	a1 e0 29 01 c0       	mov    0xc00129e0,%eax
c0008205:	8b 50 04             	mov    0x4(%eax),%edx
c0008208:	8b 45 0c             	mov    0xc(%ebp),%eax
c000820b:	89 50 04             	mov    %edx,0x4(%eax)
    return 0;
c000820e:	b8 00 00 00 00       	mov    $0x0,%eax
c0008213:	e9 af 00 00 00       	jmp    c00082c7 <sys_stat+0x128>
  }
  int32_t ret = -1;
c0008218:	c7 45 f4 ff ff ff ff 	movl   $0xffffffff,-0xc(%ebp)
  struct path_search_record searched_record;
  memset(&searched_record, 0, sizeof(struct path_search_record));
c000821f:	83 ec 04             	sub    $0x4,%esp
c0008222:	68 08 02 00 00       	push   $0x208
c0008227:	6a 00                	push   $0x0
c0008229:	8d 85 e4 fd ff ff    	lea    -0x21c(%ebp),%eax
c000822f:	50                   	push   %eax
c0008230:	e8 79 a1 ff ff       	call   c00023ae <memset>
c0008235:	83 c4 10             	add    $0x10,%esp
  int inode_no = search_file(path, &searched_record);
c0008238:	83 ec 08             	sub    $0x8,%esp
c000823b:	8d 85 e4 fd ff ff    	lea    -0x21c(%ebp),%eax
c0008241:	50                   	push   %eax
c0008242:	ff 75 08             	push   0x8(%ebp)
c0008245:	e8 92 e9 ff ff       	call   c0006bdc <search_file>
c000824a:	83 c4 10             	add    $0x10,%esp
c000824d:	89 45 f0             	mov    %eax,-0x10(%ebp)
  if (inode_no != -1) {
c0008250:	83 7d f0 ff          	cmpl   $0xffffffff,-0x10(%ebp)
c0008254:	74 4c                	je     c00082a2 <sys_stat+0x103>
    struct inode *obj_inode =
        inode_open(cur_part, inode_no); // 只为获得文件大小
c0008256:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0008259:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000825e:	83 ec 08             	sub    $0x8,%esp
c0008261:	52                   	push   %edx
c0008262:	50                   	push   %eax
c0008263:	e8 1d 04 00 00       	call   c0008685 <inode_open>
c0008268:	83 c4 10             	add    $0x10,%esp
c000826b:	89 45 ec             	mov    %eax,-0x14(%ebp)
    buf->st_size = obj_inode->i_size;
c000826e:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0008271:	8b 50 04             	mov    0x4(%eax),%edx
c0008274:	8b 45 0c             	mov    0xc(%ebp),%eax
c0008277:	89 50 04             	mov    %edx,0x4(%eax)
    inode_close(obj_inode);
c000827a:	83 ec 0c             	sub    $0xc,%esp
c000827d:	ff 75 ec             	push   -0x14(%ebp)
c0008280:	e8 43 05 00 00       	call   c00087c8 <inode_close>
c0008285:	83 c4 10             	add    $0x10,%esp
    buf->st_filetype = searched_record.file_type;
c0008288:	8b 55 e8             	mov    -0x18(%ebp),%edx
c000828b:	8b 45 0c             	mov    0xc(%ebp),%eax
c000828e:	89 50 08             	mov    %edx,0x8(%eax)
    buf->st_ino = inode_no;
c0008291:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0008294:	8b 45 0c             	mov    0xc(%ebp),%eax
c0008297:	89 10                	mov    %edx,(%eax)
    ret = 0;
c0008299:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
c00082a0:	eb 13                	jmp    c00082b5 <sys_stat+0x116>
  } else {
    printk("sys_stat: %s not found\n", path);
c00082a2:	83 ec 08             	sub    $0x8,%esp
c00082a5:	ff 75 08             	push   0x8(%ebp)
c00082a8:	68 51 d8 00 c0       	push   $0xc000d851
c00082ad:	e8 02 d4 ff ff       	call   c00056b4 <printk>
c00082b2:	83 c4 10             	add    $0x10,%esp
  }
  dir_close(searched_record.parent_dir);
c00082b5:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c00082b8:	83 ec 0c             	sub    $0xc,%esp
c00082bb:	50                   	push   %eax
c00082bc:	e8 6b 0b 00 00       	call   c0008e2c <dir_close>
c00082c1:	83 c4 10             	add    $0x10,%esp
  return ret;
c00082c4:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c00082c7:	c9                   	leave  
c00082c8:	c3                   	ret    

c00082c9 <filesys_init>:

// 在磁盘上搜索文件系统，若没有则格式化分区创建文件系统
void filesys_init() {
c00082c9:	55                   	push   %ebp
c00082ca:	89 e5                	mov    %esp,%ebp
c00082cc:	83 ec 28             	sub    $0x28,%esp
  uint8_t channel_no = 0, dev_no, part_idx = 0;
c00082cf:	c6 45 f7 00          	movb   $0x0,-0x9(%ebp)
c00082d3:	c6 45 f5 00          	movb   $0x0,-0xb(%ebp)
  struct super_block *sb_buf = (struct super_block *)sys_malloc(SECTOR_SIZE);
c00082d7:	83 ec 0c             	sub    $0xc,%esp
c00082da:	68 00 02 00 00       	push   $0x200
c00082df:	e8 40 ad ff ff       	call   c0003024 <sys_malloc>
c00082e4:	83 c4 10             	add    $0x10,%esp
c00082e7:	89 45 e8             	mov    %eax,-0x18(%ebp)
  uint32_t fd_idx = 0;
c00082ea:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)

  if (sb_buf == NULL) {
c00082f1:	83 7d e8 00          	cmpl   $0x0,-0x18(%ebp)
c00082f5:	75 1c                	jne    c0008313 <filesys_init+0x4a>
    PANIC("malloc memory failed!");
c00082f7:	68 69 d8 00 c0       	push   $0xc000d869
c00082fc:	68 94 d9 00 c0       	push   $0xc000d994
c0008301:	68 44 03 00 00       	push   $0x344
c0008306:	68 dd d0 00 c0       	push   $0xc000d0dd
c000830b:	e8 c8 9f ff ff       	call   c00022d8 <panic_spin>
c0008310:	83 c4 10             	add    $0x10,%esp
  }
  printk("searching filesystem.....\n");
c0008313:	83 ec 0c             	sub    $0xc,%esp
c0008316:	68 7f d8 00 c0       	push   $0xc000d87f
c000831b:	e8 94 d3 ff ff       	call   c00056b4 <printk>
c0008320:	83 c4 10             	add    $0x10,%esp

  while (channel_no < channel_cnt) {
c0008323:	e9 1d 01 00 00       	jmp    c0008445 <filesys_init+0x17c>
    dev_no = 0;
c0008328:	c6 45 f6 00          	movb   $0x0,-0xa(%ebp)
    while (dev_no < 2) {
c000832c:	e9 00 01 00 00       	jmp    c0008431 <filesys_init+0x168>
      if (dev_no == 0) { // 跨过裸盘hd60M.img
c0008331:	80 7d f6 00          	cmpb   $0x0,-0xa(%ebp)
c0008335:	75 0f                	jne    c0008346 <filesys_init+0x7d>
        dev_no++;
c0008337:	0f b6 45 f6          	movzbl -0xa(%ebp),%eax
c000833b:	83 c0 01             	add    $0x1,%eax
c000833e:	88 45 f6             	mov    %al,-0xa(%ebp)
        continue;
c0008341:	e9 eb 00 00 00       	jmp    c0008431 <filesys_init+0x168>
      }
      struct disk *hd = &channels[channel_no].devices[dev_no];
c0008346:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c000834a:	0f b6 55 f6          	movzbl -0xa(%ebp),%edx
c000834e:	69 d2 10 03 00 00    	imul   $0x310,%edx,%edx
c0008354:	69 c0 60 06 00 00    	imul   $0x660,%eax,%eax
c000835a:	01 d0                	add    %edx,%eax
c000835c:	83 c0 40             	add    $0x40,%eax
c000835f:	05 00 1d 01 c0       	add    $0xc0011d00,%eax
c0008364:	89 45 e4             	mov    %eax,-0x1c(%ebp)
      struct partition *part = hd->prim_parts;
c0008367:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c000836a:	83 c0 10             	add    $0x10,%eax
c000836d:	89 45 ec             	mov    %eax,-0x14(%ebp)
      while (part_idx < 12) { // 4个主分区+8个逻辑分区
c0008370:	e9 a8 00 00 00       	jmp    c000841d <filesys_init+0x154>
        if (part_idx == 4) {  // 主分区处理完开始处理逻辑分区
c0008375:	80 7d f5 04          	cmpb   $0x4,-0xb(%ebp)
c0008379:	75 0b                	jne    c0008386 <filesys_init+0xbd>
          part = hd->logic_parts;
c000837b:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c000837e:	05 10 01 00 00       	add    $0x110,%eax
c0008383:	89 45 ec             	mov    %eax,-0x14(%ebp)
        }

        if (part->sec_cnt != 0) { // 分区存在
c0008386:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0008389:	8b 40 04             	mov    0x4(%eax),%eax
c000838c:	85 c0                	test   %eax,%eax
c000838e:	74 7f                	je     c000840f <filesys_init+0x146>
          memset(sb_buf, 0, SECTOR_SIZE);
c0008390:	83 ec 04             	sub    $0x4,%esp
c0008393:	68 00 02 00 00       	push   $0x200
c0008398:	6a 00                	push   $0x0
c000839a:	ff 75 e8             	push   -0x18(%ebp)
c000839d:	e8 0c a0 ff ff       	call   c00023ae <memset>
c00083a2:	83 c4 10             	add    $0x10,%esp
          ide_read(hd, part->start_lba + 1, sb_buf, 1); // 读分区超级块
c00083a5:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00083a8:	8b 00                	mov    (%eax),%eax
c00083aa:	83 c0 01             	add    $0x1,%eax
c00083ad:	6a 01                	push   $0x1
c00083af:	ff 75 e8             	push   -0x18(%ebp)
c00083b2:	50                   	push   %eax
c00083b3:	ff 75 e4             	push   -0x1c(%ebp)
c00083b6:	e8 70 d6 ff ff       	call   c0005a2b <ide_read>
c00083bb:	83 c4 10             	add    $0x10,%esp
          if (sb_buf->magic == 0x20021112) {
c00083be:	8b 45 e8             	mov    -0x18(%ebp),%eax
c00083c1:	8b 00                	mov    (%eax),%eax
c00083c3:	3d 12 11 02 20       	cmp    $0x20021112,%eax
c00083c8:	75 19                	jne    c00083e3 <filesys_init+0x11a>
            printk("%s has filesystem\n", part->name);
c00083ca:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00083cd:	83 c0 14             	add    $0x14,%eax
c00083d0:	83 ec 08             	sub    $0x8,%esp
c00083d3:	50                   	push   %eax
c00083d4:	68 9a d8 00 c0       	push   $0xc000d89a
c00083d9:	e8 d6 d2 ff ff       	call   c00056b4 <printk>
c00083de:	83 c4 10             	add    $0x10,%esp
c00083e1:	eb 2c                	jmp    c000840f <filesys_init+0x146>
          } else {
            printk("formatting %s`s partition %s......\n", hd->name,
                   part->name);
c00083e3:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00083e6:	8d 50 14             	lea    0x14(%eax),%edx
            printk("formatting %s`s partition %s......\n", hd->name,
c00083e9:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c00083ec:	83 ec 04             	sub    $0x4,%esp
c00083ef:	52                   	push   %edx
c00083f0:	50                   	push   %eax
c00083f1:	68 b0 d8 00 c0       	push   $0xc000d8b0
c00083f6:	e8 b9 d2 ff ff       	call   c00056b4 <printk>
c00083fb:	83 c4 10             	add    $0x10,%esp
            partition_format(hd, part);
c00083fe:	83 ec 08             	sub    $0x8,%esp
c0008401:	ff 75 ec             	push   -0x14(%ebp)
c0008404:	ff 75 e4             	push   -0x1c(%ebp)
c0008407:	e8 a0 e2 ff ff       	call   c00066ac <partition_format>
c000840c:	83 c4 10             	add    $0x10,%esp
          }
        }
        part_idx++;
c000840f:	0f b6 45 f5          	movzbl -0xb(%ebp),%eax
c0008413:	83 c0 01             	add    $0x1,%eax
c0008416:	88 45 f5             	mov    %al,-0xb(%ebp)
        part++; // 下一分区
c0008419:	83 45 ec 40          	addl   $0x40,-0x14(%ebp)
      while (part_idx < 12) { // 4个主分区+8个逻辑分区
c000841d:	80 7d f5 0b          	cmpb   $0xb,-0xb(%ebp)
c0008421:	0f 86 4e ff ff ff    	jbe    c0008375 <filesys_init+0xac>
      }
      dev_no++; // 下一磁盘
c0008427:	0f b6 45 f6          	movzbl -0xa(%ebp),%eax
c000842b:	83 c0 01             	add    $0x1,%eax
c000842e:	88 45 f6             	mov    %al,-0xa(%ebp)
    while (dev_no < 2) {
c0008431:	80 7d f6 01          	cmpb   $0x1,-0xa(%ebp)
c0008435:	0f 86 f6 fe ff ff    	jbe    c0008331 <filesys_init+0x68>
    }
    channel_no++; // 下一通道
c000843b:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c000843f:	83 c0 01             	add    $0x1,%eax
c0008442:	88 45 f7             	mov    %al,-0x9(%ebp)
  while (channel_no < channel_cnt) {
c0008445:	0f b6 05 e0 1c 01 c0 	movzbl 0xc0011ce0,%eax
c000844c:	38 45 f7             	cmp    %al,-0x9(%ebp)
c000844f:	0f 82 d3 fe ff ff    	jb     c0008328 <filesys_init+0x5f>
  }
  sys_free(sb_buf);
c0008455:	83 ec 0c             	sub    $0xc,%esp
c0008458:	ff 75 e8             	push   -0x18(%ebp)
c000845b:	e8 e3 b1 ff ff       	call   c0003643 <sys_free>
c0008460:	83 c4 10             	add    $0x10,%esp
  char default_part[8] = "sdb1"; // 默认操作分区
c0008463:	c7 45 dc 73 64 62 31 	movl   $0x31626473,-0x24(%ebp)
c000846a:	c7 45 e0 00 00 00 00 	movl   $0x0,-0x20(%ebp)
  list_traversal(&partition_list, mount_partition,
c0008471:	8d 45 dc             	lea    -0x24(%ebp),%eax
c0008474:	83 ec 04             	sub    $0x4,%esp
c0008477:	50                   	push   %eax
c0008478:	68 a1 64 00 c0       	push   $0xc00064a1
c000847d:	68 c8 29 01 c0       	push   $0xc00129c8
c0008482:	e8 c5 be ff ff       	call   c000434c <list_traversal>
c0008487:	83 c4 10             	add    $0x10,%esp
                 (int)default_part); // 挂载分区

  open_root_dir(cur_part);         // 打开当前分区根目录
c000848a:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000848f:	83 ec 0c             	sub    $0xc,%esp
c0008492:	50                   	push   %eax
c0008493:	e8 4e 07 00 00       	call   c0008be6 <open_root_dir>
c0008498:	83 c4 10             	add    $0x10,%esp
  while (fd_idx < MAX_FILE_OPEN) { // 初始化文件表
c000849b:	eb 1d                	jmp    c00084ba <filesys_init+0x1f1>
    file_table[fd_idx++].fd_inode = NULL;
c000849d:	8b 55 f0             	mov    -0x10(%ebp),%edx
c00084a0:	8d 42 01             	lea    0x1(%edx),%eax
c00084a3:	89 45 f0             	mov    %eax,-0x10(%ebp)
c00084a6:	89 d0                	mov    %edx,%eax
c00084a8:	01 c0                	add    %eax,%eax
c00084aa:	01 d0                	add    %edx,%eax
c00084ac:	c1 e0 02             	shl    $0x2,%eax
c00084af:	05 08 2c 01 c0       	add    $0xc0012c08,%eax
c00084b4:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
  while (fd_idx < MAX_FILE_OPEN) { // 初始化文件表
c00084ba:	83 7d f0 1f          	cmpl   $0x1f,-0x10(%ebp)
c00084be:	76 dd                	jbe    c000849d <filesys_init+0x1d4>
  }
c00084c0:	90                   	nop
c00084c1:	90                   	nop
c00084c2:	c9                   	leave  
c00084c3:	c3                   	ret    

c00084c4 <inode_locate>:
  uint32_t off_size; // inode在扇区内的字节偏移量
};

// 获取inode所在扇区和偏移量存入inode_pos中
static void inode_locate(struct partition *part, uint32_t inode_no,
                         struct inode_position *inode_pos) {
c00084c4:	55                   	push   %ebp
c00084c5:	89 e5                	mov    %esp,%ebp
c00084c7:	83 ec 28             	sub    $0x28,%esp
  // inode_table在磁盘上连续
  ASSERT(inode_no < 4096);
c00084ca:	81 7d 0c ff 0f 00 00 	cmpl   $0xfff,0xc(%ebp)
c00084d1:	76 19                	jbe    c00084ec <inode_locate+0x28>
c00084d3:	68 a4 d9 00 c0       	push   $0xc000d9a4
c00084d8:	68 2c da 00 c0       	push   $0xc000da2c
c00084dd:	6a 18                	push   $0x18
c00084df:	68 b4 d9 00 c0       	push   $0xc000d9b4
c00084e4:	e8 ef 9d ff ff       	call   c00022d8 <panic_spin>
c00084e9:	83 c4 10             	add    $0x10,%esp
  uint32_t inode_table_lba = part->sb->inode_table_lba;
c00084ec:	8b 45 08             	mov    0x8(%ebp),%eax
c00084ef:	8b 40 1c             	mov    0x1c(%eax),%eax
c00084f2:	8b 40 20             	mov    0x20(%eax),%eax
c00084f5:	89 45 f4             	mov    %eax,-0xc(%ebp)

  uint32_t inode_size = sizeof(struct inode);
c00084f8:	c7 45 f0 4c 00 00 00 	movl   $0x4c,-0x10(%ebp)
  uint32_t off_size = inode_no * inode_size; // 字节偏移量
c00084ff:	8b 45 0c             	mov    0xc(%ebp),%eax
c0008502:	0f af 45 f0          	imul   -0x10(%ebp),%eax
c0008506:	89 45 ec             	mov    %eax,-0x14(%ebp)
  uint32_t off_sec = off_size / 512;         // 扇区偏移量
c0008509:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000850c:	c1 e8 09             	shr    $0x9,%eax
c000850f:	89 45 e8             	mov    %eax,-0x18(%ebp)
  uint32_t off_size_in_sec =
c0008512:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0008515:	25 ff 01 00 00       	and    $0x1ff,%eax
c000851a:	89 45 e4             	mov    %eax,-0x1c(%ebp)
      off_size % 512; // 待查找的inode所在扇区中的起始地址
  uint32_t left_in_sec = 512 - off_size_in_sec;
c000851d:	b8 00 02 00 00       	mov    $0x200,%eax
c0008522:	2b 45 e4             	sub    -0x1c(%ebp),%eax
c0008525:	89 45 e0             	mov    %eax,-0x20(%ebp)

  if (left_in_sec < inode_size) { // 跨2个扇区
c0008528:	8b 45 e0             	mov    -0x20(%ebp),%eax
c000852b:	3b 45 f0             	cmp    -0x10(%ebp),%eax
c000852e:	73 0b                	jae    c000853b <inode_locate+0x77>
    inode_pos->two_sec = true;
c0008530:	8b 45 10             	mov    0x10(%ebp),%eax
c0008533:	c7 00 01 00 00 00    	movl   $0x1,(%eax)
c0008539:	eb 09                	jmp    c0008544 <inode_locate+0x80>
  } else {
    inode_pos->two_sec = false;
c000853b:	8b 45 10             	mov    0x10(%ebp),%eax
c000853e:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
  }
  inode_pos->sec_lba = inode_table_lba + off_sec;
c0008544:	8b 55 f4             	mov    -0xc(%ebp),%edx
c0008547:	8b 45 e8             	mov    -0x18(%ebp),%eax
c000854a:	01 c2                	add    %eax,%edx
c000854c:	8b 45 10             	mov    0x10(%ebp),%eax
c000854f:	89 50 04             	mov    %edx,0x4(%eax)
  inode_pos->off_size = off_size_in_sec;
c0008552:	8b 45 10             	mov    0x10(%ebp),%eax
c0008555:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c0008558:	89 50 08             	mov    %edx,0x8(%eax)
}
c000855b:	90                   	nop
c000855c:	c9                   	leave  
c000855d:	c3                   	ret    

c000855e <inode_sync>:

// 将inode写入分区part
void inode_sync(struct partition *part, struct inode *inode, void *io_buf) {
c000855e:	55                   	push   %ebp
c000855f:	89 e5                	mov    %esp,%ebp
c0008561:	83 ec 68             	sub    $0x68,%esp
  uint8_t inode_no = inode->i_no;
c0008564:	8b 45 0c             	mov    0xc(%ebp),%eax
c0008567:	8b 00                	mov    (%eax),%eax
c0008569:	88 45 f7             	mov    %al,-0x9(%ebp)
  struct inode_position inode_pos;
  // inode位置信息存入inode_pos
  inode_locate(part, inode_no, &inode_pos);
c000856c:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0008570:	83 ec 04             	sub    $0x4,%esp
c0008573:	8d 55 e4             	lea    -0x1c(%ebp),%edx
c0008576:	52                   	push   %edx
c0008577:	50                   	push   %eax
c0008578:	ff 75 08             	push   0x8(%ebp)
c000857b:	e8 44 ff ff ff       	call   c00084c4 <inode_locate>
c0008580:	83 c4 10             	add    $0x10,%esp
  ASSERT(inode_pos.sec_lba <= (part->start_lba + part->sec_cnt));
c0008583:	8b 55 e8             	mov    -0x18(%ebp),%edx
c0008586:	8b 45 08             	mov    0x8(%ebp),%eax
c0008589:	8b 08                	mov    (%eax),%ecx
c000858b:	8b 45 08             	mov    0x8(%ebp),%eax
c000858e:	8b 40 04             	mov    0x4(%eax),%eax
c0008591:	01 c8                	add    %ecx,%eax
c0008593:	39 c2                	cmp    %eax,%edx
c0008595:	76 19                	jbe    c00085b0 <inode_sync+0x52>
c0008597:	68 c0 d9 00 c0       	push   $0xc000d9c0
c000859c:	68 3c da 00 c0       	push   $0xc000da3c
c00085a1:	6a 31                	push   $0x31
c00085a3:	68 b4 d9 00 c0       	push   $0xc000d9b4
c00085a8:	e8 2b 9d ff ff       	call   c00022d8 <panic_spin>
c00085ad:	83 c4 10             	add    $0x10,%esp

  /* 以下inode三个成员只在内存中有效，现在将inode同步到硬盘，清掉这三项即可 */
  struct inode pure_inode;
  memcpy(&pure_inode, inode, sizeof(struct inode));
c00085b0:	83 ec 04             	sub    $0x4,%esp
c00085b3:	6a 4c                	push   $0x4c
c00085b5:	ff 75 0c             	push   0xc(%ebp)
c00085b8:	8d 45 98             	lea    -0x68(%ebp),%eax
c00085bb:	50                   	push   %eax
c00085bc:	e8 40 9e ff ff       	call   c0002401 <memcpy>
c00085c1:	83 c4 10             	add    $0x10,%esp
  pure_inode.i_open_cnt = 0;
c00085c4:	c7 45 a0 00 00 00 00 	movl   $0x0,-0x60(%ebp)
  pure_inode.inode_tag.prev = pure_inode.inode_tag.next = NULL;
c00085cb:	c7 45 e0 00 00 00 00 	movl   $0x0,-0x20(%ebp)
c00085d2:	8b 45 e0             	mov    -0x20(%ebp),%eax
c00085d5:	89 45 dc             	mov    %eax,-0x24(%ebp)
  pure_inode.write_deny = false; // 保证在磁盘中读出为可写
c00085d8:	c7 45 a4 00 00 00 00 	movl   $0x0,-0x5c(%ebp)

  char *inode_buf = (char *)io_buf;
c00085df:	8b 45 10             	mov    0x10(%ebp),%eax
c00085e2:	89 45 f0             	mov    %eax,-0x10(%ebp)
  if (inode_pos.two_sec) { // 跨2个扇区就要读出2扇区再写2扇区
c00085e5:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c00085e8:	85 c0                	test   %eax,%eax
c00085ea:	74 4c                	je     c0008638 <inode_sync+0xda>
    /* 读写磁盘以扇区为单位，若写入数据小于一扇区，将原磁盘内容先读出来再和新数据拼成一扇区后再写入*/
    ide_read(part->my_disk, inode_pos.sec_lba, inode_buf, 2);
c00085ec:	8b 55 e8             	mov    -0x18(%ebp),%edx
c00085ef:	8b 45 08             	mov    0x8(%ebp),%eax
c00085f2:	8b 40 08             	mov    0x8(%eax),%eax
c00085f5:	6a 02                	push   $0x2
c00085f7:	ff 75 f0             	push   -0x10(%ebp)
c00085fa:	52                   	push   %edx
c00085fb:	50                   	push   %eax
c00085fc:	e8 2a d4 ff ff       	call   c0005a2b <ide_read>
c0008601:	83 c4 10             	add    $0x10,%esp
    // 将待写入的inode拼入到这2个扇区中的相应位置
    memcpy((inode_buf + inode_pos.off_size), &pure_inode, sizeof(struct inode));
c0008604:	8b 55 ec             	mov    -0x14(%ebp),%edx
c0008607:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000860a:	01 c2                	add    %eax,%edx
c000860c:	83 ec 04             	sub    $0x4,%esp
c000860f:	6a 4c                	push   $0x4c
c0008611:	8d 45 98             	lea    -0x68(%ebp),%eax
c0008614:	50                   	push   %eax
c0008615:	52                   	push   %edx
c0008616:	e8 e6 9d ff ff       	call   c0002401 <memcpy>
c000861b:	83 c4 10             	add    $0x10,%esp
    // 将拼接好的数据再写入磁盘
    ide_write(part->my_disk, inode_pos.sec_lba, inode_buf, 2);
c000861e:	8b 55 e8             	mov    -0x18(%ebp),%edx
c0008621:	8b 45 08             	mov    0x8(%ebp),%eax
c0008624:	8b 40 08             	mov    0x8(%eax),%eax
c0008627:	6a 02                	push   $0x2
c0008629:	ff 75 f0             	push   -0x10(%ebp)
c000862c:	52                   	push   %edx
c000862d:	50                   	push   %eax
c000862e:	e8 6c d5 ff ff       	call   c0005b9f <ide_write>
c0008633:	83 c4 10             	add    $0x10,%esp
  } else {
    ide_read(part->my_disk, inode_pos.sec_lba, inode_buf, 1);
    memcpy((inode_buf + inode_pos.off_size), &pure_inode, sizeof(struct inode));
    ide_write(part->my_disk, inode_pos.sec_lba, inode_buf, 1);
  }
}
c0008636:	eb 4a                	jmp    c0008682 <inode_sync+0x124>
    ide_read(part->my_disk, inode_pos.sec_lba, inode_buf, 1);
c0008638:	8b 55 e8             	mov    -0x18(%ebp),%edx
c000863b:	8b 45 08             	mov    0x8(%ebp),%eax
c000863e:	8b 40 08             	mov    0x8(%eax),%eax
c0008641:	6a 01                	push   $0x1
c0008643:	ff 75 f0             	push   -0x10(%ebp)
c0008646:	52                   	push   %edx
c0008647:	50                   	push   %eax
c0008648:	e8 de d3 ff ff       	call   c0005a2b <ide_read>
c000864d:	83 c4 10             	add    $0x10,%esp
    memcpy((inode_buf + inode_pos.off_size), &pure_inode, sizeof(struct inode));
c0008650:	8b 55 ec             	mov    -0x14(%ebp),%edx
c0008653:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0008656:	01 c2                	add    %eax,%edx
c0008658:	83 ec 04             	sub    $0x4,%esp
c000865b:	6a 4c                	push   $0x4c
c000865d:	8d 45 98             	lea    -0x68(%ebp),%eax
c0008660:	50                   	push   %eax
c0008661:	52                   	push   %edx
c0008662:	e8 9a 9d ff ff       	call   c0002401 <memcpy>
c0008667:	83 c4 10             	add    $0x10,%esp
    ide_write(part->my_disk, inode_pos.sec_lba, inode_buf, 1);
c000866a:	8b 55 e8             	mov    -0x18(%ebp),%edx
c000866d:	8b 45 08             	mov    0x8(%ebp),%eax
c0008670:	8b 40 08             	mov    0x8(%eax),%eax
c0008673:	6a 01                	push   $0x1
c0008675:	ff 75 f0             	push   -0x10(%ebp)
c0008678:	52                   	push   %edx
c0008679:	50                   	push   %eax
c000867a:	e8 20 d5 ff ff       	call   c0005b9f <ide_write>
c000867f:	83 c4 10             	add    $0x10,%esp
}
c0008682:	90                   	nop
c0008683:	c9                   	leave  
c0008684:	c3                   	ret    

c0008685 <inode_open>:

// 根据inode号返回相应的inode
struct inode *inode_open(struct partition *part, uint32_t inode_no) {
c0008685:	55                   	push   %ebp
c0008686:	89 e5                	mov    %esp,%ebp
c0008688:	83 ec 28             	sub    $0x28,%esp
  struct list_elem *elem = part->open_inodes.head.next;
c000868b:	8b 45 08             	mov    0x8(%ebp),%eax
c000868e:	8b 40 34             	mov    0x34(%eax),%eax
c0008691:	89 45 f4             	mov    %eax,-0xc(%ebp)
  struct inode *inode_found;

  // 先在已打开的inode链表中找
  while (elem != &part->open_inodes.tail) {
c0008694:	eb 33                	jmp    c00086c9 <inode_open+0x44>
    inode_found = elem2entry(struct inode, inode_tag, elem);
c0008696:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0008699:	83 e8 44             	sub    $0x44,%eax
c000869c:	89 45 e4             	mov    %eax,-0x1c(%ebp)
    if (inode_found->i_no == inode_no) {
c000869f:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c00086a2:	8b 00                	mov    (%eax),%eax
c00086a4:	39 45 0c             	cmp    %eax,0xc(%ebp)
c00086a7:	75 17                	jne    c00086c0 <inode_open+0x3b>
      inode_found->i_open_cnt++;
c00086a9:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c00086ac:	8b 40 08             	mov    0x8(%eax),%eax
c00086af:	8d 50 01             	lea    0x1(%eax),%edx
c00086b2:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c00086b5:	89 50 08             	mov    %edx,0x8(%eax)
      return inode_found;
c00086b8:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c00086bb:	e9 06 01 00 00       	jmp    c00087c6 <inode_open+0x141>
    }
    elem = elem->next;
c00086c0:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00086c3:	8b 40 04             	mov    0x4(%eax),%eax
c00086c6:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while (elem != &part->open_inodes.tail) {
c00086c9:	8b 45 08             	mov    0x8(%ebp),%eax
c00086cc:	83 c0 38             	add    $0x38,%eax
c00086cf:	39 45 f4             	cmp    %eax,-0xc(%ebp)
c00086d2:	75 c2                	jne    c0008696 <inode_open+0x11>
  }

  // 链表缓存中没有-> 从磁盘读此inode并加到链表中
  struct inode_position inode_pos;
  inode_locate(part, inode_no, &inode_pos);
c00086d4:	83 ec 04             	sub    $0x4,%esp
c00086d7:	8d 45 d8             	lea    -0x28(%ebp),%eax
c00086da:	50                   	push   %eax
c00086db:	ff 75 0c             	push   0xc(%ebp)
c00086de:	ff 75 08             	push   0x8(%ebp)
c00086e1:	e8 de fd ff ff       	call   c00084c4 <inode_locate>
c00086e6:	83 c4 10             	add    $0x10,%esp

  /* 为使通过sys_malloc创建的新inode被所有任务共享，需将inode置于内核空间 */
  struct task_struct *cur = running_thread();
c00086e9:	e8 21 b4 ff ff       	call   c0003b0f <running_thread>
c00086ee:	89 45 ec             	mov    %eax,-0x14(%ebp)
  uint32_t *cur_pgdir_bak = cur->pgdir;
c00086f1:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00086f4:	8b 40 34             	mov    0x34(%eax),%eax
c00086f7:	89 45 e8             	mov    %eax,-0x18(%ebp)
  cur_pgdir_bak = NULL; // 接下来分配的内存位于内核区
c00086fa:	c7 45 e8 00 00 00 00 	movl   $0x0,-0x18(%ebp)
  inode_found = (struct inode *)sys_malloc(sizeof(struct inode));
c0008701:	83 ec 0c             	sub    $0xc,%esp
c0008704:	6a 4c                	push   $0x4c
c0008706:	e8 19 a9 ff ff       	call   c0003024 <sys_malloc>
c000870b:	83 c4 10             	add    $0x10,%esp
c000870e:	89 45 e4             	mov    %eax,-0x1c(%ebp)
  cur->pgdir = cur_pgdir_bak; // 恢复
c0008711:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0008714:	8b 55 e8             	mov    -0x18(%ebp),%edx
c0008717:	89 50 34             	mov    %edx,0x34(%eax)

  char *inode_buf;
  if (inode_pos.two_sec) { // 跨扇区
c000871a:	8b 45 d8             	mov    -0x28(%ebp),%eax
c000871d:	85 c0                	test   %eax,%eax
c000871f:	74 2d                	je     c000874e <inode_open+0xc9>
    inode_buf = (char *)sys_malloc(1024);
c0008721:	83 ec 0c             	sub    $0xc,%esp
c0008724:	68 00 04 00 00       	push   $0x400
c0008729:	e8 f6 a8 ff ff       	call   c0003024 <sys_malloc>
c000872e:	83 c4 10             	add    $0x10,%esp
c0008731:	89 45 f0             	mov    %eax,-0x10(%ebp)
    ide_read(part->my_disk, inode_pos.sec_lba, inode_buf, 2);
c0008734:	8b 55 dc             	mov    -0x24(%ebp),%edx
c0008737:	8b 45 08             	mov    0x8(%ebp),%eax
c000873a:	8b 40 08             	mov    0x8(%eax),%eax
c000873d:	6a 02                	push   $0x2
c000873f:	ff 75 f0             	push   -0x10(%ebp)
c0008742:	52                   	push   %edx
c0008743:	50                   	push   %eax
c0008744:	e8 e2 d2 ff ff       	call   c0005a2b <ide_read>
c0008749:	83 c4 10             	add    $0x10,%esp
c000874c:	eb 2b                	jmp    c0008779 <inode_open+0xf4>
  } else {
    inode_buf = (char *)sys_malloc(512);
c000874e:	83 ec 0c             	sub    $0xc,%esp
c0008751:	68 00 02 00 00       	push   $0x200
c0008756:	e8 c9 a8 ff ff       	call   c0003024 <sys_malloc>
c000875b:	83 c4 10             	add    $0x10,%esp
c000875e:	89 45 f0             	mov    %eax,-0x10(%ebp)
    ide_read(part->my_disk, inode_pos.sec_lba, inode_buf, 1);
c0008761:	8b 55 dc             	mov    -0x24(%ebp),%edx
c0008764:	8b 45 08             	mov    0x8(%ebp),%eax
c0008767:	8b 40 08             	mov    0x8(%eax),%eax
c000876a:	6a 01                	push   $0x1
c000876c:	ff 75 f0             	push   -0x10(%ebp)
c000876f:	52                   	push   %edx
c0008770:	50                   	push   %eax
c0008771:	e8 b5 d2 ff ff       	call   c0005a2b <ide_read>
c0008776:	83 c4 10             	add    $0x10,%esp
  }
  memcpy(inode_found, inode_buf + inode_pos.off_size, sizeof(struct inode));
c0008779:	8b 55 e0             	mov    -0x20(%ebp),%edx
c000877c:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000877f:	01 d0                	add    %edx,%eax
c0008781:	83 ec 04             	sub    $0x4,%esp
c0008784:	6a 4c                	push   $0x4c
c0008786:	50                   	push   %eax
c0008787:	ff 75 e4             	push   -0x1c(%ebp)
c000878a:	e8 72 9c ff ff       	call   c0002401 <memcpy>
c000878f:	83 c4 10             	add    $0x10,%esp

  // 因为一会很可能要用到此inode，故将其插入到队首便于提前检索到
  list_push(&part->open_inodes, &inode_found->inode_tag);
c0008792:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0008795:	8d 50 44             	lea    0x44(%eax),%edx
c0008798:	8b 45 08             	mov    0x8(%ebp),%eax
c000879b:	83 c0 30             	add    $0x30,%eax
c000879e:	83 ec 08             	sub    $0x8,%esp
c00087a1:	52                   	push   %edx
c00087a2:	50                   	push   %eax
c00087a3:	e8 d1 ba ff ff       	call   c0004279 <list_push>
c00087a8:	83 c4 10             	add    $0x10,%esp
  inode_found->i_open_cnt = 1;
c00087ab:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c00087ae:	c7 40 08 01 00 00 00 	movl   $0x1,0x8(%eax)

  sys_free(inode_buf);
c00087b5:	83 ec 0c             	sub    $0xc,%esp
c00087b8:	ff 75 f0             	push   -0x10(%ebp)
c00087bb:	e8 83 ae ff ff       	call   c0003643 <sys_free>
c00087c0:	83 c4 10             	add    $0x10,%esp
  return inode_found;
c00087c3:	8b 45 e4             	mov    -0x1c(%ebp),%eax
}
c00087c6:	c9                   	leave  
c00087c7:	c3                   	ret    

c00087c8 <inode_close>:

// 关闭inode或减少inode的打开数
void inode_close(struct inode *inode) {
c00087c8:	55                   	push   %ebp
c00087c9:	89 e5                	mov    %esp,%ebp
c00087cb:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status = intr_disable();
c00087ce:	e8 6a 91 ff ff       	call   c000193d <intr_disable>
c00087d3:	89 45 f4             	mov    %eax,-0xc(%ebp)
  // 若没有进程再打开此文件，将此inode去掉并释放空间
  if (--inode->i_open_cnt == 0) {
c00087d6:	8b 45 08             	mov    0x8(%ebp),%eax
c00087d9:	8b 40 08             	mov    0x8(%eax),%eax
c00087dc:	8d 50 ff             	lea    -0x1(%eax),%edx
c00087df:	8b 45 08             	mov    0x8(%ebp),%eax
c00087e2:	89 50 08             	mov    %edx,0x8(%eax)
c00087e5:	8b 45 08             	mov    0x8(%ebp),%eax
c00087e8:	8b 40 08             	mov    0x8(%eax),%eax
c00087eb:	85 c0                	test   %eax,%eax
c00087ed:	75 44                	jne    c0008833 <inode_close+0x6b>
    list_remove(&inode->inode_tag);
c00087ef:	8b 45 08             	mov    0x8(%ebp),%eax
c00087f2:	83 c0 44             	add    $0x44,%eax
c00087f5:	83 ec 0c             	sub    $0xc,%esp
c00087f8:	50                   	push   %eax
c00087f9:	e8 b7 ba ff ff       	call   c00042b5 <list_remove>
c00087fe:	83 c4 10             	add    $0x10,%esp
    struct task_struct *cur = running_thread();
c0008801:	e8 09 b3 ff ff       	call   c0003b0f <running_thread>
c0008806:	89 45 f0             	mov    %eax,-0x10(%ebp)
    uint32_t *cur_pagedir_bak = cur->pgdir;
c0008809:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000880c:	8b 40 34             	mov    0x34(%eax),%eax
c000880f:	89 45 ec             	mov    %eax,-0x14(%ebp)
    cur->pgdir = NULL; // 确保释放的也是内核内存
c0008812:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0008815:	c7 40 34 00 00 00 00 	movl   $0x0,0x34(%eax)
    sys_free(inode);
c000881c:	83 ec 0c             	sub    $0xc,%esp
c000881f:	ff 75 08             	push   0x8(%ebp)
c0008822:	e8 1c ae ff ff       	call   c0003643 <sys_free>
c0008827:	83 c4 10             	add    $0x10,%esp
    cur->pgdir = cur_pagedir_bak;
c000882a:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000882d:	8b 55 ec             	mov    -0x14(%ebp),%edx
c0008830:	89 50 34             	mov    %edx,0x34(%eax)
  }
  intr_set_status(old_status);
c0008833:	83 ec 0c             	sub    $0xc,%esp
c0008836:	ff 75 f4             	push   -0xc(%ebp)
c0008839:	e8 45 91 ff ff       	call   c0001983 <intr_set_status>
c000883e:	83 c4 10             	add    $0x10,%esp
}
c0008841:	90                   	nop
c0008842:	c9                   	leave  
c0008843:	c3                   	ret    

c0008844 <inode_delete>:

// 清空磁盘分区part上的inode【调试添加】
void inode_delete(struct partition *part, uint32_t inode_no, void *io_buf) {
c0008844:	55                   	push   %ebp
c0008845:	89 e5                	mov    %esp,%ebp
c0008847:	83 ec 18             	sub    $0x18,%esp
  ASSERT(inode_no < 4096);
c000884a:	81 7d 0c ff 0f 00 00 	cmpl   $0xfff,0xc(%ebp)
c0008851:	76 1c                	jbe    c000886f <inode_delete+0x2b>
c0008853:	68 a4 d9 00 c0       	push   $0xc000d9a4
c0008858:	68 48 da 00 c0       	push   $0xc000da48
c000885d:	68 86 00 00 00       	push   $0x86
c0008862:	68 b4 d9 00 c0       	push   $0xc000d9b4
c0008867:	e8 6c 9a ff ff       	call   c00022d8 <panic_spin>
c000886c:	83 c4 10             	add    $0x10,%esp
  struct inode_position inode_pos;
  inode_locate(part, inode_no, &inode_pos); // inode位置信息会存入inode_pos
c000886f:	83 ec 04             	sub    $0x4,%esp
c0008872:	8d 45 e8             	lea    -0x18(%ebp),%eax
c0008875:	50                   	push   %eax
c0008876:	ff 75 0c             	push   0xc(%ebp)
c0008879:	ff 75 08             	push   0x8(%ebp)
c000887c:	e8 43 fc ff ff       	call   c00084c4 <inode_locate>
c0008881:	83 c4 10             	add    $0x10,%esp
  ASSERT(inode_pos.sec_lba <= (part->start_lba + part->sec_cnt));
c0008884:	8b 55 ec             	mov    -0x14(%ebp),%edx
c0008887:	8b 45 08             	mov    0x8(%ebp),%eax
c000888a:	8b 08                	mov    (%eax),%ecx
c000888c:	8b 45 08             	mov    0x8(%ebp),%eax
c000888f:	8b 40 04             	mov    0x4(%eax),%eax
c0008892:	01 c8                	add    %ecx,%eax
c0008894:	39 c2                	cmp    %eax,%edx
c0008896:	76 1c                	jbe    c00088b4 <inode_delete+0x70>
c0008898:	68 c0 d9 00 c0       	push   $0xc000d9c0
c000889d:	68 48 da 00 c0       	push   $0xc000da48
c00088a2:	68 89 00 00 00       	push   $0x89
c00088a7:	68 b4 d9 00 c0       	push   $0xc000d9b4
c00088ac:	e8 27 9a ff ff       	call   c00022d8 <panic_spin>
c00088b1:	83 c4 10             	add    $0x10,%esp

  char *inode_buf = (char *)io_buf;
c00088b4:	8b 45 10             	mov    0x10(%ebp),%eax
c00088b7:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (inode_pos.two_sec) { // inode跨扇区，读2个扇区
c00088ba:	8b 45 e8             	mov    -0x18(%ebp),%eax
c00088bd:	85 c0                	test   %eax,%eax
c00088bf:	74 4a                	je     c000890b <inode_delete+0xc7>
    ide_read(part->my_disk, inode_pos.sec_lba, inode_buf, 2);
c00088c1:	8b 55 ec             	mov    -0x14(%ebp),%edx
c00088c4:	8b 45 08             	mov    0x8(%ebp),%eax
c00088c7:	8b 40 08             	mov    0x8(%eax),%eax
c00088ca:	6a 02                	push   $0x2
c00088cc:	ff 75 f4             	push   -0xc(%ebp)
c00088cf:	52                   	push   %edx
c00088d0:	50                   	push   %eax
c00088d1:	e8 55 d1 ff ff       	call   c0005a2b <ide_read>
c00088d6:	83 c4 10             	add    $0x10,%esp
    memset((inode_buf + inode_pos.off_size), 0, sizeof(struct inode));
c00088d9:	8b 55 f0             	mov    -0x10(%ebp),%edx
c00088dc:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00088df:	01 d0                	add    %edx,%eax
c00088e1:	83 ec 04             	sub    $0x4,%esp
c00088e4:	6a 4c                	push   $0x4c
c00088e6:	6a 00                	push   $0x0
c00088e8:	50                   	push   %eax
c00088e9:	e8 c0 9a ff ff       	call   c00023ae <memset>
c00088ee:	83 c4 10             	add    $0x10,%esp
    // 用清0的内存数据覆盖磁盘
    ide_write(part->my_disk, inode_pos.sec_lba, inode_buf, 2);
c00088f1:	8b 55 ec             	mov    -0x14(%ebp),%edx
c00088f4:	8b 45 08             	mov    0x8(%ebp),%eax
c00088f7:	8b 40 08             	mov    0x8(%eax),%eax
c00088fa:	6a 02                	push   $0x2
c00088fc:	ff 75 f4             	push   -0xc(%ebp)
c00088ff:	52                   	push   %edx
c0008900:	50                   	push   %eax
c0008901:	e8 99 d2 ff ff       	call   c0005b9f <ide_write>
c0008906:	83 c4 10             	add    $0x10,%esp
  } else { // 未跨扇区，只读1个扇区
    ide_read(part->my_disk, inode_pos.sec_lba, inode_buf, 1);
    memset((inode_buf + inode_pos.off_size), 0, sizeof(struct inode));
    ide_write(part->my_disk, inode_pos.sec_lba, inode_buf, 1);
  }
}
c0008909:	eb 48                	jmp    c0008953 <inode_delete+0x10f>
    ide_read(part->my_disk, inode_pos.sec_lba, inode_buf, 1);
c000890b:	8b 55 ec             	mov    -0x14(%ebp),%edx
c000890e:	8b 45 08             	mov    0x8(%ebp),%eax
c0008911:	8b 40 08             	mov    0x8(%eax),%eax
c0008914:	6a 01                	push   $0x1
c0008916:	ff 75 f4             	push   -0xc(%ebp)
c0008919:	52                   	push   %edx
c000891a:	50                   	push   %eax
c000891b:	e8 0b d1 ff ff       	call   c0005a2b <ide_read>
c0008920:	83 c4 10             	add    $0x10,%esp
    memset((inode_buf + inode_pos.off_size), 0, sizeof(struct inode));
c0008923:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0008926:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0008929:	01 d0                	add    %edx,%eax
c000892b:	83 ec 04             	sub    $0x4,%esp
c000892e:	6a 4c                	push   $0x4c
c0008930:	6a 00                	push   $0x0
c0008932:	50                   	push   %eax
c0008933:	e8 76 9a ff ff       	call   c00023ae <memset>
c0008938:	83 c4 10             	add    $0x10,%esp
    ide_write(part->my_disk, inode_pos.sec_lba, inode_buf, 1);
c000893b:	8b 55 ec             	mov    -0x14(%ebp),%edx
c000893e:	8b 45 08             	mov    0x8(%ebp),%eax
c0008941:	8b 40 08             	mov    0x8(%eax),%eax
c0008944:	6a 01                	push   $0x1
c0008946:	ff 75 f4             	push   -0xc(%ebp)
c0008949:	52                   	push   %edx
c000894a:	50                   	push   %eax
c000894b:	e8 4f d2 ff ff       	call   c0005b9f <ide_write>
c0008950:	83 c4 10             	add    $0x10,%esp
}
c0008953:	90                   	nop
c0008954:	c9                   	leave  
c0008955:	c3                   	ret    

c0008956 <inode_release>:

// 回收inode的数据块和inode本身
void inode_release(struct partition *part, uint32_t inode_no) {
c0008956:	55                   	push   %ebp
c0008957:	89 e5                	mov    %esp,%ebp
c0008959:	57                   	push   %edi
c000895a:	81 ec 44 02 00 00    	sub    $0x244,%esp
  struct inode *inode_to_del = inode_open(part, inode_no);
c0008960:	83 ec 08             	sub    $0x8,%esp
c0008963:	ff 75 0c             	push   0xc(%ebp)
c0008966:	ff 75 08             	push   0x8(%ebp)
c0008969:	e8 17 fd ff ff       	call   c0008685 <inode_open>
c000896e:	83 c4 10             	add    $0x10,%esp
c0008971:	89 45 f0             	mov    %eax,-0x10(%ebp)
  ASSERT(inode_to_del->i_no == inode_no);
c0008974:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0008977:	8b 00                	mov    (%eax),%eax
c0008979:	39 45 0c             	cmp    %eax,0xc(%ebp)
c000897c:	74 1c                	je     c000899a <inode_release+0x44>
c000897e:	68 f8 d9 00 c0       	push   $0xc000d9f8
c0008983:	68 58 da 00 c0       	push   $0xc000da58
c0008988:	68 9b 00 00 00       	push   $0x9b
c000898d:	68 b4 d9 00 c0       	push   $0xc000d9b4
c0008992:	e8 41 99 ff ff       	call   c00022d8 <panic_spin>
c0008997:	83 c4 10             	add    $0x10,%esp

  /* 1、回收inode占的所有块 */
  uint8_t block_idx = 0, block_cnt = 12;
c000899a:	c6 45 f7 00          	movb   $0x0,-0x9(%ebp)
c000899e:	c6 45 f6 0c          	movb   $0xc,-0xa(%ebp)
  uint32_t block_bitmap_idx;
  uint32_t all_blocks[140] = {0}; // 12个直接块+128个间接块
c00089a2:	8d 95 b8 fd ff ff    	lea    -0x248(%ebp),%edx
c00089a8:	b8 00 00 00 00       	mov    $0x0,%eax
c00089ad:	b9 8c 00 00 00       	mov    $0x8c,%ecx
c00089b2:	89 d7                	mov    %edx,%edi
c00089b4:	f3 ab                	rep stos %eax,%es:(%edi)

  // 将前12个直接块存入all_blocks
  while (block_idx < 12) {
c00089b6:	eb 22                	jmp    c00089da <inode_release+0x84>
    all_blocks[block_idx] = inode_to_del->i_sectors[block_idx];
c00089b8:	0f b6 4d f7          	movzbl -0x9(%ebp),%ecx
c00089bc:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c00089c0:	8b 55 f0             	mov    -0x10(%ebp),%edx
c00089c3:	83 c1 04             	add    $0x4,%ecx
c00089c6:	8b 14 8a             	mov    (%edx,%ecx,4),%edx
c00089c9:	89 94 85 b8 fd ff ff 	mov    %edx,-0x248(%ebp,%eax,4)
    block_idx++;
c00089d0:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c00089d4:	83 c0 01             	add    $0x1,%eax
c00089d7:	88 45 f7             	mov    %al,-0x9(%ebp)
  while (block_idx < 12) {
c00089da:	80 7d f7 0b          	cmpb   $0xb,-0x9(%ebp)
c00089de:	76 d8                	jbe    c00089b8 <inode_release+0x62>
  }

  if (inode_to_del->i_sectors[12] != 0) { // 一级间接块表存在
c00089e0:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00089e3:	8b 40 40             	mov    0x40(%eax),%eax
c00089e6:	85 c0                	test   %eax,%eax
c00089e8:	0f 84 8b 00 00 00    	je     c0008a79 <inode_release+0x123>
    // 把间接块读到all_blocks
    ide_read(part->my_disk, inode_to_del->i_sectors[12], all_blocks + 12, 1);
c00089ee:	8d 85 b8 fd ff ff    	lea    -0x248(%ebp),%eax
c00089f4:	83 c0 30             	add    $0x30,%eax
c00089f7:	8b 55 f0             	mov    -0x10(%ebp),%edx
c00089fa:	8b 4a 40             	mov    0x40(%edx),%ecx
c00089fd:	8b 55 08             	mov    0x8(%ebp),%edx
c0008a00:	8b 52 08             	mov    0x8(%edx),%edx
c0008a03:	6a 01                	push   $0x1
c0008a05:	50                   	push   %eax
c0008a06:	51                   	push   %ecx
c0008a07:	52                   	push   %edx
c0008a08:	e8 1e d0 ff ff       	call   c0005a2b <ide_read>
c0008a0d:	83 c4 10             	add    $0x10,%esp
    block_cnt = 140;
c0008a10:	c6 45 f6 8c          	movb   $0x8c,-0xa(%ebp)
    block_bitmap_idx = inode_to_del->i_sectors[12] - part->sb->data_start_lba;
c0008a14:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0008a17:	8b 50 40             	mov    0x40(%eax),%edx
c0008a1a:	8b 45 08             	mov    0x8(%ebp),%eax
c0008a1d:	8b 40 1c             	mov    0x1c(%eax),%eax
c0008a20:	8b 48 28             	mov    0x28(%eax),%ecx
c0008a23:	89 d0                	mov    %edx,%eax
c0008a25:	29 c8                	sub    %ecx,%eax
c0008a27:	89 45 ec             	mov    %eax,-0x14(%ebp)
    ASSERT(block_bitmap_idx > 0);
c0008a2a:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c0008a2e:	75 1c                	jne    c0008a4c <inode_release+0xf6>
c0008a30:	68 17 da 00 c0       	push   $0xc000da17
c0008a35:	68 58 da 00 c0       	push   $0xc000da58
c0008a3a:	68 ad 00 00 00       	push   $0xad
c0008a3f:	68 b4 d9 00 c0       	push   $0xc000d9b4
c0008a44:	e8 8f 98 ff ff       	call   c00022d8 <panic_spin>
c0008a49:	83 c4 10             	add    $0x10,%esp
    // 释放一级间接块表占的块
    bitmap_set(&part->block_bitmap, block_bitmap_idx, 0);
c0008a4c:	8b 45 08             	mov    0x8(%ebp),%eax
c0008a4f:	83 c0 20             	add    $0x20,%eax
c0008a52:	83 ec 04             	sub    $0x4,%esp
c0008a55:	6a 00                	push   $0x0
c0008a57:	ff 75 ec             	push   -0x14(%ebp)
c0008a5a:	50                   	push   %eax
c0008a5b:	e8 a9 9e ff ff       	call   c0002909 <bitmap_set>
c0008a60:	83 c4 10             	add    $0x10,%esp
    bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
c0008a63:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0008a68:	83 ec 04             	sub    $0x4,%esp
c0008a6b:	6a 01                	push   $0x1
c0008a6d:	ff 75 ec             	push   -0x14(%ebp)
c0008a70:	50                   	push   %eax
c0008a71:	e8 59 11 00 00       	call   c0009bcf <bitmap_sync>
c0008a76:	83 c4 10             	add    $0x10,%esp
  }

  // inode所有块地址已收集到all_blocks中，下面逐个回收
  block_idx = 0;
c0008a79:	c6 45 f7 00          	movb   $0x0,-0x9(%ebp)
  while (block_idx < block_cnt) {
c0008a7d:	e9 8a 00 00 00       	jmp    c0008b0c <inode_release+0x1b6>
    if (all_blocks[block_idx] != 0) {
c0008a82:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0008a86:	8b 84 85 b8 fd ff ff 	mov    -0x248(%ebp,%eax,4),%eax
c0008a8d:	85 c0                	test   %eax,%eax
c0008a8f:	74 71                	je     c0008b02 <inode_release+0x1ac>
      block_bitmap_idx = 0;
c0008a91:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%ebp)
      block_bitmap_idx = all_blocks[block_idx] - part->sb->data_start_lba;
c0008a98:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0008a9c:	8b 94 85 b8 fd ff ff 	mov    -0x248(%ebp,%eax,4),%edx
c0008aa3:	8b 45 08             	mov    0x8(%ebp),%eax
c0008aa6:	8b 40 1c             	mov    0x1c(%eax),%eax
c0008aa9:	8b 48 28             	mov    0x28(%eax),%ecx
c0008aac:	89 d0                	mov    %edx,%eax
c0008aae:	29 c8                	sub    %ecx,%eax
c0008ab0:	89 45 ec             	mov    %eax,-0x14(%ebp)
      ASSERT(block_bitmap_idx > 0);
c0008ab3:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c0008ab7:	75 1c                	jne    c0008ad5 <inode_release+0x17f>
c0008ab9:	68 17 da 00 c0       	push   $0xc000da17
c0008abe:	68 58 da 00 c0       	push   $0xc000da58
c0008ac3:	68 b9 00 00 00       	push   $0xb9
c0008ac8:	68 b4 d9 00 c0       	push   $0xc000d9b4
c0008acd:	e8 06 98 ff ff       	call   c00022d8 <panic_spin>
c0008ad2:	83 c4 10             	add    $0x10,%esp
      bitmap_set(&part->block_bitmap, block_bitmap_idx, 0);
c0008ad5:	8b 45 08             	mov    0x8(%ebp),%eax
c0008ad8:	83 c0 20             	add    $0x20,%eax
c0008adb:	83 ec 04             	sub    $0x4,%esp
c0008ade:	6a 00                	push   $0x0
c0008ae0:	ff 75 ec             	push   -0x14(%ebp)
c0008ae3:	50                   	push   %eax
c0008ae4:	e8 20 9e ff ff       	call   c0002909 <bitmap_set>
c0008ae9:	83 c4 10             	add    $0x10,%esp
      bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
c0008aec:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0008af1:	83 ec 04             	sub    $0x4,%esp
c0008af4:	6a 01                	push   $0x1
c0008af6:	ff 75 ec             	push   -0x14(%ebp)
c0008af9:	50                   	push   %eax
c0008afa:	e8 d0 10 00 00       	call   c0009bcf <bitmap_sync>
c0008aff:	83 c4 10             	add    $0x10,%esp
    }
    block_idx++;
c0008b02:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0008b06:	83 c0 01             	add    $0x1,%eax
c0008b09:	88 45 f7             	mov    %al,-0x9(%ebp)
  while (block_idx < block_cnt) {
c0008b0c:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0008b10:	3a 45 f6             	cmp    -0xa(%ebp),%al
c0008b13:	0f 82 69 ff ff ff    	jb     c0008a82 <inode_release+0x12c>
  }

  /* 2、回收该inode所占inode */
  bitmap_set(&part->inode_bitmap, inode_no, 0);
c0008b19:	8b 45 08             	mov    0x8(%ebp),%eax
c0008b1c:	83 c0 28             	add    $0x28,%eax
c0008b1f:	83 ec 04             	sub    $0x4,%esp
c0008b22:	6a 00                	push   $0x0
c0008b24:	ff 75 0c             	push   0xc(%ebp)
c0008b27:	50                   	push   %eax
c0008b28:	e8 dc 9d ff ff       	call   c0002909 <bitmap_set>
c0008b2d:	83 c4 10             	add    $0x10,%esp
  bitmap_sync(cur_part, inode_no, INODE_BITMAP);
c0008b30:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0008b35:	83 ec 04             	sub    $0x4,%esp
c0008b38:	6a 00                	push   $0x0
c0008b3a:	ff 75 0c             	push   0xc(%ebp)
c0008b3d:	50                   	push   %eax
c0008b3e:	e8 8c 10 00 00       	call   c0009bcf <bitmap_sync>
c0008b43:	83 c4 10             	add    $0x10,%esp

  /*************inode_delete是调试用的*************
   * 此函数会在inode_table中将此inode清0，
   * 但实际上不需要，inode分配由inode_bitmap控制，
   * 磁盘上的数据无需清0，可直接覆盖 */
  void *io_buf = sys_malloc(1024);
c0008b46:	83 ec 0c             	sub    $0xc,%esp
c0008b49:	68 00 04 00 00       	push   $0x400
c0008b4e:	e8 d1 a4 ff ff       	call   c0003024 <sys_malloc>
c0008b53:	83 c4 10             	add    $0x10,%esp
c0008b56:	89 45 e8             	mov    %eax,-0x18(%ebp)
  inode_delete(part, inode_no, io_buf);
c0008b59:	83 ec 04             	sub    $0x4,%esp
c0008b5c:	ff 75 e8             	push   -0x18(%ebp)
c0008b5f:	ff 75 0c             	push   0xc(%ebp)
c0008b62:	ff 75 08             	push   0x8(%ebp)
c0008b65:	e8 da fc ff ff       	call   c0008844 <inode_delete>
c0008b6a:	83 c4 10             	add    $0x10,%esp
  sys_free(io_buf);
c0008b6d:	83 ec 0c             	sub    $0xc,%esp
c0008b70:	ff 75 e8             	push   -0x18(%ebp)
c0008b73:	e8 cb aa ff ff       	call   c0003643 <sys_free>
c0008b78:	83 c4 10             	add    $0x10,%esp
  /***********************************************/
  inode_close(inode_to_del);
c0008b7b:	83 ec 0c             	sub    $0xc,%esp
c0008b7e:	ff 75 f0             	push   -0x10(%ebp)
c0008b81:	e8 42 fc ff ff       	call   c00087c8 <inode_close>
c0008b86:	83 c4 10             	add    $0x10,%esp
}
c0008b89:	90                   	nop
c0008b8a:	8b 7d fc             	mov    -0x4(%ebp),%edi
c0008b8d:	c9                   	leave  
c0008b8e:	c3                   	ret    

c0008b8f <inode_init>:

void inode_init(uint32_t inode_no, struct inode *new_inode) {
c0008b8f:	55                   	push   %ebp
c0008b90:	89 e5                	mov    %esp,%ebp
c0008b92:	83 ec 10             	sub    $0x10,%esp
  new_inode->i_no = inode_no;
c0008b95:	8b 45 0c             	mov    0xc(%ebp),%eax
c0008b98:	8b 55 08             	mov    0x8(%ebp),%edx
c0008b9b:	89 10                	mov    %edx,(%eax)
  new_inode->i_size = 0;
c0008b9d:	8b 45 0c             	mov    0xc(%ebp),%eax
c0008ba0:	c7 40 04 00 00 00 00 	movl   $0x0,0x4(%eax)
  new_inode->i_open_cnt = 0;
c0008ba7:	8b 45 0c             	mov    0xc(%ebp),%eax
c0008baa:	c7 40 08 00 00 00 00 	movl   $0x0,0x8(%eax)
  new_inode->write_deny = false;
c0008bb1:	8b 45 0c             	mov    0xc(%ebp),%eax
c0008bb4:	c7 40 0c 00 00 00 00 	movl   $0x0,0xc(%eax)

  // 初始化块索引数组i_sector
  uint8_t sec_idx = 0;
c0008bbb:	c6 45 ff 00          	movb   $0x0,-0x1(%ebp)
  while (sec_idx < 13) {
c0008bbf:	eb 1b                	jmp    c0008bdc <inode_init+0x4d>
    new_inode->i_sectors[sec_idx] = 0;
c0008bc1:	0f b6 55 ff          	movzbl -0x1(%ebp),%edx
c0008bc5:	8b 45 0c             	mov    0xc(%ebp),%eax
c0008bc8:	83 c2 04             	add    $0x4,%edx
c0008bcb:	c7 04 90 00 00 00 00 	movl   $0x0,(%eax,%edx,4)
    sec_idx++;
c0008bd2:	0f b6 45 ff          	movzbl -0x1(%ebp),%eax
c0008bd6:	83 c0 01             	add    $0x1,%eax
c0008bd9:	88 45 ff             	mov    %al,-0x1(%ebp)
  while (sec_idx < 13) {
c0008bdc:	80 7d ff 0c          	cmpb   $0xc,-0x1(%ebp)
c0008be0:	76 df                	jbe    c0008bc1 <inode_init+0x32>
  }
c0008be2:	90                   	nop
c0008be3:	90                   	nop
c0008be4:	c9                   	leave  
c0008be5:	c3                   	ret    

c0008be6 <open_root_dir>:
#include "super_block.h"

struct dir root_dir; // 根目录

// 打开根目录
void open_root_dir(struct partition *part) {
c0008be6:	55                   	push   %ebp
c0008be7:	89 e5                	mov    %esp,%ebp
c0008be9:	83 ec 08             	sub    $0x8,%esp
  root_dir.inode = inode_open(part, part->sb->root_inode_no);
c0008bec:	8b 45 08             	mov    0x8(%ebp),%eax
c0008bef:	8b 40 1c             	mov    0x1c(%eax),%eax
c0008bf2:	8b 40 2c             	mov    0x2c(%eax),%eax
c0008bf5:	83 ec 08             	sub    $0x8,%esp
c0008bf8:	50                   	push   %eax
c0008bf9:	ff 75 08             	push   0x8(%ebp)
c0008bfc:	e8 84 fa ff ff       	call   c0008685 <inode_open>
c0008c01:	83 c4 10             	add    $0x10,%esp
c0008c04:	a3 e0 29 01 c0       	mov    %eax,0xc00129e0
  root_dir.dir_pos = 0;
c0008c09:	c7 05 e4 29 01 c0 00 	movl   $0x0,0xc00129e4
c0008c10:	00 00 00 
}
c0008c13:	90                   	nop
c0008c14:	c9                   	leave  
c0008c15:	c3                   	ret    

c0008c16 <dir_open>:

// 打开inode_no目录并返回目录指针
struct dir *dir_open(struct partition *part, uint32_t inode_no) {
c0008c16:	55                   	push   %ebp
c0008c17:	89 e5                	mov    %esp,%ebp
c0008c19:	83 ec 18             	sub    $0x18,%esp
  struct dir *pdir = (struct dir *)sys_malloc(sizeof(struct dir));
c0008c1c:	83 ec 0c             	sub    $0xc,%esp
c0008c1f:	68 08 02 00 00       	push   $0x208
c0008c24:	e8 fb a3 ff ff       	call   c0003024 <sys_malloc>
c0008c29:	83 c4 10             	add    $0x10,%esp
c0008c2c:	89 45 f4             	mov    %eax,-0xc(%ebp)
  pdir->inode = inode_open(part, inode_no);
c0008c2f:	83 ec 08             	sub    $0x8,%esp
c0008c32:	ff 75 0c             	push   0xc(%ebp)
c0008c35:	ff 75 08             	push   0x8(%ebp)
c0008c38:	e8 48 fa ff ff       	call   c0008685 <inode_open>
c0008c3d:	83 c4 10             	add    $0x10,%esp
c0008c40:	8b 55 f4             	mov    -0xc(%ebp),%edx
c0008c43:	89 02                	mov    %eax,(%edx)
  pdir->dir_pos = 0;
c0008c45:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0008c48:	c7 40 04 00 00 00 00 	movl   $0x0,0x4(%eax)
  return pdir;
c0008c4f:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0008c52:	c9                   	leave  
c0008c53:	c3                   	ret    

c0008c54 <search_dir_entry>:

// 在part分区内的pdir目录内寻找name文件/目录，找到后目录项存入dir_e（目录指针pdir、目录项指针dir_e
bool search_dir_entry(struct partition *part, struct dir *pdir,
                      const char *name, struct dir_entry *dir_e) {
c0008c54:	55                   	push   %ebp
c0008c55:	89 e5                	mov    %esp,%ebp
c0008c57:	83 ec 28             	sub    $0x28,%esp
  uint32_t block_cnt = 140; // 12个直接块+128个间接块
c0008c5a:	c7 45 e8 8c 00 00 00 	movl   $0x8c,-0x18(%ebp)
  uint32_t *all_blocks = (uint32_t *)sys_malloc(560);
c0008c61:	83 ec 0c             	sub    $0xc,%esp
c0008c64:	68 30 02 00 00       	push   $0x230
c0008c69:	e8 b6 a3 ff ff       	call   c0003024 <sys_malloc>
c0008c6e:	83 c4 10             	add    $0x10,%esp
c0008c71:	89 45 e4             	mov    %eax,-0x1c(%ebp)
  if (all_blocks == NULL) {
c0008c74:	83 7d e4 00          	cmpl   $0x0,-0x1c(%ebp)
c0008c78:	75 1a                	jne    c0008c94 <search_dir_entry+0x40>
    printk("search_dir_entry: sys_malloc for all_blocks failed");
c0008c7a:	83 ec 0c             	sub    $0xc,%esp
c0008c7d:	68 68 da 00 c0       	push   $0xc000da68
c0008c82:	e8 2d ca ff ff       	call   c00056b4 <printk>
c0008c87:	83 c4 10             	add    $0x10,%esp
    return false;
c0008c8a:	b8 00 00 00 00       	mov    $0x0,%eax
c0008c8f:	e9 96 01 00 00       	jmp    c0008e2a <search_dir_entry+0x1d6>
  }

  uint32_t block_idx = 0;
c0008c94:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  while (block_idx < 12) {
c0008c9b:	eb 23                	jmp    c0008cc0 <search_dir_entry+0x6c>
    all_blocks[block_idx] = pdir->inode->i_sectors[block_idx];
c0008c9d:	8b 45 0c             	mov    0xc(%ebp),%eax
c0008ca0:	8b 00                	mov    (%eax),%eax
c0008ca2:	8b 55 f4             	mov    -0xc(%ebp),%edx
c0008ca5:	8d 0c 95 00 00 00 00 	lea    0x0(,%edx,4),%ecx
c0008cac:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c0008caf:	01 ca                	add    %ecx,%edx
c0008cb1:	8b 4d f4             	mov    -0xc(%ebp),%ecx
c0008cb4:	83 c1 04             	add    $0x4,%ecx
c0008cb7:	8b 04 88             	mov    (%eax,%ecx,4),%eax
c0008cba:	89 02                	mov    %eax,(%edx)
    block_idx++;
c0008cbc:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
  while (block_idx < 12) {
c0008cc0:	83 7d f4 0b          	cmpl   $0xb,-0xc(%ebp)
c0008cc4:	76 d7                	jbe    c0008c9d <search_dir_entry+0x49>
  }
  block_idx = 0;
c0008cc6:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)

  if (pdir->inode->i_sectors[12] != 0) { // 有一级间接块表
c0008ccd:	8b 45 0c             	mov    0xc(%ebp),%eax
c0008cd0:	8b 00                	mov    (%eax),%eax
c0008cd2:	8b 40 40             	mov    0x40(%eax),%eax
c0008cd5:	85 c0                	test   %eax,%eax
c0008cd7:	74 21                	je     c0008cfa <search_dir_entry+0xa6>
    ide_read(part->my_disk, pdir->inode->i_sectors[12], all_blocks + 12, 1);
c0008cd9:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0008cdc:	8d 48 30             	lea    0x30(%eax),%ecx
c0008cdf:	8b 45 0c             	mov    0xc(%ebp),%eax
c0008ce2:	8b 00                	mov    (%eax),%eax
c0008ce4:	8b 50 40             	mov    0x40(%eax),%edx
c0008ce7:	8b 45 08             	mov    0x8(%ebp),%eax
c0008cea:	8b 40 08             	mov    0x8(%eax),%eax
c0008ced:	6a 01                	push   $0x1
c0008cef:	51                   	push   %ecx
c0008cf0:	52                   	push   %edx
c0008cf1:	50                   	push   %eax
c0008cf2:	e8 34 cd ff ff       	call   c0005a2b <ide_read>
c0008cf7:	83 c4 10             	add    $0x10,%esp
  }
  // 至此all_blocks存了该文件/目录的所有扇区地址

  // 往目录中写目录项选择写一整个扇区
  uint8_t *buf = (uint8_t *)sys_malloc(SECTOR_SIZE);
c0008cfa:	83 ec 0c             	sub    $0xc,%esp
c0008cfd:	68 00 02 00 00       	push   $0x200
c0008d02:	e8 1d a3 ff ff       	call   c0003024 <sys_malloc>
c0008d07:	83 c4 10             	add    $0x10,%esp
c0008d0a:	89 45 e0             	mov    %eax,-0x20(%ebp)
  struct dir_entry *p_de = (struct dir_entry *)buf; // p_de为指向目录项的指针
c0008d0d:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0008d10:	89 45 f0             	mov    %eax,-0x10(%ebp)
  uint32_t dir_entry_size = part->sb->dir_entry_size;
c0008d13:	8b 45 08             	mov    0x8(%ebp),%eax
c0008d16:	8b 40 1c             	mov    0x1c(%eax),%eax
c0008d19:	8b 40 30             	mov    0x30(%eax),%eax
c0008d1c:	89 45 dc             	mov    %eax,-0x24(%ebp)
  uint32_t dir_entry_cnt = SECTOR_SIZE / dir_entry_size; // 1扇区容纳的目录项数
c0008d1f:	b8 00 02 00 00       	mov    $0x200,%eax
c0008d24:	ba 00 00 00 00       	mov    $0x0,%edx
c0008d29:	f7 75 dc             	divl   -0x24(%ebp)
c0008d2c:	89 45 d8             	mov    %eax,-0x28(%ebp)

  // 【先遍历扇区】
  while (block_idx < block_cnt) {
c0008d2f:	e9 c9 00 00 00       	jmp    c0008dfd <search_dir_entry+0x1a9>
    if (all_blocks[block_idx] == 0) { // 该块中无数据
c0008d34:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0008d37:	8d 14 85 00 00 00 00 	lea    0x0(,%eax,4),%edx
c0008d3e:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0008d41:	01 d0                	add    %edx,%eax
c0008d43:	8b 00                	mov    (%eax),%eax
c0008d45:	85 c0                	test   %eax,%eax
c0008d47:	75 09                	jne    c0008d52 <search_dir_entry+0xfe>
      block_idx++;
c0008d49:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
      continue;
c0008d4d:	e9 ab 00 00 00       	jmp    c0008dfd <search_dir_entry+0x1a9>
    }
    ide_read(part->my_disk, all_blocks[block_idx], buf, 1);
c0008d52:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0008d55:	8d 14 85 00 00 00 00 	lea    0x0(,%eax,4),%edx
c0008d5c:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0008d5f:	01 d0                	add    %edx,%eax
c0008d61:	8b 10                	mov    (%eax),%edx
c0008d63:	8b 45 08             	mov    0x8(%ebp),%eax
c0008d66:	8b 40 08             	mov    0x8(%eax),%eax
c0008d69:	6a 01                	push   $0x1
c0008d6b:	ff 75 e0             	push   -0x20(%ebp)
c0008d6e:	52                   	push   %edx
c0008d6f:	50                   	push   %eax
c0008d70:	e8 b6 cc ff ff       	call   c0005a2b <ide_read>
c0008d75:	83 c4 10             	add    $0x10,%esp

    uint32_t dir_entry_idx = 0;
c0008d78:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%ebp)
    // 【再遍历各个扇区中的所有目录项】
    while (dir_entry_idx < dir_entry_cnt) {
c0008d7f:	eb 55                	jmp    c0008dd6 <search_dir_entry+0x182>
      // 若找到了，就直接复制整个目录项
      if (!strcmp(p_de->filename, name)) {
c0008d81:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0008d84:	83 ec 08             	sub    $0x8,%esp
c0008d87:	ff 75 10             	push   0x10(%ebp)
c0008d8a:	50                   	push   %eax
c0008d8b:	e8 f1 97 ff ff       	call   c0002581 <strcmp>
c0008d90:	83 c4 10             	add    $0x10,%esp
c0008d93:	84 c0                	test   %al,%al
c0008d95:	75 37                	jne    c0008dce <search_dir_entry+0x17a>
        memcpy(dir_e, p_de, dir_entry_size);
c0008d97:	83 ec 04             	sub    $0x4,%esp
c0008d9a:	ff 75 dc             	push   -0x24(%ebp)
c0008d9d:	ff 75 f0             	push   -0x10(%ebp)
c0008da0:	ff 75 14             	push   0x14(%ebp)
c0008da3:	e8 59 96 ff ff       	call   c0002401 <memcpy>
c0008da8:	83 c4 10             	add    $0x10,%esp
        sys_free(buf);
c0008dab:	83 ec 0c             	sub    $0xc,%esp
c0008dae:	ff 75 e0             	push   -0x20(%ebp)
c0008db1:	e8 8d a8 ff ff       	call   c0003643 <sys_free>
c0008db6:	83 c4 10             	add    $0x10,%esp
        sys_free(all_blocks);
c0008db9:	83 ec 0c             	sub    $0xc,%esp
c0008dbc:	ff 75 e4             	push   -0x1c(%ebp)
c0008dbf:	e8 7f a8 ff ff       	call   c0003643 <sys_free>
c0008dc4:	83 c4 10             	add    $0x10,%esp
        return true;
c0008dc7:	b8 01 00 00 00       	mov    $0x1,%eax
c0008dcc:	eb 5c                	jmp    c0008e2a <search_dir_entry+0x1d6>
      }
      dir_entry_idx++;
c0008dce:	83 45 ec 01          	addl   $0x1,-0x14(%ebp)
      p_de++;
c0008dd2:	83 45 f0 18          	addl   $0x18,-0x10(%ebp)
    while (dir_entry_idx < dir_entry_cnt) {
c0008dd6:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0008dd9:	3b 45 d8             	cmp    -0x28(%ebp),%eax
c0008ddc:	72 a3                	jb     c0008d81 <search_dir_entry+0x12d>
    }
    block_idx++;
c0008dde:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
    p_de = (struct dir_entry *)
c0008de2:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0008de5:	89 45 f0             	mov    %eax,-0x10(%ebp)
        buf; // 此时p_de已指向扇区内最后一个完整目录项，需恢复p_de指向为buf
    memset(buf, 0, SECTOR_SIZE); // buf清0
c0008de8:	83 ec 04             	sub    $0x4,%esp
c0008deb:	68 00 02 00 00       	push   $0x200
c0008df0:	6a 00                	push   $0x0
c0008df2:	ff 75 e0             	push   -0x20(%ebp)
c0008df5:	e8 b4 95 ff ff       	call   c00023ae <memset>
c0008dfa:	83 c4 10             	add    $0x10,%esp
  while (block_idx < block_cnt) {
c0008dfd:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0008e00:	3b 45 e8             	cmp    -0x18(%ebp),%eax
c0008e03:	0f 82 2b ff ff ff    	jb     c0008d34 <search_dir_entry+0xe0>
  }
  sys_free(buf);
c0008e09:	83 ec 0c             	sub    $0xc,%esp
c0008e0c:	ff 75 e0             	push   -0x20(%ebp)
c0008e0f:	e8 2f a8 ff ff       	call   c0003643 <sys_free>
c0008e14:	83 c4 10             	add    $0x10,%esp
  sys_free(all_blocks);
c0008e17:	83 ec 0c             	sub    $0xc,%esp
c0008e1a:	ff 75 e4             	push   -0x1c(%ebp)
c0008e1d:	e8 21 a8 ff ff       	call   c0003643 <sys_free>
c0008e22:	83 c4 10             	add    $0x10,%esp
  return false;
c0008e25:	b8 00 00 00 00       	mov    $0x0,%eax
}
c0008e2a:	c9                   	leave  
c0008e2b:	c3                   	ret    

c0008e2c <dir_close>:

// 关闭目录（根目录不能关闭，root_dir在低端1MB之内而不在堆中，free会出问题
void dir_close(struct dir *dir) {
c0008e2c:	55                   	push   %ebp
c0008e2d:	89 e5                	mov    %esp,%ebp
c0008e2f:	83 ec 08             	sub    $0x8,%esp
  if (dir == &root_dir) {
c0008e32:	81 7d 08 e0 29 01 c0 	cmpl   $0xc00129e0,0x8(%ebp)
c0008e39:	74 21                	je     c0008e5c <dir_close+0x30>
    return;
  }
  inode_close(dir->inode);
c0008e3b:	8b 45 08             	mov    0x8(%ebp),%eax
c0008e3e:	8b 00                	mov    (%eax),%eax
c0008e40:	83 ec 0c             	sub    $0xc,%esp
c0008e43:	50                   	push   %eax
c0008e44:	e8 7f f9 ff ff       	call   c00087c8 <inode_close>
c0008e49:	83 c4 10             	add    $0x10,%esp
  sys_free(dir);
c0008e4c:	83 ec 0c             	sub    $0xc,%esp
c0008e4f:	ff 75 08             	push   0x8(%ebp)
c0008e52:	e8 ec a7 ff ff       	call   c0003643 <sys_free>
c0008e57:	83 c4 10             	add    $0x10,%esp
c0008e5a:	eb 01                	jmp    c0008e5d <dir_close+0x31>
    return;
c0008e5c:	90                   	nop
}
c0008e5d:	c9                   	leave  
c0008e5e:	c3                   	ret    

c0008e5f <create_dir_entry>:

// 在内存中初始化目录项p_de
void create_dir_entry(char *filename, uint32_t inode_no, uint8_t file_type,
                      struct dir_entry *p_de) {
c0008e5f:	55                   	push   %ebp
c0008e60:	89 e5                	mov    %esp,%ebp
c0008e62:	83 ec 18             	sub    $0x18,%esp
c0008e65:	8b 45 10             	mov    0x10(%ebp),%eax
c0008e68:	88 45 f4             	mov    %al,-0xc(%ebp)
  ASSERT(strlen(filename) <= MAX_FILE_NAME_LEN);
c0008e6b:	83 ec 0c             	sub    $0xc,%esp
c0008e6e:	ff 75 08             	push   0x8(%ebp)
c0008e71:	e8 c4 96 ff ff       	call   c000253a <strlen>
c0008e76:	83 c4 10             	add    $0x10,%esp
c0008e79:	83 f8 10             	cmp    $0x10,%eax
c0008e7c:	76 19                	jbe    c0008e97 <create_dir_entry+0x38>
c0008e7e:	68 9c da 00 c0       	push   $0xc000da9c
c0008e83:	68 28 dc 00 c0       	push   $0xc000dc28
c0008e88:	6a 65                	push   $0x65
c0008e8a:	68 c2 da 00 c0       	push   $0xc000dac2
c0008e8f:	e8 44 94 ff ff       	call   c00022d8 <panic_spin>
c0008e94:	83 c4 10             	add    $0x10,%esp
  memcpy(p_de->filename, filename, strlen(filename));
c0008e97:	83 ec 0c             	sub    $0xc,%esp
c0008e9a:	ff 75 08             	push   0x8(%ebp)
c0008e9d:	e8 98 96 ff ff       	call   c000253a <strlen>
c0008ea2:	83 c4 10             	add    $0x10,%esp
c0008ea5:	8b 55 14             	mov    0x14(%ebp),%edx
c0008ea8:	83 ec 04             	sub    $0x4,%esp
c0008eab:	50                   	push   %eax
c0008eac:	ff 75 08             	push   0x8(%ebp)
c0008eaf:	52                   	push   %edx
c0008eb0:	e8 4c 95 ff ff       	call   c0002401 <memcpy>
c0008eb5:	83 c4 10             	add    $0x10,%esp
  p_de->i_no = inode_no;
c0008eb8:	8b 45 14             	mov    0x14(%ebp),%eax
c0008ebb:	8b 55 0c             	mov    0xc(%ebp),%edx
c0008ebe:	89 50 10             	mov    %edx,0x10(%eax)
  p_de->f_type = file_type;
c0008ec1:	0f b6 55 f4          	movzbl -0xc(%ebp),%edx
c0008ec5:	8b 45 14             	mov    0x14(%ebp),%eax
c0008ec8:	89 50 14             	mov    %edx,0x14(%eax)
}
c0008ecb:	90                   	nop
c0008ecc:	c9                   	leave  
c0008ecd:	c3                   	ret    

c0008ece <sync_dir_entry>:

// 将目录项写入父目录中
bool sync_dir_entry(struct dir *parent_dir, struct dir_entry *p_de,
                    void *io_buf) {
c0008ece:	55                   	push   %ebp
c0008ecf:	89 e5                	mov    %esp,%ebp
c0008ed1:	57                   	push   %edi
c0008ed2:	81 ec 54 02 00 00    	sub    $0x254,%esp
  struct inode *dir_inode = parent_dir->inode;
c0008ed8:	8b 45 08             	mov    0x8(%ebp),%eax
c0008edb:	8b 00                	mov    (%eax),%eax
c0008edd:	89 45 f0             	mov    %eax,-0x10(%ebp)
  uint32_t dir_size = dir_inode->i_size;
c0008ee0:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0008ee3:	8b 40 04             	mov    0x4(%eax),%eax
c0008ee6:	89 45 ec             	mov    %eax,-0x14(%ebp)
  uint32_t dir_entry_size = cur_part->sb->dir_entry_size;
c0008ee9:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0008eee:	8b 40 1c             	mov    0x1c(%eax),%eax
c0008ef1:	8b 40 30             	mov    0x30(%eax),%eax
c0008ef4:	89 45 e8             	mov    %eax,-0x18(%ebp)
  ASSERT(dir_size % dir_entry_size == 0);              // 整数倍
c0008ef7:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0008efa:	ba 00 00 00 00       	mov    $0x0,%edx
c0008eff:	f7 75 e8             	divl   -0x18(%ebp)
c0008f02:	89 d0                	mov    %edx,%eax
c0008f04:	85 c0                	test   %eax,%eax
c0008f06:	74 19                	je     c0008f21 <sync_dir_entry+0x53>
c0008f08:	68 cc da 00 c0       	push   $0xc000dacc
c0008f0d:	68 3c dc 00 c0       	push   $0xc000dc3c
c0008f12:	6a 71                	push   $0x71
c0008f14:	68 c2 da 00 c0       	push   $0xc000dac2
c0008f19:	e8 ba 93 ff ff       	call   c00022d8 <panic_spin>
c0008f1e:	83 c4 10             	add    $0x10,%esp
  uint32_t dir_entry_per_sec = (512 / dir_entry_size); // 每扇区最大的目录项数
c0008f21:	b8 00 02 00 00       	mov    $0x200,%eax
c0008f26:	ba 00 00 00 00       	mov    $0x0,%edx
c0008f2b:	f7 75 e8             	divl   -0x18(%ebp)
c0008f2e:	89 45 e4             	mov    %eax,-0x1c(%ebp)
  int32_t block_lba = -1;
c0008f31:	c7 45 e0 ff ff ff ff 	movl   $0xffffffff,-0x20(%ebp)

  // 将该目录的所有扇区地址（12个直接块+128个间接块）存入all_blocks
  uint8_t block_idx = 0;
c0008f38:	c6 45 f7 00          	movb   $0x0,-0x9(%ebp)
  uint32_t all_blocks[140] = {0}; // 保存目录所有的块
c0008f3c:	8d 95 a8 fd ff ff    	lea    -0x258(%ebp),%edx
c0008f42:	b8 00 00 00 00       	mov    $0x0,%eax
c0008f47:	b9 8c 00 00 00       	mov    $0x8c,%ecx
c0008f4c:	89 d7                	mov    %edx,%edi
c0008f4e:	f3 ab                	rep stos %eax,%es:(%edi)

  while (block_idx < 12) {
c0008f50:	eb 22                	jmp    c0008f74 <sync_dir_entry+0xa6>
    all_blocks[block_idx] = dir_inode->i_sectors[block_idx];
c0008f52:	0f b6 4d f7          	movzbl -0x9(%ebp),%ecx
c0008f56:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0008f5a:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0008f5d:	83 c1 04             	add    $0x4,%ecx
c0008f60:	8b 14 8a             	mov    (%edx,%ecx,4),%edx
c0008f63:	89 94 85 a8 fd ff ff 	mov    %edx,-0x258(%ebp,%eax,4)
    block_idx++;
c0008f6a:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0008f6e:	83 c0 01             	add    $0x1,%eax
c0008f71:	88 45 f7             	mov    %al,-0x9(%ebp)
  while (block_idx < 12) {
c0008f74:	80 7d f7 0b          	cmpb   $0xb,-0x9(%ebp)
c0008f78:	76 d8                	jbe    c0008f52 <sync_dir_entry+0x84>
  }

  struct dir_entry *dir_e = (struct dir_entry *)io_buf; // 在io_buf中遍历目录项
c0008f7a:	8b 45 10             	mov    0x10(%ebp),%eax
c0008f7d:	89 45 dc             	mov    %eax,-0x24(%ebp)
  int32_t block_bitmap_idx = -1;
c0008f80:	c7 45 d8 ff ff ff ff 	movl   $0xffffffff,-0x28(%ebp)

  // 开始遍历所有块寻找目录项空位（无空闲则申请新扇区来存
  block_idx = 0;
c0008f87:	c6 45 f7 00          	movb   $0x0,-0x9(%ebp)
  while (block_idx < 140) {
c0008f8b:	e9 7b 03 00 00       	jmp    c000930b <sync_dir_entry+0x43d>
    block_bitmap_idx = -1;
c0008f90:	c7 45 d8 ff ff ff ff 	movl   $0xffffffff,-0x28(%ebp)
    if (all_blocks[block_idx] == 0) {
c0008f97:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0008f9b:	8b 84 85 a8 fd ff ff 	mov    -0x258(%ebp,%eax,4),%eax
c0008fa2:	85 c0                	test   %eax,%eax
c0008fa4:	0f 85 6f 02 00 00    	jne    c0009219 <sync_dir_entry+0x34b>
      block_lba = block_bitmap_malloc(cur_part);
c0008faa:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0008faf:	83 ec 0c             	sub    $0xc,%esp
c0008fb2:	50                   	push   %eax
c0008fb3:	e8 c5 0b 00 00       	call   c0009b7d <block_bitmap_malloc>
c0008fb8:	83 c4 10             	add    $0x10,%esp
c0008fbb:	89 45 e0             	mov    %eax,-0x20(%ebp)
      if (block_lba == -1) {
c0008fbe:	83 7d e0 ff          	cmpl   $0xffffffff,-0x20(%ebp)
c0008fc2:	75 1a                	jne    c0008fde <sync_dir_entry+0x110>
        printk("malloc block bitmap for sync_dir_entry failed\n");
c0008fc4:	83 ec 0c             	sub    $0xc,%esp
c0008fc7:	68 ec da 00 c0       	push   $0xc000daec
c0008fcc:	e8 e3 c6 ff ff       	call   c00056b4 <printk>
c0008fd1:	83 c4 10             	add    $0x10,%esp
        return false;
c0008fd4:	b8 00 00 00 00       	mov    $0x0,%eax
c0008fd9:	e9 4c 03 00 00       	jmp    c000932a <sync_dir_entry+0x45c>
      }

      // 【每分配一个块就同步一次block_bitmap】
      block_bitmap_idx = block_lba - cur_part->sb->data_start_lba;
c0008fde:	8b 55 e0             	mov    -0x20(%ebp),%edx
c0008fe1:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0008fe6:	8b 40 1c             	mov    0x1c(%eax),%eax
c0008fe9:	8b 48 28             	mov    0x28(%eax),%ecx
c0008fec:	89 d0                	mov    %edx,%eax
c0008fee:	29 c8                	sub    %ecx,%eax
c0008ff0:	89 45 d8             	mov    %eax,-0x28(%ebp)
      ASSERT(block_bitmap_idx != -1);
c0008ff3:	83 7d d8 ff          	cmpl   $0xffffffff,-0x28(%ebp)
c0008ff7:	75 1c                	jne    c0009015 <sync_dir_entry+0x147>
c0008ff9:	68 1b db 00 c0       	push   $0xc000db1b
c0008ffe:	68 3c dc 00 c0       	push   $0xc000dc3c
c0009003:	68 8e 00 00 00       	push   $0x8e
c0009008:	68 c2 da 00 c0       	push   $0xc000dac2
c000900d:	e8 c6 92 ff ff       	call   c00022d8 <panic_spin>
c0009012:	83 c4 10             	add    $0x10,%esp
      bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
c0009015:	8b 55 d8             	mov    -0x28(%ebp),%edx
c0009018:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000901d:	83 ec 04             	sub    $0x4,%esp
c0009020:	6a 01                	push   $0x1
c0009022:	52                   	push   %edx
c0009023:	50                   	push   %eax
c0009024:	e8 a6 0b 00 00       	call   c0009bcf <bitmap_sync>
c0009029:	83 c4 10             	add    $0x10,%esp
      block_bitmap_idx = -1;
c000902c:	c7 45 d8 ff ff ff ff 	movl   $0xffffffff,-0x28(%ebp)

      if (block_idx < 12) { // 直接块
c0009033:	80 7d f7 0b          	cmpb   $0xb,-0x9(%ebp)
c0009037:	77 27                	ja     c0009060 <sync_dir_entry+0x192>
        dir_inode->i_sectors[block_idx] = all_blocks[block_idx] = block_lba;
c0009039:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c000903d:	8b 55 e0             	mov    -0x20(%ebp),%edx
c0009040:	89 94 85 a8 fd ff ff 	mov    %edx,-0x258(%ebp,%eax,4)
c0009047:	0f b6 4d f7          	movzbl -0x9(%ebp),%ecx
c000904b:	8b 94 85 a8 fd ff ff 	mov    -0x258(%ebp,%eax,4),%edx
c0009052:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0009055:	83 c1 04             	add    $0x4,%ecx
c0009058:	89 14 88             	mov    %edx,(%eax,%ecx,4)
c000905b:	e9 53 01 00 00       	jmp    c00091b3 <sync_dir_entry+0x2e5>
      } else if (block_idx == 12) { // 未分配一级间接块表
c0009060:	80 7d f7 0c          	cmpb   $0xc,-0x9(%ebp)
c0009064:	0f 85 16 01 00 00    	jne    c0009180 <sync_dir_entry+0x2b2>
        // 将上面分配的块作为一级间接块表地址
        dir_inode->i_sectors[12] = block_lba;
c000906a:	8b 55 e0             	mov    -0x20(%ebp),%edx
c000906d:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0009070:	89 50 40             	mov    %edx,0x40(%eax)
        block_lba = -1;
c0009073:	c7 45 e0 ff ff ff ff 	movl   $0xffffffff,-0x20(%ebp)
        // 再分配一个第0个间接块
        block_lba = block_bitmap_malloc(cur_part);
c000907a:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000907f:	83 ec 0c             	sub    $0xc,%esp
c0009082:	50                   	push   %eax
c0009083:	e8 f5 0a 00 00       	call   c0009b7d <block_bitmap_malloc>
c0009088:	83 c4 10             	add    $0x10,%esp
c000908b:	89 45 e0             	mov    %eax,-0x20(%ebp)
        if (block_lba == -1) {
c000908e:	83 7d e0 ff          	cmpl   $0xffffffff,-0x20(%ebp)
c0009092:	75 6e                	jne    c0009102 <sync_dir_entry+0x234>
          block_bitmap_idx =
              dir_inode->i_sectors[12] - cur_part->sb->data_start_lba;
c0009094:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0009097:	8b 50 40             	mov    0x40(%eax),%edx
c000909a:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000909f:	8b 40 1c             	mov    0x1c(%eax),%eax
c00090a2:	8b 48 28             	mov    0x28(%eax),%ecx
c00090a5:	89 d0                	mov    %edx,%eax
c00090a7:	29 c8                	sub    %ecx,%eax
          block_bitmap_idx =
c00090a9:	89 45 d8             	mov    %eax,-0x28(%ebp)
          bitmap_set(&cur_part->block_bitmap, block_bitmap_idx, 0);
c00090ac:	8b 45 d8             	mov    -0x28(%ebp),%eax
c00090af:	8b 15 d8 29 01 c0    	mov    0xc00129d8,%edx
c00090b5:	83 c2 20             	add    $0x20,%edx
c00090b8:	83 ec 04             	sub    $0x4,%esp
c00090bb:	6a 00                	push   $0x0
c00090bd:	50                   	push   %eax
c00090be:	52                   	push   %edx
c00090bf:	e8 45 98 ff ff       	call   c0002909 <bitmap_set>
c00090c4:	83 c4 10             	add    $0x10,%esp
          // 同步到磁盘
          bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
c00090c7:	8b 55 d8             	mov    -0x28(%ebp),%edx
c00090ca:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c00090cf:	83 ec 04             	sub    $0x4,%esp
c00090d2:	6a 01                	push   $0x1
c00090d4:	52                   	push   %edx
c00090d5:	50                   	push   %eax
c00090d6:	e8 f4 0a 00 00       	call   c0009bcf <bitmap_sync>
c00090db:	83 c4 10             	add    $0x10,%esp
          dir_inode->i_sectors[12] = 0;
c00090de:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00090e1:	c7 40 40 00 00 00 00 	movl   $0x0,0x40(%eax)
          printk("malloc block bitmap for sync_dir_entry failed\n");
c00090e8:	83 ec 0c             	sub    $0xc,%esp
c00090eb:	68 ec da 00 c0       	push   $0xc000daec
c00090f0:	e8 bf c5 ff ff       	call   c00056b4 <printk>
c00090f5:	83 c4 10             	add    $0x10,%esp
          return false;
c00090f8:	b8 00 00 00 00       	mov    $0x0,%eax
c00090fd:	e9 28 02 00 00       	jmp    c000932a <sync_dir_entry+0x45c>
        }

        // 【每分配一个块就同步一次block_bitmap】
        block_bitmap_idx = block_lba - cur_part->sb->data_start_lba;
c0009102:	8b 55 e0             	mov    -0x20(%ebp),%edx
c0009105:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000910a:	8b 40 1c             	mov    0x1c(%eax),%eax
c000910d:	8b 48 28             	mov    0x28(%eax),%ecx
c0009110:	89 d0                	mov    %edx,%eax
c0009112:	29 c8                	sub    %ecx,%eax
c0009114:	89 45 d8             	mov    %eax,-0x28(%ebp)
        ASSERT(block_bitmap_idx != -1);
c0009117:	83 7d d8 ff          	cmpl   $0xffffffff,-0x28(%ebp)
c000911b:	75 1c                	jne    c0009139 <sync_dir_entry+0x26b>
c000911d:	68 1b db 00 c0       	push   $0xc000db1b
c0009122:	68 3c dc 00 c0       	push   $0xc000dc3c
c0009127:	68 a7 00 00 00       	push   $0xa7
c000912c:	68 c2 da 00 c0       	push   $0xc000dac2
c0009131:	e8 a2 91 ff ff       	call   c00022d8 <panic_spin>
c0009136:	83 c4 10             	add    $0x10,%esp
        bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
c0009139:	8b 55 d8             	mov    -0x28(%ebp),%edx
c000913c:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0009141:	83 ec 04             	sub    $0x4,%esp
c0009144:	6a 01                	push   $0x1
c0009146:	52                   	push   %edx
c0009147:	50                   	push   %eax
c0009148:	e8 82 0a 00 00       	call   c0009bcf <bitmap_sync>
c000914d:	83 c4 10             	add    $0x10,%esp
        all_blocks[12] = block_lba;
c0009150:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0009153:	89 85 d8 fd ff ff    	mov    %eax,-0x228(%ebp)

        /* 把新分配的第0个间接块地址写入一级间接块表 */
        ide_write(cur_part->my_disk, dir_inode->i_sectors[12], all_blocks + 12,
c0009159:	8d 85 a8 fd ff ff    	lea    -0x258(%ebp),%eax
c000915f:	83 c0 30             	add    $0x30,%eax
c0009162:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0009165:	8b 4a 40             	mov    0x40(%edx),%ecx
c0009168:	8b 15 d8 29 01 c0    	mov    0xc00129d8,%edx
c000916e:	8b 52 08             	mov    0x8(%edx),%edx
c0009171:	6a 01                	push   $0x1
c0009173:	50                   	push   %eax
c0009174:	51                   	push   %ecx
c0009175:	52                   	push   %edx
c0009176:	e8 24 ca ff ff       	call   c0005b9f <ide_write>
c000917b:	83 c4 10             	add    $0x10,%esp
c000917e:	eb 33                	jmp    c00091b3 <sync_dir_entry+0x2e5>
                  1);
      } else { // 建立间接块
        all_blocks[block_idx] = block_lba;
c0009180:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0009184:	8b 55 e0             	mov    -0x20(%ebp),%edx
c0009187:	89 94 85 a8 fd ff ff 	mov    %edx,-0x258(%ebp,%eax,4)
        // 把新分配的第(block_idx-12)个间接块地址写入一级间接块表
        ide_write(cur_part->my_disk, dir_inode->i_sectors[12], all_blocks + 12,
c000918e:	8d 85 a8 fd ff ff    	lea    -0x258(%ebp),%eax
c0009194:	83 c0 30             	add    $0x30,%eax
c0009197:	8b 55 f0             	mov    -0x10(%ebp),%edx
c000919a:	8b 4a 40             	mov    0x40(%edx),%ecx
c000919d:	8b 15 d8 29 01 c0    	mov    0xc00129d8,%edx
c00091a3:	8b 52 08             	mov    0x8(%edx),%edx
c00091a6:	6a 01                	push   $0x1
c00091a8:	50                   	push   %eax
c00091a9:	51                   	push   %ecx
c00091aa:	52                   	push   %edx
c00091ab:	e8 ef c9 ff ff       	call   c0005b9f <ide_write>
c00091b0:	83 c4 10             	add    $0x10,%esp
                  1);
      }

      // 再将新目录项p_de写入新分配的间接块
      memset(io_buf, 0, 512);
c00091b3:	83 ec 04             	sub    $0x4,%esp
c00091b6:	68 00 02 00 00       	push   $0x200
c00091bb:	6a 00                	push   $0x0
c00091bd:	ff 75 10             	push   0x10(%ebp)
c00091c0:	e8 e9 91 ff ff       	call   c00023ae <memset>
c00091c5:	83 c4 10             	add    $0x10,%esp
      memcpy(io_buf, p_de, dir_entry_size);
c00091c8:	83 ec 04             	sub    $0x4,%esp
c00091cb:	ff 75 e8             	push   -0x18(%ebp)
c00091ce:	ff 75 0c             	push   0xc(%ebp)
c00091d1:	ff 75 10             	push   0x10(%ebp)
c00091d4:	e8 28 92 ff ff       	call   c0002401 <memcpy>
c00091d9:	83 c4 10             	add    $0x10,%esp
      ide_write(cur_part->my_disk, all_blocks[block_idx], io_buf, 1);
c00091dc:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c00091e0:	8b 94 85 a8 fd ff ff 	mov    -0x258(%ebp,%eax,4),%edx
c00091e7:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c00091ec:	8b 40 08             	mov    0x8(%eax),%eax
c00091ef:	6a 01                	push   $0x1
c00091f1:	ff 75 10             	push   0x10(%ebp)
c00091f4:	52                   	push   %edx
c00091f5:	50                   	push   %eax
c00091f6:	e8 a4 c9 ff ff       	call   c0005b9f <ide_write>
c00091fb:	83 c4 10             	add    $0x10,%esp
      dir_inode->i_size += dir_entry_size;
c00091fe:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0009201:	8b 50 04             	mov    0x4(%eax),%edx
c0009204:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0009207:	01 c2                	add    %eax,%edx
c0009209:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000920c:	89 50 04             	mov    %edx,0x4(%eax)
      return true;
c000920f:	b8 01 00 00 00       	mov    $0x1,%eax
c0009214:	e9 11 01 00 00       	jmp    c000932a <sync_dir_entry+0x45c>
    }

    // 若第block_idx块已存在，将其读进内存，然后在该块中查找空目录项
    ide_read(cur_part->my_disk, all_blocks[block_idx], io_buf, 1);
c0009219:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c000921d:	8b 94 85 a8 fd ff ff 	mov    -0x258(%ebp,%eax,4),%edx
c0009224:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0009229:	8b 40 08             	mov    0x8(%eax),%eax
c000922c:	6a 01                	push   $0x1
c000922e:	ff 75 10             	push   0x10(%ebp)
c0009231:	52                   	push   %edx
c0009232:	50                   	push   %eax
c0009233:	e8 f3 c7 ff ff       	call   c0005a2b <ide_read>
c0009238:	83 c4 10             	add    $0x10,%esp
    uint8_t dir_entry_idx = 0;
c000923b:	c6 45 f6 00          	movb   $0x0,-0xa(%ebp)
    while (dir_entry_idx < dir_entry_per_sec) { // 在扇区内查找空目录项
c000923f:	e9 85 00 00 00       	jmp    c00092c9 <sync_dir_entry+0x3fb>
      if ((dir_e + dir_entry_idx)->f_type == FT_UNKNOWN) {
c0009244:	0f b6 55 f6          	movzbl -0xa(%ebp),%edx
c0009248:	89 d0                	mov    %edx,%eax
c000924a:	01 c0                	add    %eax,%eax
c000924c:	01 d0                	add    %edx,%eax
c000924e:	c1 e0 03             	shl    $0x3,%eax
c0009251:	89 c2                	mov    %eax,%edx
c0009253:	8b 45 dc             	mov    -0x24(%ebp),%eax
c0009256:	01 d0                	add    %edx,%eax
c0009258:	8b 40 14             	mov    0x14(%eax),%eax
c000925b:	85 c0                	test   %eax,%eax
c000925d:	75 60                	jne    c00092bf <sync_dir_entry+0x3f1>
        memcpy(dir_e + dir_entry_idx, p_de, dir_entry_size);
c000925f:	0f b6 55 f6          	movzbl -0xa(%ebp),%edx
c0009263:	89 d0                	mov    %edx,%eax
c0009265:	01 c0                	add    %eax,%eax
c0009267:	01 d0                	add    %edx,%eax
c0009269:	c1 e0 03             	shl    $0x3,%eax
c000926c:	89 c2                	mov    %eax,%edx
c000926e:	8b 45 dc             	mov    -0x24(%ebp),%eax
c0009271:	01 d0                	add    %edx,%eax
c0009273:	83 ec 04             	sub    $0x4,%esp
c0009276:	ff 75 e8             	push   -0x18(%ebp)
c0009279:	ff 75 0c             	push   0xc(%ebp)
c000927c:	50                   	push   %eax
c000927d:	e8 7f 91 ff ff       	call   c0002401 <memcpy>
c0009282:	83 c4 10             	add    $0x10,%esp
        ide_write(cur_part->my_disk, all_blocks[block_idx], io_buf, 1);
c0009285:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0009289:	8b 94 85 a8 fd ff ff 	mov    -0x258(%ebp,%eax,4),%edx
c0009290:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0009295:	8b 40 08             	mov    0x8(%eax),%eax
c0009298:	6a 01                	push   $0x1
c000929a:	ff 75 10             	push   0x10(%ebp)
c000929d:	52                   	push   %edx
c000929e:	50                   	push   %eax
c000929f:	e8 fb c8 ff ff       	call   c0005b9f <ide_write>
c00092a4:	83 c4 10             	add    $0x10,%esp
        dir_inode->i_size += dir_entry_size;
c00092a7:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00092aa:	8b 50 04             	mov    0x4(%eax),%edx
c00092ad:	8b 45 e8             	mov    -0x18(%ebp),%eax
c00092b0:	01 c2                	add    %eax,%edx
c00092b2:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00092b5:	89 50 04             	mov    %edx,0x4(%eax)
        return true;
c00092b8:	b8 01 00 00 00       	mov    $0x1,%eax
c00092bd:	eb 6b                	jmp    c000932a <sync_dir_entry+0x45c>
      }
      dir_entry_idx++;
c00092bf:	0f b6 45 f6          	movzbl -0xa(%ebp),%eax
c00092c3:	83 c0 01             	add    $0x1,%eax
c00092c6:	88 45 f6             	mov    %al,-0xa(%ebp)
    while (dir_entry_idx < dir_entry_per_sec) { // 在扇区内查找空目录项
c00092c9:	0f b6 45 f6          	movzbl -0xa(%ebp),%eax
c00092cd:	39 45 e4             	cmp    %eax,-0x1c(%ebp)
c00092d0:	0f 87 6e ff ff ff    	ja     c0009244 <sync_dir_entry+0x376>
    }
    block_idx++;
c00092d6:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c00092da:	83 c0 01             	add    $0x1,%eax
c00092dd:	88 45 f7             	mov    %al,-0x9(%ebp)
    if (block_idx > 12) {
c00092e0:	80 7d f7 0c          	cmpb   $0xc,-0x9(%ebp)
c00092e4:	76 25                	jbe    c000930b <sync_dir_entry+0x43d>
      ide_read(cur_part->my_disk, all_blocks[12], all_blocks + 12, 1);
c00092e6:	8d 85 a8 fd ff ff    	lea    -0x258(%ebp),%eax
c00092ec:	83 c0 30             	add    $0x30,%eax
c00092ef:	8b 8d d8 fd ff ff    	mov    -0x228(%ebp),%ecx
c00092f5:	8b 15 d8 29 01 c0    	mov    0xc00129d8,%edx
c00092fb:	8b 52 08             	mov    0x8(%edx),%edx
c00092fe:	6a 01                	push   $0x1
c0009300:	50                   	push   %eax
c0009301:	51                   	push   %ecx
c0009302:	52                   	push   %edx
c0009303:	e8 23 c7 ff ff       	call   c0005a2b <ide_read>
c0009308:	83 c4 10             	add    $0x10,%esp
  while (block_idx < 140) {
c000930b:	80 7d f7 8b          	cmpb   $0x8b,-0x9(%ebp)
c000930f:	0f 86 7b fc ff ff    	jbe    c0008f90 <sync_dir_entry+0xc2>
    }
  }
  printk("directory is full!\n");
c0009315:	83 ec 0c             	sub    $0xc,%esp
c0009318:	68 32 db 00 c0       	push   $0xc000db32
c000931d:	e8 92 c3 ff ff       	call   c00056b4 <printk>
c0009322:	83 c4 10             	add    $0x10,%esp
  return false;
c0009325:	b8 00 00 00 00       	mov    $0x0,%eax
}
c000932a:	8b 7d fc             	mov    -0x4(%ebp),%edi
c000932d:	c9                   	leave  
c000932e:	c3                   	ret    

c000932f <delete_dir_entry>:

// 把分区part目录pdir中编号为inode_no的目录项删除
bool delete_dir_entry(struct partition *part, struct dir *pdir,
                      uint32_t inode_no, void *io_buf) {
c000932f:	55                   	push   %ebp
c0009330:	89 e5                	mov    %esp,%ebp
c0009332:	57                   	push   %edi
c0009333:	81 ec 64 02 00 00    	sub    $0x264,%esp
  struct inode *dir_inode = pdir->inode;
c0009339:	8b 45 0c             	mov    0xc(%ebp),%eax
c000933c:	8b 00                	mov    (%eax),%eax
c000933e:	89 45 e0             	mov    %eax,-0x20(%ebp)
  uint32_t block_idx = 0, all_blocks[140] = {0};
c0009341:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
c0009348:	8d 95 9c fd ff ff    	lea    -0x264(%ebp),%edx
c000934e:	b8 00 00 00 00       	mov    $0x0,%eax
c0009353:	b9 8c 00 00 00       	mov    $0x8c,%ecx
c0009358:	89 d7                	mov    %edx,%edi
c000935a:	f3 ab                	rep stos %eax,%es:(%edi)

  while (block_idx < 12) {
c000935c:	eb 1a                	jmp    c0009378 <delete_dir_entry+0x49>
    all_blocks[block_idx] = dir_inode->i_sectors[block_idx];
c000935e:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0009361:	8b 55 f4             	mov    -0xc(%ebp),%edx
c0009364:	83 c2 04             	add    $0x4,%edx
c0009367:	8b 14 90             	mov    (%eax,%edx,4),%edx
c000936a:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000936d:	89 94 85 9c fd ff ff 	mov    %edx,-0x264(%ebp,%eax,4)
    block_idx++;
c0009374:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
  while (block_idx < 12) {
c0009378:	83 7d f4 0b          	cmpl   $0xb,-0xc(%ebp)
c000937c:	76 e0                	jbe    c000935e <delete_dir_entry+0x2f>
  }
  if (dir_inode->i_sectors[12]) {
c000937e:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0009381:	8b 40 40             	mov    0x40(%eax),%eax
c0009384:	85 c0                	test   %eax,%eax
c0009386:	74 22                	je     c00093aa <delete_dir_entry+0x7b>
    ide_read(part->my_disk, dir_inode->i_sectors[12], all_blocks + 12, 1);
c0009388:	8d 85 9c fd ff ff    	lea    -0x264(%ebp),%eax
c000938e:	83 c0 30             	add    $0x30,%eax
c0009391:	8b 55 e0             	mov    -0x20(%ebp),%edx
c0009394:	8b 4a 40             	mov    0x40(%edx),%ecx
c0009397:	8b 55 08             	mov    0x8(%ebp),%edx
c000939a:	8b 52 08             	mov    0x8(%edx),%edx
c000939d:	6a 01                	push   $0x1
c000939f:	50                   	push   %eax
c00093a0:	51                   	push   %ecx
c00093a1:	52                   	push   %edx
c00093a2:	e8 84 c6 ff ff       	call   c0005a2b <ide_read>
c00093a7:	83 c4 10             	add    $0x10,%esp
  }

  uint32_t dir_entry_size = part->sb->dir_entry_size;
c00093aa:	8b 45 08             	mov    0x8(%ebp),%eax
c00093ad:	8b 40 1c             	mov    0x1c(%eax),%eax
c00093b0:	8b 40 30             	mov    0x30(%eax),%eax
c00093b3:	89 45 dc             	mov    %eax,-0x24(%ebp)
  uint32_t dir_entry_per_sec =
c00093b6:	b8 00 02 00 00       	mov    $0x200,%eax
c00093bb:	ba 00 00 00 00       	mov    $0x0,%edx
c00093c0:	f7 75 dc             	divl   -0x24(%ebp)
c00093c3:	89 45 d8             	mov    %eax,-0x28(%ebp)
      (SECTOR_SIZE / dir_entry_size); // 每扇区最大的目录项数目
  struct dir_entry *dir_e = (struct dir_entry *)io_buf;
c00093c6:	8b 45 14             	mov    0x14(%ebp),%eax
c00093c9:	89 45 d4             	mov    %eax,-0x2c(%ebp)
  struct dir_entry *dir_entry_found = NULL;
c00093cc:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
  uint8_t dir_entry_idx, dir_entry_cnt; // 此扇区内目录项总数
  bool is_dir_first_block = false; // 当前待删除的块是否是目录第一个块“.”
c00093d3:	c7 45 e8 00 00 00 00 	movl   $0x0,-0x18(%ebp)

  // 遍历所有块寻找目录项
  block_idx = 0;
c00093da:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  while (block_idx < 140) {
c00093e1:	e9 9a 03 00 00       	jmp    c0009780 <delete_dir_entry+0x451>
    is_dir_first_block = false;
c00093e6:	c7 45 e8 00 00 00 00 	movl   $0x0,-0x18(%ebp)
    if (all_blocks[block_idx] == 0) {
c00093ed:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00093f0:	8b 84 85 9c fd ff ff 	mov    -0x264(%ebp,%eax,4),%eax
c00093f7:	85 c0                	test   %eax,%eax
c00093f9:	75 09                	jne    c0009404 <delete_dir_entry+0xd5>
      block_idx++;
c00093fb:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
      continue;
c00093ff:	e9 7c 03 00 00       	jmp    c0009780 <delete_dir_entry+0x451>
    }
    dir_entry_idx = dir_entry_cnt = 0;
c0009404:	c6 45 ee 00          	movb   $0x0,-0x12(%ebp)
c0009408:	0f b6 45 ee          	movzbl -0x12(%ebp),%eax
c000940c:	88 45 ef             	mov    %al,-0x11(%ebp)
    memset(io_buf, 0, SECTOR_SIZE);
c000940f:	83 ec 04             	sub    $0x4,%esp
c0009412:	68 00 02 00 00       	push   $0x200
c0009417:	6a 00                	push   $0x0
c0009419:	ff 75 14             	push   0x14(%ebp)
c000941c:	e8 8d 8f ff ff       	call   c00023ae <memset>
c0009421:	83 c4 10             	add    $0x10,%esp
    // 读扇区获取目录项
    ide_read(part->my_disk, all_blocks[block_idx], io_buf, 1);
c0009424:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0009427:	8b 94 85 9c fd ff ff 	mov    -0x264(%ebp,%eax,4),%edx
c000942e:	8b 45 08             	mov    0x8(%ebp),%eax
c0009431:	8b 40 08             	mov    0x8(%eax),%eax
c0009434:	6a 01                	push   $0x1
c0009436:	ff 75 14             	push   0x14(%ebp)
c0009439:	52                   	push   %edx
c000943a:	50                   	push   %eax
c000943b:	e8 eb c5 ff ff       	call   c0005a2b <ide_read>
c0009440:	83 c4 10             	add    $0x10,%esp

    /* 遍历所有的目录项，统计该扇区的目录项数量及是否有待删除的目录项 */
    while (dir_entry_idx < dir_entry_per_sec) {
c0009443:	e9 13 01 00 00       	jmp    c000955b <delete_dir_entry+0x22c>
      if ((dir_e + dir_entry_idx)->f_type != FT_UNKNOWN) { // 该目录项有意义
c0009448:	0f b6 55 ef          	movzbl -0x11(%ebp),%edx
c000944c:	89 d0                	mov    %edx,%eax
c000944e:	01 c0                	add    %eax,%eax
c0009450:	01 d0                	add    %edx,%eax
c0009452:	c1 e0 03             	shl    $0x3,%eax
c0009455:	89 c2                	mov    %eax,%edx
c0009457:	8b 45 d4             	mov    -0x2c(%ebp),%eax
c000945a:	01 d0                	add    %edx,%eax
c000945c:	8b 40 14             	mov    0x14(%eax),%eax
c000945f:	85 c0                	test   %eax,%eax
c0009461:	0f 84 ea 00 00 00    	je     c0009551 <delete_dir_entry+0x222>
        if (!strcmp((dir_e + dir_entry_idx)->filename, ".")) {
c0009467:	0f b6 55 ef          	movzbl -0x11(%ebp),%edx
c000946b:	89 d0                	mov    %edx,%eax
c000946d:	01 c0                	add    %eax,%eax
c000946f:	01 d0                	add    %edx,%eax
c0009471:	c1 e0 03             	shl    $0x3,%eax
c0009474:	89 c2                	mov    %eax,%edx
c0009476:	8b 45 d4             	mov    -0x2c(%ebp),%eax
c0009479:	01 d0                	add    %edx,%eax
c000947b:	83 ec 08             	sub    $0x8,%esp
c000947e:	68 46 db 00 c0       	push   $0xc000db46
c0009483:	50                   	push   %eax
c0009484:	e8 f8 90 ff ff       	call   c0002581 <strcmp>
c0009489:	83 c4 10             	add    $0x10,%esp
c000948c:	84 c0                	test   %al,%al
c000948e:	75 0c                	jne    c000949c <delete_dir_entry+0x16d>
          is_dir_first_block = true;
c0009490:	c7 45 e8 01 00 00 00 	movl   $0x1,-0x18(%ebp)
c0009497:	e9 b5 00 00 00       	jmp    c0009551 <delete_dir_entry+0x222>
        } else if (strcmp((dir_e + dir_entry_idx)->filename, ".") &&
c000949c:	0f b6 55 ef          	movzbl -0x11(%ebp),%edx
c00094a0:	89 d0                	mov    %edx,%eax
c00094a2:	01 c0                	add    %eax,%eax
c00094a4:	01 d0                	add    %edx,%eax
c00094a6:	c1 e0 03             	shl    $0x3,%eax
c00094a9:	89 c2                	mov    %eax,%edx
c00094ab:	8b 45 d4             	mov    -0x2c(%ebp),%eax
c00094ae:	01 d0                	add    %edx,%eax
c00094b0:	83 ec 08             	sub    $0x8,%esp
c00094b3:	68 46 db 00 c0       	push   $0xc000db46
c00094b8:	50                   	push   %eax
c00094b9:	e8 c3 90 ff ff       	call   c0002581 <strcmp>
c00094be:	83 c4 10             	add    $0x10,%esp
c00094c1:	84 c0                	test   %al,%al
c00094c3:	0f 84 88 00 00 00    	je     c0009551 <delete_dir_entry+0x222>
                   strcmp((dir_e + dir_entry_idx)->filename, "..")) {
c00094c9:	0f b6 55 ef          	movzbl -0x11(%ebp),%edx
c00094cd:	89 d0                	mov    %edx,%eax
c00094cf:	01 c0                	add    %eax,%eax
c00094d1:	01 d0                	add    %edx,%eax
c00094d3:	c1 e0 03             	shl    $0x3,%eax
c00094d6:	89 c2                	mov    %eax,%edx
c00094d8:	8b 45 d4             	mov    -0x2c(%ebp),%eax
c00094db:	01 d0                	add    %edx,%eax
c00094dd:	83 ec 08             	sub    $0x8,%esp
c00094e0:	68 48 db 00 c0       	push   $0xc000db48
c00094e5:	50                   	push   %eax
c00094e6:	e8 96 90 ff ff       	call   c0002581 <strcmp>
c00094eb:	83 c4 10             	add    $0x10,%esp
        } else if (strcmp((dir_e + dir_entry_idx)->filename, ".") &&
c00094ee:	84 c0                	test   %al,%al
c00094f0:	74 5f                	je     c0009551 <delete_dir_entry+0x222>
          dir_entry_cnt++; // 用来判断删除目录项后是否回收该扇区
c00094f2:	0f b6 45 ee          	movzbl -0x12(%ebp),%eax
c00094f6:	83 c0 01             	add    $0x1,%eax
c00094f9:	88 45 ee             	mov    %al,-0x12(%ebp)
          if ((dir_e + dir_entry_idx)->i_no == inode_no) { // 找到此inode
c00094fc:	0f b6 55 ef          	movzbl -0x11(%ebp),%edx
c0009500:	89 d0                	mov    %edx,%eax
c0009502:	01 c0                	add    %eax,%eax
c0009504:	01 d0                	add    %edx,%eax
c0009506:	c1 e0 03             	shl    $0x3,%eax
c0009509:	89 c2                	mov    %eax,%edx
c000950b:	8b 45 d4             	mov    -0x2c(%ebp),%eax
c000950e:	01 d0                	add    %edx,%eax
c0009510:	8b 40 10             	mov    0x10(%eax),%eax
c0009513:	39 45 10             	cmp    %eax,0x10(%ebp)
c0009516:	75 39                	jne    c0009551 <delete_dir_entry+0x222>
            ASSERT(dir_entry_found == NULL);
c0009518:	83 7d f0 00          	cmpl   $0x0,-0x10(%ebp)
c000951c:	74 1c                	je     c000953a <delete_dir_entry+0x20b>
c000951e:	68 4b db 00 c0       	push   $0xc000db4b
c0009523:	68 4c dc 00 c0       	push   $0xc000dc4c
c0009528:	68 fe 00 00 00       	push   $0xfe
c000952d:	68 c2 da 00 c0       	push   $0xc000dac2
c0009532:	e8 a1 8d ff ff       	call   c00022d8 <panic_spin>
c0009537:	83 c4 10             	add    $0x10,%esp
            // 将其记录在dir_entry_found
            dir_entry_found = dir_e + dir_entry_idx;
c000953a:	0f b6 55 ef          	movzbl -0x11(%ebp),%edx
c000953e:	89 d0                	mov    %edx,%eax
c0009540:	01 c0                	add    %eax,%eax
c0009542:	01 d0                	add    %edx,%eax
c0009544:	c1 e0 03             	shl    $0x3,%eax
c0009547:	89 c2                	mov    %eax,%edx
c0009549:	8b 45 d4             	mov    -0x2c(%ebp),%eax
c000954c:	01 d0                	add    %edx,%eax
c000954e:	89 45 f0             	mov    %eax,-0x10(%ebp)
            /* 找到后也继续遍历，统计总目录项数 */
          }
        }
      }
      dir_entry_idx++;
c0009551:	0f b6 45 ef          	movzbl -0x11(%ebp),%eax
c0009555:	83 c0 01             	add    $0x1,%eax
c0009558:	88 45 ef             	mov    %al,-0x11(%ebp)
    while (dir_entry_idx < dir_entry_per_sec) {
c000955b:	0f b6 45 ef          	movzbl -0x11(%ebp),%eax
c000955f:	39 45 d8             	cmp    %eax,-0x28(%ebp)
c0009562:	0f 87 e0 fe ff ff    	ja     c0009448 <delete_dir_entry+0x119>
    }
    /* 此扇区未找到该目录项，继续在下个扇区找 */
    if (dir_entry_found == NULL) {
c0009568:	83 7d f0 00          	cmpl   $0x0,-0x10(%ebp)
c000956c:	75 09                	jne    c0009577 <delete_dir_entry+0x248>
      block_idx++;
c000956e:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
      continue;
c0009572:	e9 09 02 00 00       	jmp    c0009780 <delete_dir_entry+0x451>
    }
    /* 找到目录项 */
    ASSERT(dir_entry_cnt >= 1);
c0009577:	80 7d ee 00          	cmpb   $0x0,-0x12(%ebp)
c000957b:	75 1c                	jne    c0009599 <delete_dir_entry+0x26a>
c000957d:	68 63 db 00 c0       	push   $0xc000db63
c0009582:	68 4c dc 00 c0       	push   $0xc000dc4c
c0009587:	68 0d 01 00 00       	push   $0x10d
c000958c:	68 c2 da 00 c0       	push   $0xc000dac2
c0009591:	e8 42 8d ff ff       	call   c00022d8 <panic_spin>
c0009596:	83 c4 10             	add    $0x10,%esp
    // 除目录第1个扇区外，该扇区只有目录项自己-> 将整个扇区回收
    if (dir_entry_cnt == 1 && !is_dir_first_block) {
c0009599:	80 7d ee 01          	cmpb   $0x1,-0x12(%ebp)
c000959d:	0f 85 43 01 00 00    	jne    c00096e6 <delete_dir_entry+0x3b7>
c00095a3:	83 7d e8 00          	cmpl   $0x0,-0x18(%ebp)
c00095a7:	0f 85 39 01 00 00    	jne    c00096e6 <delete_dir_entry+0x3b7>
      // 1、从块位图中回收该块
      uint32_t block_bitmap_idx =
          all_blocks[block_idx] - part->sb->data_start_lba;
c00095ad:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00095b0:	8b 94 85 9c fd ff ff 	mov    -0x264(%ebp,%eax,4),%edx
c00095b7:	8b 45 08             	mov    0x8(%ebp),%eax
c00095ba:	8b 40 1c             	mov    0x1c(%eax),%eax
c00095bd:	8b 48 28             	mov    0x28(%eax),%ecx
      uint32_t block_bitmap_idx =
c00095c0:	89 d0                	mov    %edx,%eax
c00095c2:	29 c8                	sub    %ecx,%eax
c00095c4:	89 45 d0             	mov    %eax,-0x30(%ebp)
      bitmap_set(&part->block_bitmap, block_bitmap_idx, 0);
c00095c7:	8b 45 08             	mov    0x8(%ebp),%eax
c00095ca:	83 c0 20             	add    $0x20,%eax
c00095cd:	83 ec 04             	sub    $0x4,%esp
c00095d0:	6a 00                	push   $0x0
c00095d2:	ff 75 d0             	push   -0x30(%ebp)
c00095d5:	50                   	push   %eax
c00095d6:	e8 2e 93 ff ff       	call   c0002909 <bitmap_set>
c00095db:	83 c4 10             	add    $0x10,%esp
      bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
c00095de:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c00095e3:	83 ec 04             	sub    $0x4,%esp
c00095e6:	6a 01                	push   $0x1
c00095e8:	ff 75 d0             	push   -0x30(%ebp)
c00095eb:	50                   	push   %eax
c00095ec:	e8 de 05 00 00       	call   c0009bcf <bitmap_sync>
c00095f1:	83 c4 10             	add    $0x10,%esp
      // 2、将块地址从数组i_sectors或索引表中去掉
      if (block_idx < 12) {
c00095f4:	83 7d f4 0b          	cmpl   $0xb,-0xc(%ebp)
c00095f8:	77 15                	ja     c000960f <delete_dir_entry+0x2e0>
        dir_inode->i_sectors[block_idx] = 0;
c00095fa:	8b 45 e0             	mov    -0x20(%ebp),%eax
c00095fd:	8b 55 f4             	mov    -0xc(%ebp),%edx
c0009600:	83 c2 04             	add    $0x4,%edx
c0009603:	c7 04 90 00 00 00 00 	movl   $0x0,(%eax,%edx,4)
    if (dir_entry_cnt == 1 && !is_dir_first_block) {
c000960a:	e9 09 01 00 00       	jmp    c0009718 <delete_dir_entry+0x3e9>
      } else { /* 先判断一级间接索引表的间接块数，如果仅有这个间接块，连同间接索引表块一同回收*/
        uint32_t indirect_blocks = 0;
c000960f:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%ebp)
        uint32_t indirect_block_idx = 12;
c0009616:	c7 45 cc 0c 00 00 00 	movl   $0xc,-0x34(%ebp)
        while (indirect_block_idx < 140) {
c000961d:	eb 12                	jmp    c0009631 <delete_dir_entry+0x302>
          if (all_blocks[indirect_block_idx] != 0) {
c000961f:	8b 45 cc             	mov    -0x34(%ebp),%eax
c0009622:	8b 84 85 9c fd ff ff 	mov    -0x264(%ebp,%eax,4),%eax
c0009629:	85 c0                	test   %eax,%eax
c000962b:	74 04                	je     c0009631 <delete_dir_entry+0x302>
            indirect_blocks++;
c000962d:	83 45 e4 01          	addl   $0x1,-0x1c(%ebp)
        while (indirect_block_idx < 140) {
c0009631:	81 7d cc 8b 00 00 00 	cmpl   $0x8b,-0x34(%ebp)
c0009638:	76 e5                	jbe    c000961f <delete_dir_entry+0x2f0>
          }
        }
        ASSERT(indirect_blocks >= 1);
c000963a:	83 7d e4 00          	cmpl   $0x0,-0x1c(%ebp)
c000963e:	75 1c                	jne    c000965c <delete_dir_entry+0x32d>
c0009640:	68 76 db 00 c0       	push   $0xc000db76
c0009645:	68 4c dc 00 c0       	push   $0xc000dc4c
c000964a:	68 20 01 00 00       	push   $0x120
c000964f:	68 c2 da 00 c0       	push   $0xc000dac2
c0009654:	e8 7f 8c ff ff       	call   c00022d8 <panic_spin>
c0009659:	83 c4 10             	add    $0x10,%esp
        if (indirect_blocks > 1) { // 间接索引表中还有其他间接块
c000965c:	83 7d e4 01          	cmpl   $0x1,-0x1c(%ebp)
c0009660:	76 35                	jbe    c0009697 <delete_dir_entry+0x368>
          all_blocks[block_idx] = 0;
c0009662:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0009665:	c7 84 85 9c fd ff ff 	movl   $0x0,-0x264(%ebp,%eax,4)
c000966c:	00 00 00 00 
          ide_write(part->my_disk, dir_inode->i_sectors[12], all_blocks + 12,
c0009670:	8d 85 9c fd ff ff    	lea    -0x264(%ebp),%eax
c0009676:	83 c0 30             	add    $0x30,%eax
c0009679:	8b 55 e0             	mov    -0x20(%ebp),%edx
c000967c:	8b 4a 40             	mov    0x40(%edx),%ecx
c000967f:	8b 55 08             	mov    0x8(%ebp),%edx
c0009682:	8b 52 08             	mov    0x8(%edx),%edx
c0009685:	6a 01                	push   $0x1
c0009687:	50                   	push   %eax
c0009688:	51                   	push   %ecx
c0009689:	52                   	push   %edx
c000968a:	e8 10 c5 ff ff       	call   c0005b9f <ide_write>
c000968f:	83 c4 10             	add    $0x10,%esp
    if (dir_entry_cnt == 1 && !is_dir_first_block) {
c0009692:	e9 81 00 00 00       	jmp    c0009718 <delete_dir_entry+0x3e9>
                    1);
        } else {
          /* 回收间接索引表所在的块 */
          block_bitmap_idx =
              dir_inode->i_sectors[12] - part->sb->data_start_lba;
c0009697:	8b 45 e0             	mov    -0x20(%ebp),%eax
c000969a:	8b 50 40             	mov    0x40(%eax),%edx
c000969d:	8b 45 08             	mov    0x8(%ebp),%eax
c00096a0:	8b 40 1c             	mov    0x1c(%eax),%eax
c00096a3:	8b 48 28             	mov    0x28(%eax),%ecx
          block_bitmap_idx =
c00096a6:	89 d0                	mov    %edx,%eax
c00096a8:	29 c8                	sub    %ecx,%eax
c00096aa:	89 45 d0             	mov    %eax,-0x30(%ebp)
          bitmap_set(&part->block_bitmap, block_bitmap_idx, 0);
c00096ad:	8b 45 08             	mov    0x8(%ebp),%eax
c00096b0:	83 c0 20             	add    $0x20,%eax
c00096b3:	83 ec 04             	sub    $0x4,%esp
c00096b6:	6a 00                	push   $0x0
c00096b8:	ff 75 d0             	push   -0x30(%ebp)
c00096bb:	50                   	push   %eax
c00096bc:	e8 48 92 ff ff       	call   c0002909 <bitmap_set>
c00096c1:	83 c4 10             	add    $0x10,%esp
          bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
c00096c4:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c00096c9:	83 ec 04             	sub    $0x4,%esp
c00096cc:	6a 01                	push   $0x1
c00096ce:	ff 75 d0             	push   -0x30(%ebp)
c00096d1:	50                   	push   %eax
c00096d2:	e8 f8 04 00 00       	call   c0009bcf <bitmap_sync>
c00096d7:	83 c4 10             	add    $0x10,%esp
          dir_inode->i_sectors[12] = 0; // 将间接索引表地址清0
c00096da:	8b 45 e0             	mov    -0x20(%ebp),%eax
c00096dd:	c7 40 40 00 00 00 00 	movl   $0x0,0x40(%eax)
    if (dir_entry_cnt == 1 && !is_dir_first_block) {
c00096e4:	eb 32                	jmp    c0009718 <delete_dir_entry+0x3e9>
        }
      }
    } else { // 仅将该目录项清空
      memset(dir_entry_found, 0, dir_entry_size);
c00096e6:	83 ec 04             	sub    $0x4,%esp
c00096e9:	ff 75 dc             	push   -0x24(%ebp)
c00096ec:	6a 00                	push   $0x0
c00096ee:	ff 75 f0             	push   -0x10(%ebp)
c00096f1:	e8 b8 8c ff ff       	call   c00023ae <memset>
c00096f6:	83 c4 10             	add    $0x10,%esp
      ide_write(part->my_disk, all_blocks[block_idx], io_buf, 1);
c00096f9:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00096fc:	8b 94 85 9c fd ff ff 	mov    -0x264(%ebp,%eax,4),%edx
c0009703:	8b 45 08             	mov    0x8(%ebp),%eax
c0009706:	8b 40 08             	mov    0x8(%eax),%eax
c0009709:	6a 01                	push   $0x1
c000970b:	ff 75 14             	push   0x14(%ebp)
c000970e:	52                   	push   %edx
c000970f:	50                   	push   %eax
c0009710:	e8 8a c4 ff ff       	call   c0005b9f <ide_write>
c0009715:	83 c4 10             	add    $0x10,%esp
    }

    // 更新inode信息并同步到磁盘
    ASSERT(dir_inode->i_size >= dir_entry_size);
c0009718:	8b 45 e0             	mov    -0x20(%ebp),%eax
c000971b:	8b 40 04             	mov    0x4(%eax),%eax
c000971e:	39 45 dc             	cmp    %eax,-0x24(%ebp)
c0009721:	76 1c                	jbe    c000973f <delete_dir_entry+0x410>
c0009723:	68 8c db 00 c0       	push   $0xc000db8c
c0009728:	68 4c dc 00 c0       	push   $0xc000dc4c
c000972d:	68 34 01 00 00       	push   $0x134
c0009732:	68 c2 da 00 c0       	push   $0xc000dac2
c0009737:	e8 9c 8b ff ff       	call   c00022d8 <panic_spin>
c000973c:	83 c4 10             	add    $0x10,%esp
    dir_inode->i_size -= dir_entry_size;
c000973f:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0009742:	8b 40 04             	mov    0x4(%eax),%eax
c0009745:	2b 45 dc             	sub    -0x24(%ebp),%eax
c0009748:	89 c2                	mov    %eax,%edx
c000974a:	8b 45 e0             	mov    -0x20(%ebp),%eax
c000974d:	89 50 04             	mov    %edx,0x4(%eax)
    memset(io_buf, 0, SECTOR_SIZE * 2);
c0009750:	83 ec 04             	sub    $0x4,%esp
c0009753:	68 00 04 00 00       	push   $0x400
c0009758:	6a 00                	push   $0x0
c000975a:	ff 75 14             	push   0x14(%ebp)
c000975d:	e8 4c 8c ff ff       	call   c00023ae <memset>
c0009762:	83 c4 10             	add    $0x10,%esp
    inode_sync(part, dir_inode, io_buf);
c0009765:	83 ec 04             	sub    $0x4,%esp
c0009768:	ff 75 14             	push   0x14(%ebp)
c000976b:	ff 75 e0             	push   -0x20(%ebp)
c000976e:	ff 75 08             	push   0x8(%ebp)
c0009771:	e8 e8 ed ff ff       	call   c000855e <inode_sync>
c0009776:	83 c4 10             	add    $0x10,%esp
    return true;
c0009779:	b8 01 00 00 00       	mov    $0x1,%eax
c000977e:	eb 12                	jmp    c0009792 <delete_dir_entry+0x463>
  while (block_idx < 140) {
c0009780:	81 7d f4 8b 00 00 00 	cmpl   $0x8b,-0xc(%ebp)
c0009787:	0f 86 59 fc ff ff    	jbe    c00093e6 <delete_dir_entry+0xb7>
  }
  // 所有块中未找到则返回false（这种情况该是serarch_file出错了
  return false;
c000978d:	b8 00 00 00 00       	mov    $0x0,%eax
}
c0009792:	8b 7d fc             	mov    -0x4(%ebp),%edi
c0009795:	c9                   	leave  
c0009796:	c3                   	ret    

c0009797 <dir_read>:

// 读取目录，成功返回1个目录项
struct dir_entry *dir_read(struct dir *dir) {
c0009797:	55                   	push   %ebp
c0009798:	89 e5                	mov    %esp,%ebp
c000979a:	57                   	push   %edi
c000979b:	81 ec 54 02 00 00    	sub    $0x254,%esp
  struct dir_entry *dir_e = (struct dir_entry *)dir->dir_buf;
c00097a1:	8b 45 08             	mov    0x8(%ebp),%eax
c00097a4:	83 c0 08             	add    $0x8,%eax
c00097a7:	89 45 e8             	mov    %eax,-0x18(%ebp)
  struct inode *dir_inode = dir->inode;
c00097aa:	8b 45 08             	mov    0x8(%ebp),%eax
c00097ad:	8b 00                	mov    (%eax),%eax
c00097af:	89 45 e4             	mov    %eax,-0x1c(%ebp)
  uint32_t all_blocks[140] = {0}, block_cnt = 12;
c00097b2:	8d 95 a8 fd ff ff    	lea    -0x258(%ebp),%edx
c00097b8:	b8 00 00 00 00       	mov    $0x0,%eax
c00097bd:	b9 8c 00 00 00       	mov    $0x8c,%ecx
c00097c2:	89 d7                	mov    %edx,%edi
c00097c4:	f3 ab                	rep stos %eax,%es:(%edi)
c00097c6:	c7 45 e0 0c 00 00 00 	movl   $0xc,-0x20(%ebp)
  uint32_t block_idx = 0, dir_entry_idx = 0;
c00097cd:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
c00097d4:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)

  while (block_idx < 12) {
c00097db:	eb 1a                	jmp    c00097f7 <dir_read+0x60>
    all_blocks[block_idx] = dir_inode->i_sectors[block_idx];
c00097dd:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c00097e0:	8b 55 f4             	mov    -0xc(%ebp),%edx
c00097e3:	83 c2 04             	add    $0x4,%edx
c00097e6:	8b 14 90             	mov    (%eax,%edx,4),%edx
c00097e9:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00097ec:	89 94 85 a8 fd ff ff 	mov    %edx,-0x258(%ebp,%eax,4)
    block_idx++;
c00097f3:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
  while (block_idx < 12) {
c00097f7:	83 7d f4 0b          	cmpl   $0xb,-0xc(%ebp)
c00097fb:	76 e0                	jbe    c00097dd <dir_read+0x46>
  }

  block_idx = 0;
c00097fd:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  uint32_t cur_dir_entry_pos = 0; // 当前目录项偏移,判断目录项是否之前已经返回过
c0009804:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%ebp)
  uint32_t dir_entry_size = cur_part->sb->dir_entry_size;
c000980b:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0009810:	8b 40 1c             	mov    0x1c(%eax),%eax
c0009813:	8b 40 30             	mov    0x30(%eax),%eax
c0009816:	89 45 dc             	mov    %eax,-0x24(%ebp)
  uint32_t dir_entrys_per_sec =
c0009819:	b8 00 02 00 00       	mov    $0x200,%eax
c000981e:	ba 00 00 00 00       	mov    $0x0,%edx
c0009823:	f7 75 dc             	divl   -0x24(%ebp)
c0009826:	89 45 d8             	mov    %eax,-0x28(%ebp)
      SECTOR_SIZE / dir_entry_size; // 一扇区内可容纳目录项个数

  // 在目录大小内遍历
  while (block_idx < block_cnt) {
c0009829:	e9 42 01 00 00       	jmp    c0009970 <dir_read+0x1d9>
    if (dir->dir_pos >= dir_inode->i_size) {
c000982e:	8b 45 08             	mov    0x8(%ebp),%eax
c0009831:	8b 50 04             	mov    0x4(%eax),%edx
c0009834:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0009837:	8b 40 04             	mov    0x4(%eax),%eax
c000983a:	39 c2                	cmp    %eax,%edx
c000983c:	72 0a                	jb     c0009848 <dir_read+0xb1>
      return NULL;
c000983e:	b8 00 00 00 00       	mov    $0x0,%eax
c0009843:	e9 39 01 00 00       	jmp    c0009981 <dir_read+0x1ea>
    }
    if (all_blocks[block_idx] == 0) { // 此块地址为0即空块，继续读出下一块
c0009848:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000984b:	8b 84 85 a8 fd ff ff 	mov    -0x258(%ebp,%eax,4),%eax
c0009852:	85 c0                	test   %eax,%eax
c0009854:	75 09                	jne    c000985f <dir_read+0xc8>
      block_idx++;
c0009856:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
      continue;
c000985a:	e9 11 01 00 00       	jmp    c0009970 <dir_read+0x1d9>
    }
    memset(dir_e, 0, SECTOR_SIZE);
c000985f:	83 ec 04             	sub    $0x4,%esp
c0009862:	68 00 02 00 00       	push   $0x200
c0009867:	6a 00                	push   $0x0
c0009869:	ff 75 e8             	push   -0x18(%ebp)
c000986c:	e8 3d 8b ff ff       	call   c00023ae <memset>
c0009871:	83 c4 10             	add    $0x10,%esp
    ide_read(cur_part->my_disk, all_blocks[block_idx], dir_e, 1);
c0009874:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0009877:	8b 94 85 a8 fd ff ff 	mov    -0x258(%ebp,%eax,4),%edx
c000987e:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0009883:	8b 40 08             	mov    0x8(%eax),%eax
c0009886:	6a 01                	push   $0x1
c0009888:	ff 75 e8             	push   -0x18(%ebp)
c000988b:	52                   	push   %edx
c000988c:	50                   	push   %eax
c000988d:	e8 99 c1 ff ff       	call   c0005a2b <ide_read>
c0009892:	83 c4 10             	add    $0x10,%esp
    dir_entry_idx = 0;
c0009895:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
    // 遍历块内所有目录项
    while (dir_entry_idx < dir_entrys_per_sec) {
c000989c:	e9 bf 00 00 00       	jmp    c0009960 <dir_read+0x1c9>
      if ((dir_e + dir_entry_idx)->f_type) { // 文件类型有效
c00098a1:	8b 55 f0             	mov    -0x10(%ebp),%edx
c00098a4:	89 d0                	mov    %edx,%eax
c00098a6:	01 c0                	add    %eax,%eax
c00098a8:	01 d0                	add    %edx,%eax
c00098aa:	c1 e0 03             	shl    $0x3,%eax
c00098ad:	89 c2                	mov    %eax,%edx
c00098af:	8b 45 e8             	mov    -0x18(%ebp),%eax
c00098b2:	01 d0                	add    %edx,%eax
c00098b4:	8b 40 14             	mov    0x14(%eax),%eax
c00098b7:	85 c0                	test   %eax,%eax
c00098b9:	0f 84 9d 00 00 00    	je     c000995c <dir_read+0x1c5>
        if (cur_dir_entry_pos < dir->dir_pos) { // 判断是不是最新的目录项
c00098bf:	8b 45 08             	mov    0x8(%ebp),%eax
c00098c2:	8b 40 04             	mov    0x4(%eax),%eax
c00098c5:	39 45 ec             	cmp    %eax,-0x14(%ebp)
c00098c8:	73 0f                	jae    c00098d9 <dir_read+0x142>
          // 是之前返回过的目录项
          cur_dir_entry_pos += dir_entry_size;
c00098ca:	8b 45 dc             	mov    -0x24(%ebp),%eax
c00098cd:	01 45 ec             	add    %eax,-0x14(%ebp)
          dir_entry_idx++;
c00098d0:	83 45 f0 01          	addl   $0x1,-0x10(%ebp)
          continue;
c00098d4:	e9 87 00 00 00       	jmp    c0009960 <dir_read+0x1c9>
        }
        ASSERT(cur_dir_entry_pos == dir->dir_pos); // 找到了要返回的目录项
c00098d9:	8b 45 08             	mov    0x8(%ebp),%eax
c00098dc:	8b 40 04             	mov    0x4(%eax),%eax
c00098df:	39 45 ec             	cmp    %eax,-0x14(%ebp)
c00098e2:	74 1c                	je     c0009900 <dir_read+0x169>
c00098e4:	68 b0 db 00 c0       	push   $0xc000dbb0
c00098e9:	68 60 dc 00 c0       	push   $0xc000dc60
c00098ee:	68 65 01 00 00       	push   $0x165
c00098f3:	68 c2 da 00 c0       	push   $0xc000dac2
c00098f8:	e8 db 89 ff ff       	call   c00022d8 <panic_spin>
c00098fd:	83 c4 10             	add    $0x10,%esp
        if (dir_inode->i_sectors[12] != 0) {       // 有一级间接块表
c0009900:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0009903:	8b 40 40             	mov    0x40(%eax),%eax
c0009906:	85 c0                	test   %eax,%eax
c0009908:	74 2c                	je     c0009936 <dir_read+0x19f>
          ide_read(cur_part->my_disk, dir_inode->i_sectors[12], all_blocks + 12,
c000990a:	8d 85 a8 fd ff ff    	lea    -0x258(%ebp),%eax
c0009910:	83 c0 30             	add    $0x30,%eax
c0009913:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c0009916:	8b 4a 40             	mov    0x40(%edx),%ecx
c0009919:	8b 15 d8 29 01 c0    	mov    0xc00129d8,%edx
c000991f:	8b 52 08             	mov    0x8(%edx),%edx
c0009922:	6a 01                	push   $0x1
c0009924:	50                   	push   %eax
c0009925:	51                   	push   %ecx
c0009926:	52                   	push   %edx
c0009927:	e8 ff c0 ff ff       	call   c0005a2b <ide_read>
c000992c:	83 c4 10             	add    $0x10,%esp
                   1);
          block_cnt = 140;
c000992f:	c7 45 e0 8c 00 00 00 	movl   $0x8c,-0x20(%ebp)
        }
        dir->dir_pos += dir_entry_size; // 更新位置为下个返回的目录项地址
c0009936:	8b 45 08             	mov    0x8(%ebp),%eax
c0009939:	8b 50 04             	mov    0x4(%eax),%edx
c000993c:	8b 45 dc             	mov    -0x24(%ebp),%eax
c000993f:	01 c2                	add    %eax,%edx
c0009941:	8b 45 08             	mov    0x8(%ebp),%eax
c0009944:	89 50 04             	mov    %edx,0x4(%eax)
        return dir_e + dir_entry_idx;
c0009947:	8b 55 f0             	mov    -0x10(%ebp),%edx
c000994a:	89 d0                	mov    %edx,%eax
c000994c:	01 c0                	add    %eax,%eax
c000994e:	01 d0                	add    %edx,%eax
c0009950:	c1 e0 03             	shl    $0x3,%eax
c0009953:	89 c2                	mov    %eax,%edx
c0009955:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0009958:	01 d0                	add    %edx,%eax
c000995a:	eb 25                	jmp    c0009981 <dir_read+0x1ea>
      }
      dir_entry_idx++;
c000995c:	83 45 f0 01          	addl   $0x1,-0x10(%ebp)
    while (dir_entry_idx < dir_entrys_per_sec) {
c0009960:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0009963:	3b 45 d8             	cmp    -0x28(%ebp),%eax
c0009966:	0f 82 35 ff ff ff    	jb     c00098a1 <dir_read+0x10a>
    }
    block_idx++;
c000996c:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
  while (block_idx < block_cnt) {
c0009970:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0009973:	3b 45 e0             	cmp    -0x20(%ebp),%eax
c0009976:	0f 82 b2 fe ff ff    	jb     c000982e <dir_read+0x97>
  }
  return NULL;
c000997c:	b8 00 00 00 00       	mov    $0x0,%eax
}
c0009981:	8b 7d fc             	mov    -0x4(%ebp),%edi
c0009984:	c9                   	leave  
c0009985:	c3                   	ret    

c0009986 <dir_is_empty>:

bool dir_is_empty(struct dir *dir) {
c0009986:	55                   	push   %ebp
c0009987:	89 e5                	mov    %esp,%ebp
c0009989:	83 ec 10             	sub    $0x10,%esp
  struct inode *dir_inode = dir->inode;
c000998c:	8b 45 08             	mov    0x8(%ebp),%eax
c000998f:	8b 00                	mov    (%eax),%eax
c0009991:	89 45 fc             	mov    %eax,-0x4(%ebp)
  // 若目录下只有.和..这两个目录项，则目录为空
  return (dir_inode->i_size == cur_part->sb->dir_entry_size * 2);
c0009994:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0009997:	8b 50 04             	mov    0x4(%eax),%edx
c000999a:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000999f:	8b 40 1c             	mov    0x1c(%eax),%eax
c00099a2:	8b 40 30             	mov    0x30(%eax),%eax
c00099a5:	01 c0                	add    %eax,%eax
c00099a7:	39 c2                	cmp    %eax,%edx
c00099a9:	0f 94 c0             	sete   %al
c00099ac:	0f b6 c0             	movzbl %al,%eax
}
c00099af:	c9                   	leave  
c00099b0:	c3                   	ret    

c00099b1 <dir_remove>:

// 在父目录中删除child_dir（child_dir要为空
int32_t dir_remove(struct dir *parent_dir, struct dir *child_dir) {
c00099b1:	55                   	push   %ebp
c00099b2:	89 e5                	mov    %esp,%ebp
c00099b4:	83 ec 18             	sub    $0x18,%esp
  struct inode *child_dir_inode = child_dir->inode;
c00099b7:	8b 45 0c             	mov    0xc(%ebp),%eax
c00099ba:	8b 00                	mov    (%eax),%eax
c00099bc:	89 45 f0             	mov    %eax,-0x10(%ebp)
  int32_t block_idx = 1;
c00099bf:	c7 45 f4 01 00 00 00 	movl   $0x1,-0xc(%ebp)
  while (block_idx < 13) {
c00099c6:	eb 30                	jmp    c00099f8 <dir_remove+0x47>
    // 空目录只在inode->i_sectors[0]中有扇区，其他扇区都应该为空
    ASSERT(child_dir_inode->i_sectors[block_idx] == 0);
c00099c8:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00099cb:	8b 55 f4             	mov    -0xc(%ebp),%edx
c00099ce:	83 c2 04             	add    $0x4,%edx
c00099d1:	8b 04 90             	mov    (%eax,%edx,4),%eax
c00099d4:	85 c0                	test   %eax,%eax
c00099d6:	74 1c                	je     c00099f4 <dir_remove+0x43>
c00099d8:	68 d4 db 00 c0       	push   $0xc000dbd4
c00099dd:	68 6c dc 00 c0       	push   $0xc000dc6c
c00099e2:	68 81 01 00 00       	push   $0x181
c00099e7:	68 c2 da 00 c0       	push   $0xc000dac2
c00099ec:	e8 e7 88 ff ff       	call   c00022d8 <panic_spin>
c00099f1:	83 c4 10             	add    $0x10,%esp
    block_idx++;
c00099f4:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
  while (block_idx < 13) {
c00099f8:	83 7d f4 0c          	cmpl   $0xc,-0xc(%ebp)
c00099fc:	7e ca                	jle    c00099c8 <dir_remove+0x17>
  }
  void *io_buf = sys_malloc(SECTOR_SIZE * 2);
c00099fe:	83 ec 0c             	sub    $0xc,%esp
c0009a01:	68 00 04 00 00       	push   $0x400
c0009a06:	e8 19 96 ff ff       	call   c0003024 <sys_malloc>
c0009a0b:	83 c4 10             	add    $0x10,%esp
c0009a0e:	89 45 ec             	mov    %eax,-0x14(%ebp)
  if (io_buf == NULL) {
c0009a11:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c0009a15:	75 17                	jne    c0009a2e <dir_remove+0x7d>
    printk("dir_remove: malloc for io_buf failed\n");
c0009a17:	83 ec 0c             	sub    $0xc,%esp
c0009a1a:	68 00 dc 00 c0       	push   $0xc000dc00
c0009a1f:	e8 90 bc ff ff       	call   c00056b4 <printk>
c0009a24:	83 c4 10             	add    $0x10,%esp
    return -1;
c0009a27:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c0009a2c:	eb 44                	jmp    c0009a72 <dir_remove+0xc1>
  }
  // 在父目录中删除子目录对应目录项
  delete_dir_entry(cur_part, parent_dir, child_dir_inode->i_no, io_buf);
c0009a2e:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0009a31:	8b 10                	mov    (%eax),%edx
c0009a33:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0009a38:	ff 75 ec             	push   -0x14(%ebp)
c0009a3b:	52                   	push   %edx
c0009a3c:	ff 75 08             	push   0x8(%ebp)
c0009a3f:	50                   	push   %eax
c0009a40:	e8 ea f8 ff ff       	call   c000932f <delete_dir_entry>
c0009a45:	83 c4 10             	add    $0x10,%esp
  // 回收inode中i_secotrs占用的扇区，并同步inode_bitmap和block_bitmap
  inode_release(cur_part, child_dir_inode->i_no);
c0009a48:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0009a4b:	8b 10                	mov    (%eax),%edx
c0009a4d:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0009a52:	83 ec 08             	sub    $0x8,%esp
c0009a55:	52                   	push   %edx
c0009a56:	50                   	push   %eax
c0009a57:	e8 fa ee ff ff       	call   c0008956 <inode_release>
c0009a5c:	83 c4 10             	add    $0x10,%esp
  sys_free(io_buf);
c0009a5f:	83 ec 0c             	sub    $0xc,%esp
c0009a62:	ff 75 ec             	push   -0x14(%ebp)
c0009a65:	e8 d9 9b ff ff       	call   c0003643 <sys_free>
c0009a6a:	83 c4 10             	add    $0x10,%esp
  return 0;
c0009a6d:	b8 00 00 00 00       	mov    $0x0,%eax
c0009a72:	c9                   	leave  
c0009a73:	c3                   	ret    

c0009a74 <get_free_slot_in_global>:
#include "thread.h"

struct file file_table[MAX_FILE_OPEN]; // 文件表（文件处于打开状态

// 从文件表中获取一个空闲位
int32_t get_free_slot_in_global(void) {
c0009a74:	55                   	push   %ebp
c0009a75:	89 e5                	mov    %esp,%ebp
c0009a77:	83 ec 18             	sub    $0x18,%esp
  uint32_t fd_idx = 3; // 跨过stdin,stdout,stderr
c0009a7a:	c7 45 f4 03 00 00 00 	movl   $0x3,-0xc(%ebp)

  while (fd_idx < MAX_FILE_OPEN) {
c0009a81:	eb 1b                	jmp    c0009a9e <get_free_slot_in_global+0x2a>
    if (file_table[fd_idx].fd_inode == NULL) {
c0009a83:	8b 55 f4             	mov    -0xc(%ebp),%edx
c0009a86:	89 d0                	mov    %edx,%eax
c0009a88:	01 c0                	add    %eax,%eax
c0009a8a:	01 d0                	add    %edx,%eax
c0009a8c:	c1 e0 02             	shl    $0x2,%eax
c0009a8f:	05 08 2c 01 c0       	add    $0xc0012c08,%eax
c0009a94:	8b 00                	mov    (%eax),%eax
c0009a96:	85 c0                	test   %eax,%eax
c0009a98:	74 0c                	je     c0009aa6 <get_free_slot_in_global+0x32>
      break;
    }
    fd_idx++;
c0009a9a:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
  while (fd_idx < MAX_FILE_OPEN) {
c0009a9e:	83 7d f4 1f          	cmpl   $0x1f,-0xc(%ebp)
c0009aa2:	76 df                	jbe    c0009a83 <get_free_slot_in_global+0xf>
c0009aa4:	eb 01                	jmp    c0009aa7 <get_free_slot_in_global+0x33>
      break;
c0009aa6:	90                   	nop
  }
  if (fd_idx == MAX_FILE_OPEN) {
c0009aa7:	83 7d f4 20          	cmpl   $0x20,-0xc(%ebp)
c0009aab:	75 17                	jne    c0009ac4 <get_free_slot_in_global+0x50>
    printk("exceed max open files\n");
c0009aad:	83 ec 0c             	sub    $0xc,%esp
c0009ab0:	68 78 dc 00 c0       	push   $0xc000dc78
c0009ab5:	e8 fa bb ff ff       	call   c00056b4 <printk>
c0009aba:	83 c4 10             	add    $0x10,%esp
    return -1;
c0009abd:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c0009ac2:	eb 03                	jmp    c0009ac7 <get_free_slot_in_global+0x53>
  }
  return fd_idx;
c0009ac4:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0009ac7:	c9                   	leave  
c0009ac8:	c3                   	ret    

c0009ac9 <pcb_fd_install>:

// 将全局描述符下标安装到进程/线程自己的文件描述符数组fd_table中
int32_t pcb_fd_install(int32_t global_fd_idx) {
c0009ac9:	55                   	push   %ebp
c0009aca:	89 e5                	mov    %esp,%ebp
c0009acc:	83 ec 18             	sub    $0x18,%esp
  struct task_struct *cur = running_thread();
c0009acf:	e8 3b a0 ff ff       	call   c0003b0f <running_thread>
c0009ad4:	89 45 f0             	mov    %eax,-0x10(%ebp)
  uint8_t local_fd_idx = 3; // 跨过stdin,stdout,stderr
c0009ad7:	c6 45 f7 03          	movb   $0x3,-0x9(%ebp)

  while (local_fd_idx < MAX_FILES_OPEN_PER_PROC) {
c0009adb:	eb 30                	jmp    c0009b0d <pcb_fd_install+0x44>
    if (cur->fd_table[local_fd_idx] == -1) { // -1表示free_slot，可用
c0009add:	0f b6 55 f7          	movzbl -0x9(%ebp),%edx
c0009ae1:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0009ae4:	83 c2 38             	add    $0x38,%edx
c0009ae7:	8b 44 90 0c          	mov    0xc(%eax,%edx,4),%eax
c0009aeb:	83 f8 ff             	cmp    $0xffffffff,%eax
c0009aee:	75 13                	jne    c0009b03 <pcb_fd_install+0x3a>
      cur->fd_table[local_fd_idx] = global_fd_idx;
c0009af0:	0f b6 55 f7          	movzbl -0x9(%ebp),%edx
c0009af4:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0009af7:	8d 4a 38             	lea    0x38(%edx),%ecx
c0009afa:	8b 55 08             	mov    0x8(%ebp),%edx
c0009afd:	89 54 88 0c          	mov    %edx,0xc(%eax,%ecx,4)
      break;
c0009b01:	eb 10                	jmp    c0009b13 <pcb_fd_install+0x4a>
    }
    local_fd_idx++;
c0009b03:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0009b07:	83 c0 01             	add    $0x1,%eax
c0009b0a:	88 45 f7             	mov    %al,-0x9(%ebp)
  while (local_fd_idx < MAX_FILES_OPEN_PER_PROC) {
c0009b0d:	80 7d f7 07          	cmpb   $0x7,-0x9(%ebp)
c0009b11:	76 ca                	jbe    c0009add <pcb_fd_install+0x14>
  }
  if (local_fd_idx == MAX_FILES_OPEN_PER_PROC) {
c0009b13:	80 7d f7 08          	cmpb   $0x8,-0x9(%ebp)
c0009b17:	75 17                	jne    c0009b30 <pcb_fd_install+0x67>
    printk("exceed max open files_per_proc\n");
c0009b19:	83 ec 0c             	sub    $0xc,%esp
c0009b1c:	68 90 dc 00 c0       	push   $0xc000dc90
c0009b21:	e8 8e bb ff ff       	call   c00056b4 <printk>
c0009b26:	83 c4 10             	add    $0x10,%esp
    return -1;
c0009b29:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c0009b2e:	eb 04                	jmp    c0009b34 <pcb_fd_install+0x6b>
  }
  return local_fd_idx; // 文件描述符（也就是下标）
c0009b30:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
}
c0009b34:	c9                   	leave  
c0009b35:	c3                   	ret    

c0009b36 <inode_bitmap_malloc>:

// 分配一个inode
int32_t inode_bitmap_malloc(struct partition *part) {
c0009b36:	55                   	push   %ebp
c0009b37:	89 e5                	mov    %esp,%ebp
c0009b39:	83 ec 18             	sub    $0x18,%esp
  int32_t bit_idx = bitmap_scan(&part->inode_bitmap, 1);
c0009b3c:	8b 45 08             	mov    0x8(%ebp),%eax
c0009b3f:	83 c0 28             	add    $0x28,%eax
c0009b42:	83 ec 08             	sub    $0x8,%esp
c0009b45:	6a 01                	push   $0x1
c0009b47:	50                   	push   %eax
c0009b48:	e8 91 8c ff ff       	call   c00027de <bitmap_scan>
c0009b4d:	83 c4 10             	add    $0x10,%esp
c0009b50:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (bit_idx == -1) {
c0009b53:	83 7d f4 ff          	cmpl   $0xffffffff,-0xc(%ebp)
c0009b57:	75 07                	jne    c0009b60 <inode_bitmap_malloc+0x2a>
    return -1;
c0009b59:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c0009b5e:	eb 1b                	jmp    c0009b7b <inode_bitmap_malloc+0x45>
  }
  bitmap_set(&part->inode_bitmap, bit_idx, 1);
c0009b60:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0009b63:	8b 55 08             	mov    0x8(%ebp),%edx
c0009b66:	83 c2 28             	add    $0x28,%edx
c0009b69:	83 ec 04             	sub    $0x4,%esp
c0009b6c:	6a 01                	push   $0x1
c0009b6e:	50                   	push   %eax
c0009b6f:	52                   	push   %edx
c0009b70:	e8 94 8d ff ff       	call   c0002909 <bitmap_set>
c0009b75:	83 c4 10             	add    $0x10,%esp
  return bit_idx;
c0009b78:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0009b7b:	c9                   	leave  
c0009b7c:	c3                   	ret    

c0009b7d <block_bitmap_malloc>:

// 分配一个扇区
int32_t block_bitmap_malloc(struct partition *part) {
c0009b7d:	55                   	push   %ebp
c0009b7e:	89 e5                	mov    %esp,%ebp
c0009b80:	83 ec 18             	sub    $0x18,%esp
  int32_t bit_idx = bitmap_scan(&part->inode_bitmap, 1);
c0009b83:	8b 45 08             	mov    0x8(%ebp),%eax
c0009b86:	83 c0 28             	add    $0x28,%eax
c0009b89:	83 ec 08             	sub    $0x8,%esp
c0009b8c:	6a 01                	push   $0x1
c0009b8e:	50                   	push   %eax
c0009b8f:	e8 4a 8c ff ff       	call   c00027de <bitmap_scan>
c0009b94:	83 c4 10             	add    $0x10,%esp
c0009b97:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (bit_idx == -1) {
c0009b9a:	83 7d f4 ff          	cmpl   $0xffffffff,-0xc(%ebp)
c0009b9e:	75 07                	jne    c0009ba7 <block_bitmap_malloc+0x2a>
    return -1;
c0009ba0:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c0009ba5:	eb 26                	jmp    c0009bcd <block_bitmap_malloc+0x50>
  }
  bitmap_set(&part->inode_bitmap, bit_idx, 1);
c0009ba7:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0009baa:	8b 55 08             	mov    0x8(%ebp),%edx
c0009bad:	83 c2 28             	add    $0x28,%edx
c0009bb0:	83 ec 04             	sub    $0x4,%esp
c0009bb3:	6a 01                	push   $0x1
c0009bb5:	50                   	push   %eax
c0009bb6:	52                   	push   %edx
c0009bb7:	e8 4d 8d ff ff       	call   c0002909 <bitmap_set>
c0009bbc:	83 c4 10             	add    $0x10,%esp
  return (part->sb->data_start_lba + bit_idx);
c0009bbf:	8b 45 08             	mov    0x8(%ebp),%eax
c0009bc2:	8b 40 1c             	mov    0x1c(%eax),%eax
c0009bc5:	8b 50 28             	mov    0x28(%eax),%edx
c0009bc8:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0009bcb:	01 d0                	add    %edx,%eax
}
c0009bcd:	c9                   	leave  
c0009bce:	c3                   	ret    

c0009bcf <bitmap_sync>:

// 将内存中bitmap第bit_idx位所在的512字节同步到硬盘
void bitmap_sync(struct partition *part, uint32_t bit_idx, uint8_t btmp) {
c0009bcf:	55                   	push   %ebp
c0009bd0:	89 e5                	mov    %esp,%ebp
c0009bd2:	83 ec 28             	sub    $0x28,%esp
c0009bd5:	8b 45 10             	mov    0x10(%ebp),%eax
c0009bd8:	88 45 e4             	mov    %al,-0x1c(%ebp)
  uint32_t off_sec = bit_idx / 4096;
c0009bdb:	8b 45 0c             	mov    0xc(%ebp),%eax
c0009bde:	c1 e8 0c             	shr    $0xc,%eax
c0009be1:	89 45 ec             	mov    %eax,-0x14(%ebp)
  uint32_t off_size = off_sec * BLOCK_SIZE;
c0009be4:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0009be7:	c1 e0 09             	shl    $0x9,%eax
c0009bea:	89 45 e8             	mov    %eax,-0x18(%ebp)
  uint32_t sec_lba;
  uint8_t *bitmap_off;

  // 需要被同步到硬盘的位图只有inode_bitmap和block_bitmap
  switch (btmp) {
c0009bed:	0f b6 45 e4          	movzbl -0x1c(%ebp),%eax
c0009bf1:	85 c0                	test   %eax,%eax
c0009bf3:	74 07                	je     c0009bfc <bitmap_sync+0x2d>
c0009bf5:	83 f8 01             	cmp    $0x1,%eax
c0009bf8:	74 23                	je     c0009c1d <bitmap_sync+0x4e>
c0009bfa:	eb 41                	jmp    c0009c3d <bitmap_sync+0x6e>
  case INODE_BITMAP:
    sec_lba = part->sb->inode_bitmap_lba + off_sec;
c0009bfc:	8b 45 08             	mov    0x8(%ebp),%eax
c0009bff:	8b 40 1c             	mov    0x1c(%eax),%eax
c0009c02:	8b 50 18             	mov    0x18(%eax),%edx
c0009c05:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0009c08:	01 d0                	add    %edx,%eax
c0009c0a:	89 45 f4             	mov    %eax,-0xc(%ebp)
    bitmap_off = part->inode_bitmap.bits + off_size;
c0009c0d:	8b 45 08             	mov    0x8(%ebp),%eax
c0009c10:	8b 50 2c             	mov    0x2c(%eax),%edx
c0009c13:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0009c16:	01 d0                	add    %edx,%eax
c0009c18:	89 45 f0             	mov    %eax,-0x10(%ebp)
    break;
c0009c1b:	eb 20                	jmp    c0009c3d <bitmap_sync+0x6e>

  case BLOCK_BITMAP:
    sec_lba = part->sb->block_bitmap_lba + off_sec;
c0009c1d:	8b 45 08             	mov    0x8(%ebp),%eax
c0009c20:	8b 40 1c             	mov    0x1c(%eax),%eax
c0009c23:	8b 50 10             	mov    0x10(%eax),%edx
c0009c26:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0009c29:	01 d0                	add    %edx,%eax
c0009c2b:	89 45 f4             	mov    %eax,-0xc(%ebp)
    bitmap_off = part->block_bitmap.bits + off_size;
c0009c2e:	8b 45 08             	mov    0x8(%ebp),%eax
c0009c31:	8b 50 24             	mov    0x24(%eax),%edx
c0009c34:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0009c37:	01 d0                	add    %edx,%eax
c0009c39:	89 45 f0             	mov    %eax,-0x10(%ebp)
    break;
c0009c3c:	90                   	nop
  }
  ide_write(part->my_disk, sec_lba, bitmap_off, 1);
c0009c3d:	8b 45 08             	mov    0x8(%ebp),%eax
c0009c40:	8b 40 08             	mov    0x8(%eax),%eax
c0009c43:	6a 01                	push   $0x1
c0009c45:	ff 75 f0             	push   -0x10(%ebp)
c0009c48:	ff 75 f4             	push   -0xc(%ebp)
c0009c4b:	50                   	push   %eax
c0009c4c:	e8 4e bf ff ff       	call   c0005b9f <ide_write>
c0009c51:	83 c4 10             	add    $0x10,%esp
}
c0009c54:	90                   	nop
c0009c55:	c9                   	leave  
c0009c56:	c3                   	ret    

c0009c57 <file_create>:

// 创建文件，成功返回文件描述符
int32_t file_create(struct dir *parent_dir, char *filename, uint8_t flag) {
c0009c57:	55                   	push   %ebp
c0009c58:	89 e5                	mov    %esp,%ebp
c0009c5a:	83 ec 48             	sub    $0x48,%esp
c0009c5d:	8b 45 10             	mov    0x10(%ebp),%eax
c0009c60:	88 45 c4             	mov    %al,-0x3c(%ebp)
  void *io_buf = sys_malloc(1024);
c0009c63:	83 ec 0c             	sub    $0xc,%esp
c0009c66:	68 00 04 00 00       	push   $0x400
c0009c6b:	e8 b4 93 ff ff       	call   c0003024 <sys_malloc>
c0009c70:	83 c4 10             	add    $0x10,%esp
c0009c73:	89 45 ec             	mov    %eax,-0x14(%ebp)
  if (io_buf == NULL) {
c0009c76:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c0009c7a:	75 1a                	jne    c0009c96 <file_create+0x3f>
    printk("in file_creat: sys_malloc for io_buf failed\n");
c0009c7c:	83 ec 0c             	sub    $0xc,%esp
c0009c7f:	68 b0 dc 00 c0       	push   $0xc000dcb0
c0009c84:	e8 2b ba ff ff       	call   c00056b4 <printk>
c0009c89:	83 c4 10             	add    $0x10,%esp
    return -1;
c0009c8c:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c0009c91:	e9 86 02 00 00       	jmp    c0009f1c <file_create+0x2c5>
  }
  uint8_t rollback_step = 0; // 用于操作失败时回滚各资源状态
c0009c96:	c6 45 f7 00          	movb   $0x0,-0x9(%ebp)

  int32_t inode_no = inode_bitmap_malloc(cur_part); // 分配inode
c0009c9a:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0009c9f:	83 ec 0c             	sub    $0xc,%esp
c0009ca2:	50                   	push   %eax
c0009ca3:	e8 8e fe ff ff       	call   c0009b36 <inode_bitmap_malloc>
c0009ca8:	83 c4 10             	add    $0x10,%esp
c0009cab:	89 45 e8             	mov    %eax,-0x18(%ebp)
  if (inode_no == -1) {
c0009cae:	83 7d e8 ff          	cmpl   $0xffffffff,-0x18(%ebp)
c0009cb2:	75 1a                	jne    c0009cce <file_create+0x77>
    printk("in file_creat: allocate inode failed\n");
c0009cb4:	83 ec 0c             	sub    $0xc,%esp
c0009cb7:	68 e0 dc 00 c0       	push   $0xc000dce0
c0009cbc:	e8 f3 b9 ff ff       	call   c00056b4 <printk>
c0009cc1:	83 c4 10             	add    $0x10,%esp
    return -1;
c0009cc4:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c0009cc9:	e9 4e 02 00 00       	jmp    c0009f1c <file_create+0x2c5>
  }

  struct inode *new_file_inode =
      (struct inode *)sys_malloc(sizeof(struct inode));
c0009cce:	83 ec 0c             	sub    $0xc,%esp
c0009cd1:	6a 4c                	push   $0x4c
c0009cd3:	e8 4c 93 ff ff       	call   c0003024 <sys_malloc>
c0009cd8:	83 c4 10             	add    $0x10,%esp
c0009cdb:	89 45 e4             	mov    %eax,-0x1c(%ebp)
  if (new_file_inode == NULL) {
c0009cde:	83 7d e4 00          	cmpl   $0x0,-0x1c(%ebp)
c0009ce2:	75 19                	jne    c0009cfd <file_create+0xa6>
    printk("file_create: sys_malloc for inode failded\n");
c0009ce4:	83 ec 0c             	sub    $0xc,%esp
c0009ce7:	68 08 dd 00 c0       	push   $0xc000dd08
c0009cec:	e8 c3 b9 ff ff       	call   c00056b4 <printk>
c0009cf1:	83 c4 10             	add    $0x10,%esp
    rollback_step = 1;
c0009cf4:	c6 45 f7 01          	movb   $0x1,-0x9(%ebp)
    goto rollback;
c0009cf8:	e9 a7 01 00 00       	jmp    c0009ea4 <file_create+0x24d>
  }
  inode_init(inode_no, new_file_inode);
c0009cfd:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0009d00:	83 ec 08             	sub    $0x8,%esp
c0009d03:	ff 75 e4             	push   -0x1c(%ebp)
c0009d06:	50                   	push   %eax
c0009d07:	e8 83 ee ff ff       	call   c0008b8f <inode_init>
c0009d0c:	83 c4 10             	add    $0x10,%esp

  int fd_idx = get_free_slot_in_global(); // file_table数组下标
c0009d0f:	e8 60 fd ff ff       	call   c0009a74 <get_free_slot_in_global>
c0009d14:	89 45 f0             	mov    %eax,-0x10(%ebp)
  if (fd_idx == -1) {
c0009d17:	83 7d f0 ff          	cmpl   $0xffffffff,-0x10(%ebp)
c0009d1b:	75 19                	jne    c0009d36 <file_create+0xdf>
    printk("exceed max open files\n");
c0009d1d:	83 ec 0c             	sub    $0xc,%esp
c0009d20:	68 78 dc 00 c0       	push   $0xc000dc78
c0009d25:	e8 8a b9 ff ff       	call   c00056b4 <printk>
c0009d2a:	83 c4 10             	add    $0x10,%esp
    rollback_step = 2;
c0009d2d:	c6 45 f7 02          	movb   $0x2,-0x9(%ebp)
    goto rollback;
c0009d31:	e9 6e 01 00 00       	jmp    c0009ea4 <file_create+0x24d>
  }

  file_table[fd_idx].fd_inode = new_file_inode;
c0009d36:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0009d39:	89 d0                	mov    %edx,%eax
c0009d3b:	01 c0                	add    %eax,%eax
c0009d3d:	01 d0                	add    %edx,%eax
c0009d3f:	c1 e0 02             	shl    $0x2,%eax
c0009d42:	8d 90 08 2c 01 c0    	lea    -0x3ffed3f8(%eax),%edx
c0009d48:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0009d4b:	89 02                	mov    %eax,(%edx)
  file_table[fd_idx].fd_pos = 0;
c0009d4d:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0009d50:	89 d0                	mov    %edx,%eax
c0009d52:	01 c0                	add    %eax,%eax
c0009d54:	01 d0                	add    %edx,%eax
c0009d56:	c1 e0 02             	shl    $0x2,%eax
c0009d59:	05 00 2c 01 c0       	add    $0xc0012c00,%eax
c0009d5e:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
  file_table[fd_idx].fd_flag = flag;
c0009d64:	0f b6 55 c4          	movzbl -0x3c(%ebp),%edx
c0009d68:	8b 4d f0             	mov    -0x10(%ebp),%ecx
c0009d6b:	89 c8                	mov    %ecx,%eax
c0009d6d:	01 c0                	add    %eax,%eax
c0009d6f:	01 c8                	add    %ecx,%eax
c0009d71:	c1 e0 02             	shl    $0x2,%eax
c0009d74:	05 04 2c 01 c0       	add    $0xc0012c04,%eax
c0009d79:	89 10                	mov    %edx,(%eax)
  file_table[fd_idx].fd_inode->write_deny = false;
c0009d7b:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0009d7e:	89 d0                	mov    %edx,%eax
c0009d80:	01 c0                	add    %eax,%eax
c0009d82:	01 d0                	add    %edx,%eax
c0009d84:	c1 e0 02             	shl    $0x2,%eax
c0009d87:	05 08 2c 01 c0       	add    $0xc0012c08,%eax
c0009d8c:	8b 00                	mov    (%eax),%eax
c0009d8e:	c7 40 0c 00 00 00 00 	movl   $0x0,0xc(%eax)

  struct dir_entry new_dir_entry;
  memset(&new_dir_entry, 0, sizeof(struct dir_entry));
c0009d95:	83 ec 04             	sub    $0x4,%esp
c0009d98:	6a 18                	push   $0x18
c0009d9a:	6a 00                	push   $0x0
c0009d9c:	8d 45 cc             	lea    -0x34(%ebp),%eax
c0009d9f:	50                   	push   %eax
c0009da0:	e8 09 86 ff ff       	call   c00023ae <memset>
c0009da5:	83 c4 10             	add    $0x10,%esp
  create_dir_entry(filename, inode_no, FT_REGULAR, &new_dir_entry);
c0009da8:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0009dab:	8d 55 cc             	lea    -0x34(%ebp),%edx
c0009dae:	52                   	push   %edx
c0009daf:	6a 01                	push   $0x1
c0009db1:	50                   	push   %eax
c0009db2:	ff 75 0c             	push   0xc(%ebp)
c0009db5:	e8 a5 f0 ff ff       	call   c0008e5f <create_dir_entry>
c0009dba:	83 c4 10             	add    $0x10,%esp

  /* 同步内存数据到磁盘 */
  // 1、在目录parent_dir下安装目录项new_dir_entry，写入磁盘后返回true
  if (!sync_dir_entry(parent_dir, &new_dir_entry, io_buf)) {
c0009dbd:	83 ec 04             	sub    $0x4,%esp
c0009dc0:	ff 75 ec             	push   -0x14(%ebp)
c0009dc3:	8d 45 cc             	lea    -0x34(%ebp),%eax
c0009dc6:	50                   	push   %eax
c0009dc7:	ff 75 08             	push   0x8(%ebp)
c0009dca:	e8 ff f0 ff ff       	call   c0008ece <sync_dir_entry>
c0009dcf:	83 c4 10             	add    $0x10,%esp
c0009dd2:	85 c0                	test   %eax,%eax
c0009dd4:	75 19                	jne    c0009def <file_create+0x198>
    printk("sync dir_entry to disk failed\n");
c0009dd6:	83 ec 0c             	sub    $0xc,%esp
c0009dd9:	68 34 dd 00 c0       	push   $0xc000dd34
c0009dde:	e8 d1 b8 ff ff       	call   c00056b4 <printk>
c0009de3:	83 c4 10             	add    $0x10,%esp
    rollback_step = 3;
c0009de6:	c6 45 f7 03          	movb   $0x3,-0x9(%ebp)
    goto rollback;
c0009dea:	e9 b5 00 00 00       	jmp    c0009ea4 <file_create+0x24d>
  }
  memset(io_buf, 0, 1024);
c0009def:	83 ec 04             	sub    $0x4,%esp
c0009df2:	68 00 04 00 00       	push   $0x400
c0009df7:	6a 00                	push   $0x0
c0009df9:	ff 75 ec             	push   -0x14(%ebp)
c0009dfc:	e8 ad 85 ff ff       	call   c00023ae <memset>
c0009e01:	83 c4 10             	add    $0x10,%esp
  // 2、将父目录inode的内容同步到磁盘
  inode_sync(cur_part, parent_dir->inode, io_buf);
c0009e04:	8b 45 08             	mov    0x8(%ebp),%eax
c0009e07:	8b 10                	mov    (%eax),%edx
c0009e09:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0009e0e:	83 ec 04             	sub    $0x4,%esp
c0009e11:	ff 75 ec             	push   -0x14(%ebp)
c0009e14:	52                   	push   %edx
c0009e15:	50                   	push   %eax
c0009e16:	e8 43 e7 ff ff       	call   c000855e <inode_sync>
c0009e1b:	83 c4 10             	add    $0x10,%esp
  memset(io_buf, 0, 1024);
c0009e1e:	83 ec 04             	sub    $0x4,%esp
c0009e21:	68 00 04 00 00       	push   $0x400
c0009e26:	6a 00                	push   $0x0
c0009e28:	ff 75 ec             	push   -0x14(%ebp)
c0009e2b:	e8 7e 85 ff ff       	call   c00023ae <memset>
c0009e30:	83 c4 10             	add    $0x10,%esp
  // 3、将新创建文件inode内容同步到磁盘
  inode_sync(cur_part, new_file_inode, io_buf);
c0009e33:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0009e38:	83 ec 04             	sub    $0x4,%esp
c0009e3b:	ff 75 ec             	push   -0x14(%ebp)
c0009e3e:	ff 75 e4             	push   -0x1c(%ebp)
c0009e41:	50                   	push   %eax
c0009e42:	e8 17 e7 ff ff       	call   c000855e <inode_sync>
c0009e47:	83 c4 10             	add    $0x10,%esp
  // 4、将inode_bitmap同步到磁盘
  bitmap_sync(cur_part, inode_no, INODE_BITMAP);
c0009e4a:	8b 55 e8             	mov    -0x18(%ebp),%edx
c0009e4d:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0009e52:	83 ec 04             	sub    $0x4,%esp
c0009e55:	6a 00                	push   $0x0
c0009e57:	52                   	push   %edx
c0009e58:	50                   	push   %eax
c0009e59:	e8 71 fd ff ff       	call   c0009bcf <bitmap_sync>
c0009e5e:	83 c4 10             	add    $0x10,%esp
  // 5、将创建的文件inode添加到open_inodes链表
  list_push(&cur_part->open_inodes, &new_file_inode->inode_tag);
c0009e61:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0009e64:	8d 50 44             	lea    0x44(%eax),%edx
c0009e67:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0009e6c:	83 c0 30             	add    $0x30,%eax
c0009e6f:	83 ec 08             	sub    $0x8,%esp
c0009e72:	52                   	push   %edx
c0009e73:	50                   	push   %eax
c0009e74:	e8 00 a4 ff ff       	call   c0004279 <list_push>
c0009e79:	83 c4 10             	add    $0x10,%esp
  new_file_inode->i_open_cnt = 1;
c0009e7c:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0009e7f:	c7 40 08 01 00 00 00 	movl   $0x1,0x8(%eax)

  sys_free(io_buf);
c0009e86:	83 ec 0c             	sub    $0xc,%esp
c0009e89:	ff 75 ec             	push   -0x14(%ebp)
c0009e8c:	e8 b2 97 ff ff       	call   c0003643 <sys_free>
c0009e91:	83 c4 10             	add    $0x10,%esp
  return pcb_fd_install(fd_idx); // 返回文件描述符
c0009e94:	83 ec 0c             	sub    $0xc,%esp
c0009e97:	ff 75 f0             	push   -0x10(%ebp)
c0009e9a:	e8 2a fc ff ff       	call   c0009ac9 <pcb_fd_install>
c0009e9f:	83 c4 10             	add    $0x10,%esp
c0009ea2:	eb 78                	jmp    c0009f1c <file_create+0x2c5>

// 回滚资源操作
rollback:
  switch (rollback_step) {
c0009ea4:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
c0009ea8:	83 f8 03             	cmp    $0x3,%eax
c0009eab:	74 11                	je     c0009ebe <file_create+0x267>
c0009ead:	83 f8 03             	cmp    $0x3,%eax
c0009eb0:	7f 57                	jg     c0009f09 <file_create+0x2b2>
c0009eb2:	83 f8 01             	cmp    $0x1,%eax
c0009eb5:	74 36                	je     c0009eed <file_create+0x296>
c0009eb7:	83 f8 02             	cmp    $0x2,%eax
c0009eba:	74 23                	je     c0009edf <file_create+0x288>
c0009ebc:	eb 4b                	jmp    c0009f09 <file_create+0x2b2>
  case 3:
    // 失败时，将file_table中相应位清空
    memset(&file_table[fd_idx], 0, sizeof(struct file));
c0009ebe:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0009ec1:	89 d0                	mov    %edx,%eax
c0009ec3:	01 c0                	add    %eax,%eax
c0009ec5:	01 d0                	add    %edx,%eax
c0009ec7:	c1 e0 02             	shl    $0x2,%eax
c0009eca:	05 00 2c 01 c0       	add    $0xc0012c00,%eax
c0009ecf:	83 ec 04             	sub    $0x4,%esp
c0009ed2:	6a 0c                	push   $0xc
c0009ed4:	6a 00                	push   $0x0
c0009ed6:	50                   	push   %eax
c0009ed7:	e8 d2 84 ff ff       	call   c00023ae <memset>
c0009edc:	83 c4 10             	add    $0x10,%esp
  case 2:
    sys_free(new_file_inode);
c0009edf:	83 ec 0c             	sub    $0xc,%esp
c0009ee2:	ff 75 e4             	push   -0x1c(%ebp)
c0009ee5:	e8 59 97 ff ff       	call   c0003643 <sys_free>
c0009eea:	83 c4 10             	add    $0x10,%esp
  case 1:
    // 如果新文件inode创建失败，之前位图中分配的inode_no也要恢复
    bitmap_set(&cur_part->inode_bitmap, inode_no, 0);
c0009eed:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0009ef0:	8b 15 d8 29 01 c0    	mov    0xc00129d8,%edx
c0009ef6:	83 c2 28             	add    $0x28,%edx
c0009ef9:	83 ec 04             	sub    $0x4,%esp
c0009efc:	6a 00                	push   $0x0
c0009efe:	50                   	push   %eax
c0009eff:	52                   	push   %edx
c0009f00:	e8 04 8a ff ff       	call   c0002909 <bitmap_set>
c0009f05:	83 c4 10             	add    $0x10,%esp
    break;
c0009f08:	90                   	nop
  }
  sys_free(io_buf);
c0009f09:	83 ec 0c             	sub    $0xc,%esp
c0009f0c:	ff 75 ec             	push   -0x14(%ebp)
c0009f0f:	e8 2f 97 ff ff       	call   c0003643 <sys_free>
c0009f14:	83 c4 10             	add    $0x10,%esp
  return -1;
c0009f17:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
}
c0009f1c:	c9                   	leave  
c0009f1d:	c3                   	ret    

c0009f1e <file_open>:

// 打开编号为inode_no的inode对应文件，成功返回文件描述符
int32_t file_open(uint32_t inode_no, uint8_t flag) {
c0009f1e:	55                   	push   %ebp
c0009f1f:	89 e5                	mov    %esp,%ebp
c0009f21:	83 ec 28             	sub    $0x28,%esp
c0009f24:	8b 45 0c             	mov    0xc(%ebp),%eax
c0009f27:	88 45 e4             	mov    %al,-0x1c(%ebp)
  int fd_idx = get_free_slot_in_global();
c0009f2a:	e8 45 fb ff ff       	call   c0009a74 <get_free_slot_in_global>
c0009f2f:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (fd_idx == -1) {
c0009f32:	83 7d f4 ff          	cmpl   $0xffffffff,-0xc(%ebp)
c0009f36:	75 1a                	jne    c0009f52 <file_open+0x34>
    printk("exceed max open files\n");
c0009f38:	83 ec 0c             	sub    $0xc,%esp
c0009f3b:	68 78 dc 00 c0       	push   $0xc000dc78
c0009f40:	e8 6f b7 ff ff       	call   c00056b4 <printk>
c0009f45:	83 c4 10             	add    $0x10,%esp
    return -1;
c0009f48:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c0009f4d:	e9 e3 00 00 00       	jmp    c000a035 <file_open+0x117>
  }

  file_table[fd_idx].fd_inode = inode_open(cur_part, inode_no);
c0009f52:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c0009f57:	83 ec 08             	sub    $0x8,%esp
c0009f5a:	ff 75 08             	push   0x8(%ebp)
c0009f5d:	50                   	push   %eax
c0009f5e:	e8 22 e7 ff ff       	call   c0008685 <inode_open>
c0009f63:	83 c4 10             	add    $0x10,%esp
c0009f66:	89 c2                	mov    %eax,%edx
c0009f68:	8b 4d f4             	mov    -0xc(%ebp),%ecx
c0009f6b:	89 c8                	mov    %ecx,%eax
c0009f6d:	01 c0                	add    %eax,%eax
c0009f6f:	01 c8                	add    %ecx,%eax
c0009f71:	c1 e0 02             	shl    $0x2,%eax
c0009f74:	05 08 2c 01 c0       	add    $0xc0012c08,%eax
c0009f79:	89 10                	mov    %edx,(%eax)
  file_table[fd_idx].fd_pos = 0; // 每次打开文件要让文件内指针指向开头
c0009f7b:	8b 55 f4             	mov    -0xc(%ebp),%edx
c0009f7e:	89 d0                	mov    %edx,%eax
c0009f80:	01 c0                	add    %eax,%eax
c0009f82:	01 d0                	add    %edx,%eax
c0009f84:	c1 e0 02             	shl    $0x2,%eax
c0009f87:	05 00 2c 01 c0       	add    $0xc0012c00,%eax
c0009f8c:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
  file_table[fd_idx].fd_flag = flag;
c0009f92:	0f b6 55 e4          	movzbl -0x1c(%ebp),%edx
c0009f96:	8b 4d f4             	mov    -0xc(%ebp),%ecx
c0009f99:	89 c8                	mov    %ecx,%eax
c0009f9b:	01 c0                	add    %eax,%eax
c0009f9d:	01 c8                	add    %ecx,%eax
c0009f9f:	c1 e0 02             	shl    $0x2,%eax
c0009fa2:	05 04 2c 01 c0       	add    $0xc0012c04,%eax
c0009fa7:	89 10                	mov    %edx,(%eax)
  bool *write_deny = &file_table[fd_idx].fd_inode->write_deny; // 并行检查
c0009fa9:	8b 55 f4             	mov    -0xc(%ebp),%edx
c0009fac:	89 d0                	mov    %edx,%eax
c0009fae:	01 c0                	add    %eax,%eax
c0009fb0:	01 d0                	add    %edx,%eax
c0009fb2:	c1 e0 02             	shl    $0x2,%eax
c0009fb5:	05 08 2c 01 c0       	add    $0xc0012c08,%eax
c0009fba:	8b 00                	mov    (%eax),%eax
c0009fbc:	83 c0 0c             	add    $0xc,%eax
c0009fbf:	89 45 f0             	mov    %eax,-0x10(%ebp)

  if (flag & O_WRONLY || flag & O_RDWR) {
c0009fc2:	0f b6 45 e4          	movzbl -0x1c(%ebp),%eax
c0009fc6:	83 e0 01             	and    $0x1,%eax
c0009fc9:	85 c0                	test   %eax,%eax
c0009fcb:	75 0b                	jne    c0009fd8 <file_open+0xba>
c0009fcd:	0f b6 45 e4          	movzbl -0x1c(%ebp),%eax
c0009fd1:	83 e0 02             	and    $0x2,%eax
c0009fd4:	85 c0                	test   %eax,%eax
c0009fd6:	74 4f                	je     c000a027 <file_open+0x109>
    enum intr_status old_status = intr_disable(); // 进入临界区前先关中断
c0009fd8:	e8 60 79 ff ff       	call   c000193d <intr_disable>
c0009fdd:	89 45 ec             	mov    %eax,-0x14(%ebp)
    if (!(*write_deny)) {
c0009fe0:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0009fe3:	8b 00                	mov    (%eax),%eax
c0009fe5:	85 c0                	test   %eax,%eax
c0009fe7:	75 19                	jne    c000a002 <file_open+0xe4>
      *write_deny = true; // 当前没有其他进程写该文件，将其占用
c0009fe9:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0009fec:	c7 00 01 00 00 00    	movl   $0x1,(%eax)
      intr_set_status(old_status); // 恢复中断
c0009ff2:	83 ec 0c             	sub    $0xc,%esp
c0009ff5:	ff 75 ec             	push   -0x14(%ebp)
c0009ff8:	e8 86 79 ff ff       	call   c0001983 <intr_set_status>
c0009ffd:	83 c4 10             	add    $0x10,%esp
c000a000:	eb 25                	jmp    c000a027 <file_open+0x109>
    } else {
      intr_set_status(old_status);
c000a002:	83 ec 0c             	sub    $0xc,%esp
c000a005:	ff 75 ec             	push   -0x14(%ebp)
c000a008:	e8 76 79 ff ff       	call   c0001983 <intr_set_status>
c000a00d:	83 c4 10             	add    $0x10,%esp
      printk("file can't be write now, try again later\n");
c000a010:	83 ec 0c             	sub    $0xc,%esp
c000a013:	68 54 dd 00 c0       	push   $0xc000dd54
c000a018:	e8 97 b6 ff ff       	call   c00056b4 <printk>
c000a01d:	83 c4 10             	add    $0x10,%esp
      return -1;
c000a020:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000a025:	eb 0e                	jmp    c000a035 <file_open+0x117>
    }
  }
  // 读或创建文件，不用理write_deny，保持默认
  return pcb_fd_install(fd_idx);
c000a027:	83 ec 0c             	sub    $0xc,%esp
c000a02a:	ff 75 f4             	push   -0xc(%ebp)
c000a02d:	e8 97 fa ff ff       	call   c0009ac9 <pcb_fd_install>
c000a032:	83 c4 10             	add    $0x10,%esp
}
c000a035:	c9                   	leave  
c000a036:	c3                   	ret    

c000a037 <file_close>:

// 关闭文件
int32_t file_close(struct file *file) {
c000a037:	55                   	push   %ebp
c000a038:	89 e5                	mov    %esp,%ebp
c000a03a:	83 ec 08             	sub    $0x8,%esp
  if (file == NULL) {
c000a03d:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c000a041:	75 07                	jne    c000a04a <file_close+0x13>
    return -1;
c000a043:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000a048:	eb 2e                	jmp    c000a078 <file_close+0x41>
  }
  file->fd_inode->write_deny = false;
c000a04a:	8b 45 08             	mov    0x8(%ebp),%eax
c000a04d:	8b 40 08             	mov    0x8(%eax),%eax
c000a050:	c7 40 0c 00 00 00 00 	movl   $0x0,0xc(%eax)
  inode_close(file->fd_inode);
c000a057:	8b 45 08             	mov    0x8(%ebp),%eax
c000a05a:	8b 40 08             	mov    0x8(%eax),%eax
c000a05d:	83 ec 0c             	sub    $0xc,%esp
c000a060:	50                   	push   %eax
c000a061:	e8 62 e7 ff ff       	call   c00087c8 <inode_close>
c000a066:	83 c4 10             	add    $0x10,%esp
  file->fd_inode = NULL; // 使文件结构可用
c000a069:	8b 45 08             	mov    0x8(%ebp),%eax
c000a06c:	c7 40 08 00 00 00 00 	movl   $0x0,0x8(%eax)
  return 0;
c000a073:	b8 00 00 00 00       	mov    $0x0,%eax
}
c000a078:	c9                   	leave  
c000a079:	c3                   	ret    

c000a07a <file_write>:

// 把buf中count个字节写入file，成功返回写入字节数，失败返-1
int32_t file_write(struct file *file, const void *buf, uint32_t count) {
c000a07a:	55                   	push   %ebp
c000a07b:	89 e5                	mov    %esp,%ebp
c000a07d:	83 ec 58             	sub    $0x58,%esp
  // 文件支持的最大字节
  if ((file->fd_inode->i_size + count) > (BLOCK_SIZE * 140)) {
c000a080:	8b 45 08             	mov    0x8(%ebp),%eax
c000a083:	8b 40 08             	mov    0x8(%eax),%eax
c000a086:	8b 50 04             	mov    0x4(%eax),%edx
c000a089:	8b 45 10             	mov    0x10(%ebp),%eax
c000a08c:	01 d0                	add    %edx,%eax
c000a08e:	3d 00 18 01 00       	cmp    $0x11800,%eax
c000a093:	76 1a                	jbe    c000a0af <file_write+0x35>
    printk("exceed max file_size 71680 bytes, write file failed\n");
c000a095:	83 ec 0c             	sub    $0xc,%esp
c000a098:	68 80 dd 00 c0       	push   $0xc000dd80
c000a09d:	e8 12 b6 ff ff       	call   c00056b4 <printk>
c000a0a2:	83 c4 10             	add    $0x10,%esp
    return -1;
c000a0a5:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000a0aa:	e9 98 07 00 00       	jmp    c000a847 <file_write+0x7cd>
  }

  uint8_t *io_buf = sys_malloc(512);
c000a0af:	83 ec 0c             	sub    $0xc,%esp
c000a0b2:	68 00 02 00 00       	push   $0x200
c000a0b7:	e8 68 8f ff ff       	call   c0003024 <sys_malloc>
c000a0bc:	83 c4 10             	add    $0x10,%esp
c000a0bf:	89 45 e0             	mov    %eax,-0x20(%ebp)
  if (io_buf == NULL) {
c000a0c2:	83 7d e0 00          	cmpl   $0x0,-0x20(%ebp)
c000a0c6:	75 1a                	jne    c000a0e2 <file_write+0x68>
    printk("file_write: sys_malloc for io_buf failed\n");
c000a0c8:	83 ec 0c             	sub    $0xc,%esp
c000a0cb:	68 b8 dd 00 c0       	push   $0xc000ddb8
c000a0d0:	e8 df b5 ff ff       	call   c00056b4 <printk>
c000a0d5:	83 c4 10             	add    $0x10,%esp
    return -1;
c000a0d8:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000a0dd:	e9 65 07 00 00       	jmp    c000a847 <file_write+0x7cd>
  }

  // 记录文件所有块地址
  uint32_t *all_blocks = (uint32_t *)sys_malloc(BLOCK_SIZE + 48);
c000a0e2:	83 ec 0c             	sub    $0xc,%esp
c000a0e5:	68 30 02 00 00       	push   $0x230
c000a0ea:	e8 35 8f ff ff       	call   c0003024 <sys_malloc>
c000a0ef:	83 c4 10             	add    $0x10,%esp
c000a0f2:	89 45 dc             	mov    %eax,-0x24(%ebp)
  if (all_blocks == NULL) {
c000a0f5:	83 7d dc 00          	cmpl   $0x0,-0x24(%ebp)
c000a0f9:	75 1a                	jne    c000a115 <file_write+0x9b>
    printk("file_write: sys_malloc for all_blocks failed\n");
c000a0fb:	83 ec 0c             	sub    $0xc,%esp
c000a0fe:	68 e4 dd 00 c0       	push   $0xc000dde4
c000a103:	e8 ac b5 ff ff       	call   c00056b4 <printk>
c000a108:	83 c4 10             	add    $0x10,%esp
    return -1;
c000a10b:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000a110:	e9 32 07 00 00       	jmp    c000a847 <file_write+0x7cd>
  }

  const uint8_t *src = buf;   // 指向buf中待写入数据
c000a115:	8b 45 0c             	mov    0xc(%ebp),%eax
c000a118:	89 45 f4             	mov    %eax,-0xc(%ebp)
  uint32_t bytes_written = 0; // 已写入数据大小
c000a11b:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
  uint32_t size_left = count; // 未写入数据大小
c000a122:	8b 45 10             	mov    0x10(%ebp),%eax
c000a125:	89 45 ec             	mov    %eax,-0x14(%ebp)
  uint32_t block_idx;
  int32_t block_lba = -1;
c000a128:	c7 45 d8 ff ff ff ff 	movl   $0xffffffff,-0x28(%ebp)
  uint32_t block_bitmap_idx = 0;
c000a12f:	c7 45 d4 00 00 00 00 	movl   $0x0,-0x2c(%ebp)
  uint32_t sec_left_bytes;       // 扇区剩余字节量
  uint32_t chunk_size;           // 每次写入硬盘的数据块大小
  uint32_t indirect_block_table; // 一级间接表地址

  // 文件是否是第一次写
  if (file->fd_inode->i_sectors[0] == 0) {
c000a136:	8b 45 08             	mov    0x8(%ebp),%eax
c000a139:	8b 40 08             	mov    0x8(%eax),%eax
c000a13c:	8b 40 10             	mov    0x10(%eax),%eax
c000a13f:	85 c0                	test   %eax,%eax
c000a141:	0f 85 8d 00 00 00    	jne    c000a1d4 <file_write+0x15a>
    block_lba = block_bitmap_malloc(cur_part); // 先为其分配一个块
c000a147:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a14c:	83 ec 0c             	sub    $0xc,%esp
c000a14f:	50                   	push   %eax
c000a150:	e8 28 fa ff ff       	call   c0009b7d <block_bitmap_malloc>
c000a155:	83 c4 10             	add    $0x10,%esp
c000a158:	89 45 d8             	mov    %eax,-0x28(%ebp)
    if (block_lba == -1) {
c000a15b:	83 7d d8 ff          	cmpl   $0xffffffff,-0x28(%ebp)
c000a15f:	75 1a                	jne    c000a17b <file_write+0x101>
      printk("file_write: block_bitmap_alloc failed\n");
c000a161:	83 ec 0c             	sub    $0xc,%esp
c000a164:	68 14 de 00 c0       	push   $0xc000de14
c000a169:	e8 46 b5 ff ff       	call   c00056b4 <printk>
c000a16e:	83 c4 10             	add    $0x10,%esp
      return -1;
c000a171:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000a176:	e9 cc 06 00 00       	jmp    c000a847 <file_write+0x7cd>
    }
    file->fd_inode->i_sectors[0] = block_lba;
c000a17b:	8b 45 08             	mov    0x8(%ebp),%eax
c000a17e:	8b 40 08             	mov    0x8(%eax),%eax
c000a181:	8b 55 d8             	mov    -0x28(%ebp),%edx
c000a184:	89 50 10             	mov    %edx,0x10(%eax)

    // 每分配一个块就将位图同步磁盘
    block_bitmap_idx = block_lba - cur_part->sb->data_start_lba;
c000a187:	8b 55 d8             	mov    -0x28(%ebp),%edx
c000a18a:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a18f:	8b 40 1c             	mov    0x1c(%eax),%eax
c000a192:	8b 48 28             	mov    0x28(%eax),%ecx
c000a195:	89 d0                	mov    %edx,%eax
c000a197:	29 c8                	sub    %ecx,%eax
c000a199:	89 45 d4             	mov    %eax,-0x2c(%ebp)
    ASSERT(block_bitmap_idx != 0);
c000a19c:	83 7d d4 00          	cmpl   $0x0,-0x2c(%ebp)
c000a1a0:	75 1c                	jne    c000a1be <file_write+0x144>
c000a1a2:	68 3b de 00 c0       	push   $0xc000de3b
c000a1a7:	68 98 e0 00 c0       	push   $0xc000e098
c000a1ac:	68 04 01 00 00       	push   $0x104
c000a1b1:	68 51 de 00 c0       	push   $0xc000de51
c000a1b6:	e8 1d 81 ff ff       	call   c00022d8 <panic_spin>
c000a1bb:	83 c4 10             	add    $0x10,%esp
    bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
c000a1be:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a1c3:	83 ec 04             	sub    $0x4,%esp
c000a1c6:	6a 01                	push   $0x1
c000a1c8:	ff 75 d4             	push   -0x2c(%ebp)
c000a1cb:	50                   	push   %eax
c000a1cc:	e8 fe f9 ff ff       	call   c0009bcf <bitmap_sync>
c000a1d1:	83 c4 10             	add    $0x10,%esp
  }

  uint32_t file_has_used_blocks = // 写count个字节前该文件已占用的块数
      file->fd_inode->i_size / BLOCK_SIZE + 1;
c000a1d4:	8b 45 08             	mov    0x8(%ebp),%eax
c000a1d7:	8b 40 08             	mov    0x8(%eax),%eax
c000a1da:	8b 40 04             	mov    0x4(%eax),%eax
c000a1dd:	c1 e8 09             	shr    $0x9,%eax
  uint32_t file_has_used_blocks = // 写count个字节前该文件已占用的块数
c000a1e0:	83 c0 01             	add    $0x1,%eax
c000a1e3:	89 45 d0             	mov    %eax,-0x30(%ebp)
  uint32_t file_will_use_blocks = // 存count字节后该文件将占用的块数
      (file->fd_inode->i_size + count) / BLOCK_SIZE + 1;
c000a1e6:	8b 45 08             	mov    0x8(%ebp),%eax
c000a1e9:	8b 40 08             	mov    0x8(%eax),%eax
c000a1ec:	8b 50 04             	mov    0x4(%eax),%edx
c000a1ef:	8b 45 10             	mov    0x10(%ebp),%eax
c000a1f2:	01 d0                	add    %edx,%eax
c000a1f4:	c1 e8 09             	shr    $0x9,%eax
  uint32_t file_will_use_blocks = // 存count字节后该文件将占用的块数
c000a1f7:	83 c0 01             	add    $0x1,%eax
c000a1fa:	89 45 cc             	mov    %eax,-0x34(%ebp)
  ASSERT(file_will_use_blocks <= 140);
c000a1fd:	81 7d cc 8c 00 00 00 	cmpl   $0x8c,-0x34(%ebp)
c000a204:	76 1c                	jbe    c000a222 <file_write+0x1a8>
c000a206:	68 5b de 00 c0       	push   $0xc000de5b
c000a20b:	68 98 e0 00 c0       	push   $0xc000e098
c000a210:	68 0c 01 00 00       	push   $0x10c
c000a215:	68 51 de 00 c0       	push   $0xc000de51
c000a21a:	e8 b9 80 ff ff       	call   c00022d8 <panic_spin>
c000a21f:	83 c4 10             	add    $0x10,%esp
  uint32_t add_blocks = // 用来判断是否需要分配新扇区
c000a222:	8b 45 cc             	mov    -0x34(%ebp),%eax
c000a225:	2b 45 d0             	sub    -0x30(%ebp),%eax
c000a228:	89 45 c8             	mov    %eax,-0x38(%ebp)
      file_will_use_blocks - file_has_used_blocks;

  // 将写文件所用到的块地址收集到all_blocks
  if (add_blocks == 0) { // 无需分配新扇区
c000a22b:	83 7d c8 00          	cmpl   $0x0,-0x38(%ebp)
c000a22f:	0f 85 8b 00 00 00    	jne    c000a2c0 <file_write+0x246>
    if (file_will_use_blocks <= 12) {
c000a235:	83 7d cc 0c          	cmpl   $0xc,-0x34(%ebp)
c000a239:	77 2e                	ja     c000a269 <file_write+0x1ef>
      block_idx = file_has_used_blocks - 1; // 指向最后一个已有数据的扇区
c000a23b:	8b 45 d0             	mov    -0x30(%ebp),%eax
c000a23e:	83 e8 01             	sub    $0x1,%eax
c000a241:	89 45 e8             	mov    %eax,-0x18(%ebp)
      all_blocks[block_idx] = file->fd_inode->i_sectors[block_idx];
c000a244:	8b 45 08             	mov    0x8(%ebp),%eax
c000a247:	8b 40 08             	mov    0x8(%eax),%eax
c000a24a:	8b 55 e8             	mov    -0x18(%ebp),%edx
c000a24d:	8d 0c 95 00 00 00 00 	lea    0x0(,%edx,4),%ecx
c000a254:	8b 55 dc             	mov    -0x24(%ebp),%edx
c000a257:	01 ca                	add    %ecx,%edx
c000a259:	8b 4d e8             	mov    -0x18(%ebp),%ecx
c000a25c:	83 c1 04             	add    $0x4,%ecx
c000a25f:	8b 04 88             	mov    (%eax,%ecx,4),%eax
c000a262:	89 02                	mov    %eax,(%edx)
c000a264:	e9 75 04 00 00       	jmp    c000a6de <file_write+0x664>
    } else { // 写前已占了间接块-> 将间接块地址（i_sectors[12]）读进来
      ASSERT(file->fd_inode->i_sectors[12] != 0);
c000a269:	8b 45 08             	mov    0x8(%ebp),%eax
c000a26c:	8b 40 08             	mov    0x8(%eax),%eax
c000a26f:	8b 40 40             	mov    0x40(%eax),%eax
c000a272:	85 c0                	test   %eax,%eax
c000a274:	75 1c                	jne    c000a292 <file_write+0x218>
c000a276:	68 78 de 00 c0       	push   $0xc000de78
c000a27b:	68 98 e0 00 c0       	push   $0xc000e098
c000a280:	68 16 01 00 00       	push   $0x116
c000a285:	68 51 de 00 c0       	push   $0xc000de51
c000a28a:	e8 49 80 ff ff       	call   c00022d8 <panic_spin>
c000a28f:	83 c4 10             	add    $0x10,%esp
      indirect_block_table = file->fd_inode->i_sectors[12];
c000a292:	8b 45 08             	mov    0x8(%ebp),%eax
c000a295:	8b 40 08             	mov    0x8(%eax),%eax
c000a298:	8b 40 40             	mov    0x40(%eax),%eax
c000a29b:	89 45 c4             	mov    %eax,-0x3c(%ebp)
      ide_read(cur_part->my_disk, indirect_block_table, all_blocks + 12, 1);
c000a29e:	8b 45 dc             	mov    -0x24(%ebp),%eax
c000a2a1:	8d 50 30             	lea    0x30(%eax),%edx
c000a2a4:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a2a9:	8b 40 08             	mov    0x8(%eax),%eax
c000a2ac:	6a 01                	push   $0x1
c000a2ae:	52                   	push   %edx
c000a2af:	ff 75 c4             	push   -0x3c(%ebp)
c000a2b2:	50                   	push   %eax
c000a2b3:	e8 73 b7 ff ff       	call   c0005a2b <ide_read>
c000a2b8:	83 c4 10             	add    $0x10,%esp
c000a2bb:	e9 1e 04 00 00       	jmp    c000a6de <file_write+0x664>
    }
  } else { // 需要分配新扇区
    /* 1、12个直接块够用 */
    if (file_will_use_blocks <= 12) {
c000a2c0:	83 7d cc 0c          	cmpl   $0xc,-0x34(%ebp)
c000a2c4:	0f 87 2b 01 00 00    	ja     c000a3f5 <file_write+0x37b>
      // 先将有剩余空间的第一个可用块地址写入all_blocks
      block_idx = file_has_used_blocks - 1;
c000a2ca:	8b 45 d0             	mov    -0x30(%ebp),%eax
c000a2cd:	83 e8 01             	sub    $0x1,%eax
c000a2d0:	89 45 e8             	mov    %eax,-0x18(%ebp)
      ASSERT(file->fd_inode->i_sectors[block_idx] != 0);
c000a2d3:	8b 45 08             	mov    0x8(%ebp),%eax
c000a2d6:	8b 40 08             	mov    0x8(%eax),%eax
c000a2d9:	8b 55 e8             	mov    -0x18(%ebp),%edx
c000a2dc:	83 c2 04             	add    $0x4,%edx
c000a2df:	8b 04 90             	mov    (%eax,%edx,4),%eax
c000a2e2:	85 c0                	test   %eax,%eax
c000a2e4:	75 1c                	jne    c000a302 <file_write+0x288>
c000a2e6:	68 9c de 00 c0       	push   $0xc000de9c
c000a2eb:	68 98 e0 00 c0       	push   $0xc000e098
c000a2f0:	68 1f 01 00 00       	push   $0x11f
c000a2f5:	68 51 de 00 c0       	push   $0xc000de51
c000a2fa:	e8 d9 7f ff ff       	call   c00022d8 <panic_spin>
c000a2ff:	83 c4 10             	add    $0x10,%esp
      all_blocks[block_idx] = file->fd_inode->i_sectors[block_idx];
c000a302:	8b 45 08             	mov    0x8(%ebp),%eax
c000a305:	8b 40 08             	mov    0x8(%eax),%eax
c000a308:	8b 55 e8             	mov    -0x18(%ebp),%edx
c000a30b:	8d 0c 95 00 00 00 00 	lea    0x0(,%edx,4),%ecx
c000a312:	8b 55 dc             	mov    -0x24(%ebp),%edx
c000a315:	01 ca                	add    %ecx,%edx
c000a317:	8b 4d e8             	mov    -0x18(%ebp),%ecx
c000a31a:	83 c1 04             	add    $0x4,%ecx
c000a31d:	8b 04 88             	mov    (%eax,%ecx,4),%eax
c000a320:	89 02                	mov    %eax,(%edx)
      block_idx = file_has_used_blocks; // 指向第一个要分配的新块
c000a322:	8b 45 d0             	mov    -0x30(%ebp),%eax
c000a325:	89 45 e8             	mov    %eax,-0x18(%ebp)

      while (block_idx < file_will_use_blocks) {
c000a328:	e9 b7 00 00 00       	jmp    c000a3e4 <file_write+0x36a>
        // 除第一个块 后面占的整块再另外开辟
        block_lba = block_bitmap_malloc(cur_part);
c000a32d:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a332:	83 ec 0c             	sub    $0xc,%esp
c000a335:	50                   	push   %eax
c000a336:	e8 42 f8 ff ff       	call   c0009b7d <block_bitmap_malloc>
c000a33b:	83 c4 10             	add    $0x10,%esp
c000a33e:	89 45 d8             	mov    %eax,-0x28(%ebp)
        if (block_lba == -1) {
c000a341:	83 7d d8 ff          	cmpl   $0xffffffff,-0x28(%ebp)
c000a345:	75 1a                	jne    c000a361 <file_write+0x2e7>
          printk("file_write: block_bitmap_malloc for situation 1 failed\n");
c000a347:	83 ec 0c             	sub    $0xc,%esp
c000a34a:	68 c8 de 00 c0       	push   $0xc000dec8
c000a34f:	e8 60 b3 ff ff       	call   c00056b4 <printk>
c000a354:	83 c4 10             	add    $0x10,%esp
          return -1;
c000a357:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000a35c:	e9 e6 04 00 00       	jmp    c000a847 <file_write+0x7cd>
        }
        ASSERT(file->fd_inode->i_sectors[block_idx] == 0); // 确保未分配扇区地址
c000a361:	8b 45 08             	mov    0x8(%ebp),%eax
c000a364:	8b 40 08             	mov    0x8(%eax),%eax
c000a367:	8b 55 e8             	mov    -0x18(%ebp),%edx
c000a36a:	83 c2 04             	add    $0x4,%edx
c000a36d:	8b 04 90             	mov    (%eax,%edx,4),%eax
c000a370:	85 c0                	test   %eax,%eax
c000a372:	74 1c                	je     c000a390 <file_write+0x316>
c000a374:	68 00 df 00 c0       	push   $0xc000df00
c000a379:	68 98 e0 00 c0       	push   $0xc000e098
c000a37e:	68 2a 01 00 00       	push   $0x12a
c000a383:	68 51 de 00 c0       	push   $0xc000de51
c000a388:	e8 4b 7f ff ff       	call   c00022d8 <panic_spin>
c000a38d:	83 c4 10             	add    $0x10,%esp
        file->fd_inode->i_sectors[block_idx] = all_blocks[block_idx] =
c000a390:	8b 45 e8             	mov    -0x18(%ebp),%eax
c000a393:	8d 14 85 00 00 00 00 	lea    0x0(,%eax,4),%edx
c000a39a:	8b 45 dc             	mov    -0x24(%ebp),%eax
c000a39d:	01 d0                	add    %edx,%eax
c000a39f:	8b 55 d8             	mov    -0x28(%ebp),%edx
c000a3a2:	89 10                	mov    %edx,(%eax)
c000a3a4:	8b 55 08             	mov    0x8(%ebp),%edx
c000a3a7:	8b 52 08             	mov    0x8(%edx),%edx
c000a3aa:	8b 00                	mov    (%eax),%eax
c000a3ac:	8b 4d e8             	mov    -0x18(%ebp),%ecx
c000a3af:	83 c1 04             	add    $0x4,%ecx
c000a3b2:	89 04 8a             	mov    %eax,(%edx,%ecx,4)
            block_lba;
        // 每分配一个块就将位图同步到磁盘
        block_bitmap_idx = block_lba - cur_part->sb->data_start_lba;
c000a3b5:	8b 55 d8             	mov    -0x28(%ebp),%edx
c000a3b8:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a3bd:	8b 40 1c             	mov    0x1c(%eax),%eax
c000a3c0:	8b 48 28             	mov    0x28(%eax),%ecx
c000a3c3:	89 d0                	mov    %edx,%eax
c000a3c5:	29 c8                	sub    %ecx,%eax
c000a3c7:	89 45 d4             	mov    %eax,-0x2c(%ebp)
        bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
c000a3ca:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a3cf:	83 ec 04             	sub    $0x4,%esp
c000a3d2:	6a 01                	push   $0x1
c000a3d4:	ff 75 d4             	push   -0x2c(%ebp)
c000a3d7:	50                   	push   %eax
c000a3d8:	e8 f2 f7 ff ff       	call   c0009bcf <bitmap_sync>
c000a3dd:	83 c4 10             	add    $0x10,%esp
        block_idx++; // 下个新扇区
c000a3e0:	83 45 e8 01          	addl   $0x1,-0x18(%ebp)
      while (block_idx < file_will_use_blocks) {
c000a3e4:	8b 45 e8             	mov    -0x18(%ebp),%eax
c000a3e7:	3b 45 cc             	cmp    -0x34(%ebp),%eax
c000a3ea:	0f 82 3d ff ff ff    	jb     c000a32d <file_write+0x2b3>
c000a3f0:	e9 e9 02 00 00       	jmp    c000a6de <file_write+0x664>
      }
    } else if (file_has_used_blocks <= 12 && file_will_use_blocks > 12) {
c000a3f5:	83 7d d0 0c          	cmpl   $0xc,-0x30(%ebp)
c000a3f9:	0f 87 d9 01 00 00    	ja     c000a5d8 <file_write+0x55e>
c000a3ff:	83 7d cc 0c          	cmpl   $0xc,-0x34(%ebp)
c000a403:	0f 86 cf 01 00 00    	jbe    c000a5d8 <file_write+0x55e>
      /* 2、旧数据在12个直接块内，新数据将使用间接块*/
      block_idx = file_has_used_blocks - 1;
c000a409:	8b 45 d0             	mov    -0x30(%ebp),%eax
c000a40c:	83 e8 01             	sub    $0x1,%eax
c000a40f:	89 45 e8             	mov    %eax,-0x18(%ebp)
      all_blocks[block_idx] = file->fd_inode->i_sectors[block_idx];
c000a412:	8b 45 08             	mov    0x8(%ebp),%eax
c000a415:	8b 40 08             	mov    0x8(%eax),%eax
c000a418:	8b 55 e8             	mov    -0x18(%ebp),%edx
c000a41b:	8d 0c 95 00 00 00 00 	lea    0x0(,%edx,4),%ecx
c000a422:	8b 55 dc             	mov    -0x24(%ebp),%edx
c000a425:	01 ca                	add    %ecx,%edx
c000a427:	8b 4d e8             	mov    -0x18(%ebp),%ecx
c000a42a:	83 c1 04             	add    $0x4,%ecx
c000a42d:	8b 04 88             	mov    (%eax,%ecx,4),%eax
c000a430:	89 02                	mov    %eax,(%edx)
      block_lba = block_bitmap_malloc(cur_part); // 创建一级间接块表
c000a432:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a437:	83 ec 0c             	sub    $0xc,%esp
c000a43a:	50                   	push   %eax
c000a43b:	e8 3d f7 ff ff       	call   c0009b7d <block_bitmap_malloc>
c000a440:	83 c4 10             	add    $0x10,%esp
c000a443:	89 45 d8             	mov    %eax,-0x28(%ebp)
      if (block_lba == -1) {
c000a446:	83 7d d8 ff          	cmpl   $0xffffffff,-0x28(%ebp)
c000a44a:	75 1a                	jne    c000a466 <file_write+0x3ec>
        printk("file_write: block_bitmap_malloc for situation 2 failed\n");
c000a44c:	83 ec 0c             	sub    $0xc,%esp
c000a44f:	68 2c df 00 c0       	push   $0xc000df2c
c000a454:	e8 5b b2 ff ff       	call   c00056b4 <printk>
c000a459:	83 c4 10             	add    $0x10,%esp
        return -1;
c000a45c:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000a461:	e9 e1 03 00 00       	jmp    c000a847 <file_write+0x7cd>
      }
      block_bitmap_idx = block_lba - cur_part->sb->data_start_lba;
c000a466:	8b 55 d8             	mov    -0x28(%ebp),%edx
c000a469:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a46e:	8b 40 1c             	mov    0x1c(%eax),%eax
c000a471:	8b 48 28             	mov    0x28(%eax),%ecx
c000a474:	89 d0                	mov    %edx,%eax
c000a476:	29 c8                	sub    %ecx,%eax
c000a478:	89 45 d4             	mov    %eax,-0x2c(%ebp)
      bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
c000a47b:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a480:	83 ec 04             	sub    $0x4,%esp
c000a483:	6a 01                	push   $0x1
c000a485:	ff 75 d4             	push   -0x2c(%ebp)
c000a488:	50                   	push   %eax
c000a489:	e8 41 f7 ff ff       	call   c0009bcf <bitmap_sync>
c000a48e:	83 c4 10             	add    $0x10,%esp

      ASSERT(file->fd_inode->i_sectors[12] == 0); // 确保一级间接块表未分配
c000a491:	8b 45 08             	mov    0x8(%ebp),%eax
c000a494:	8b 40 08             	mov    0x8(%eax),%eax
c000a497:	8b 40 40             	mov    0x40(%eax),%eax
c000a49a:	85 c0                	test   %eax,%eax
c000a49c:	74 1c                	je     c000a4ba <file_write+0x440>
c000a49e:	68 64 df 00 c0       	push   $0xc000df64
c000a4a3:	68 98 e0 00 c0       	push   $0xc000e098
c000a4a8:	68 3e 01 00 00       	push   $0x13e
c000a4ad:	68 51 de 00 c0       	push   $0xc000de51
c000a4b2:	e8 21 7e ff ff       	call   c00022d8 <panic_spin>
c000a4b7:	83 c4 10             	add    $0x10,%esp
      // 分配一级间接块索引表
      indirect_block_table = file->fd_inode->i_sectors[12] = block_lba;
c000a4ba:	8b 45 08             	mov    0x8(%ebp),%eax
c000a4bd:	8b 40 08             	mov    0x8(%eax),%eax
c000a4c0:	8b 55 d8             	mov    -0x28(%ebp),%edx
c000a4c3:	89 50 40             	mov    %edx,0x40(%eax)
c000a4c6:	8b 40 40             	mov    0x40(%eax),%eax
c000a4c9:	89 45 c4             	mov    %eax,-0x3c(%ebp)
      block_idx = file_has_used_blocks;
c000a4cc:	8b 45 d0             	mov    -0x30(%ebp),%eax
c000a4cf:	89 45 e8             	mov    %eax,-0x18(%ebp)

      while (block_idx < file_will_use_blocks) {
c000a4d2:	e9 d3 00 00 00       	jmp    c000a5aa <file_write+0x530>
        block_lba = block_bitmap_malloc(cur_part);
c000a4d7:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a4dc:	83 ec 0c             	sub    $0xc,%esp
c000a4df:	50                   	push   %eax
c000a4e0:	e8 98 f6 ff ff       	call   c0009b7d <block_bitmap_malloc>
c000a4e5:	83 c4 10             	add    $0x10,%esp
c000a4e8:	89 45 d8             	mov    %eax,-0x28(%ebp)
        if (block_lba == -1) {
c000a4eb:	83 7d d8 ff          	cmpl   $0xffffffff,-0x28(%ebp)
c000a4ef:	75 1a                	jne    c000a50b <file_write+0x491>
          printk("file_write: block_bitmap_malloc for situation 2 failed\n");
c000a4f1:	83 ec 0c             	sub    $0xc,%esp
c000a4f4:	68 2c df 00 c0       	push   $0xc000df2c
c000a4f9:	e8 b6 b1 ff ff       	call   c00056b4 <printk>
c000a4fe:	83 c4 10             	add    $0x10,%esp
          return -1;
c000a501:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000a506:	e9 3c 03 00 00       	jmp    c000a847 <file_write+0x7cd>
        }
        if (block_idx < 12) {
c000a50b:	83 7d e8 0b          	cmpl   $0xb,-0x18(%ebp)
c000a50f:	77 56                	ja     c000a567 <file_write+0x4ed>
          ASSERT(file->fd_inode->i_sectors[block_idx] == 0);
c000a511:	8b 45 08             	mov    0x8(%ebp),%eax
c000a514:	8b 40 08             	mov    0x8(%eax),%eax
c000a517:	8b 55 e8             	mov    -0x18(%ebp),%edx
c000a51a:	83 c2 04             	add    $0x4,%edx
c000a51d:	8b 04 90             	mov    (%eax,%edx,4),%eax
c000a520:	85 c0                	test   %eax,%eax
c000a522:	74 1c                	je     c000a540 <file_write+0x4c6>
c000a524:	68 00 df 00 c0       	push   $0xc000df00
c000a529:	68 98 e0 00 c0       	push   $0xc000e098
c000a52e:	68 4a 01 00 00       	push   $0x14a
c000a533:	68 51 de 00 c0       	push   $0xc000de51
c000a538:	e8 9b 7d ff ff       	call   c00022d8 <panic_spin>
c000a53d:	83 c4 10             	add    $0x10,%esp
          file->fd_inode->i_sectors[block_idx] = all_blocks[block_idx] =
c000a540:	8b 45 e8             	mov    -0x18(%ebp),%eax
c000a543:	8d 14 85 00 00 00 00 	lea    0x0(,%eax,4),%edx
c000a54a:	8b 45 dc             	mov    -0x24(%ebp),%eax
c000a54d:	01 d0                	add    %edx,%eax
c000a54f:	8b 55 d8             	mov    -0x28(%ebp),%edx
c000a552:	89 10                	mov    %edx,(%eax)
c000a554:	8b 55 08             	mov    0x8(%ebp),%edx
c000a557:	8b 52 08             	mov    0x8(%edx),%edx
c000a55a:	8b 00                	mov    (%eax),%eax
c000a55c:	8b 4d e8             	mov    -0x18(%ebp),%ecx
c000a55f:	83 c1 04             	add    $0x4,%ecx
c000a562:	89 04 8a             	mov    %eax,(%edx,%ecx,4)
c000a565:	eb 14                	jmp    c000a57b <file_write+0x501>
              block_lba;
        } else {
          all_blocks[block_idx] = block_lba;
c000a567:	8b 45 e8             	mov    -0x18(%ebp),%eax
c000a56a:	8d 14 85 00 00 00 00 	lea    0x0(,%eax,4),%edx
c000a571:	8b 45 dc             	mov    -0x24(%ebp),%eax
c000a574:	01 c2                	add    %eax,%edx
c000a576:	8b 45 d8             	mov    -0x28(%ebp),%eax
c000a579:	89 02                	mov    %eax,(%edx)
        }
        block_bitmap_idx = block_lba - cur_part->sb->data_start_lba;
c000a57b:	8b 55 d8             	mov    -0x28(%ebp),%edx
c000a57e:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a583:	8b 40 1c             	mov    0x1c(%eax),%eax
c000a586:	8b 48 28             	mov    0x28(%eax),%ecx
c000a589:	89 d0                	mov    %edx,%eax
c000a58b:	29 c8                	sub    %ecx,%eax
c000a58d:	89 45 d4             	mov    %eax,-0x2c(%ebp)
        bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
c000a590:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a595:	83 ec 04             	sub    $0x4,%esp
c000a598:	6a 01                	push   $0x1
c000a59a:	ff 75 d4             	push   -0x2c(%ebp)
c000a59d:	50                   	push   %eax
c000a59e:	e8 2c f6 ff ff       	call   c0009bcf <bitmap_sync>
c000a5a3:	83 c4 10             	add    $0x10,%esp
        block_idx++; // 下个新扇区
c000a5a6:	83 45 e8 01          	addl   $0x1,-0x18(%ebp)
      while (block_idx < file_will_use_blocks) {
c000a5aa:	8b 45 e8             	mov    -0x18(%ebp),%eax
c000a5ad:	3b 45 cc             	cmp    -0x34(%ebp),%eax
c000a5b0:	0f 82 21 ff ff ff    	jb     c000a4d7 <file_write+0x45d>
      }
      // 同步一级间接块表到磁盘
      ide_write(cur_part->my_disk, indirect_block_table, all_blocks + 12, 1);
c000a5b6:	8b 45 dc             	mov    -0x24(%ebp),%eax
c000a5b9:	8d 50 30             	lea    0x30(%eax),%edx
c000a5bc:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a5c1:	8b 40 08             	mov    0x8(%eax),%eax
c000a5c4:	6a 01                	push   $0x1
c000a5c6:	52                   	push   %edx
c000a5c7:	ff 75 c4             	push   -0x3c(%ebp)
c000a5ca:	50                   	push   %eax
c000a5cb:	e8 cf b5 ff ff       	call   c0005b9f <ide_write>
c000a5d0:	83 c4 10             	add    $0x10,%esp
c000a5d3:	e9 06 01 00 00       	jmp    c000a6de <file_write+0x664>
    } else if (file_has_used_blocks > 12) {
c000a5d8:	83 7d d0 0c          	cmpl   $0xc,-0x30(%ebp)
c000a5dc:	0f 86 fc 00 00 00    	jbe    c000a6de <file_write+0x664>
      /* 3、占间接块 */
      ASSERT(file->fd_inode->i_sectors[12] != 0);
c000a5e2:	8b 45 08             	mov    0x8(%ebp),%eax
c000a5e5:	8b 40 08             	mov    0x8(%eax),%eax
c000a5e8:	8b 40 40             	mov    0x40(%eax),%eax
c000a5eb:	85 c0                	test   %eax,%eax
c000a5ed:	75 1c                	jne    c000a60b <file_write+0x591>
c000a5ef:	68 78 de 00 c0       	push   $0xc000de78
c000a5f4:	68 98 e0 00 c0       	push   $0xc000e098
c000a5f9:	68 58 01 00 00       	push   $0x158
c000a5fe:	68 51 de 00 c0       	push   $0xc000de51
c000a603:	e8 d0 7c ff ff       	call   c00022d8 <panic_spin>
c000a608:	83 c4 10             	add    $0x10,%esp
      indirect_block_table = file->fd_inode->i_sectors[12];
c000a60b:	8b 45 08             	mov    0x8(%ebp),%eax
c000a60e:	8b 40 08             	mov    0x8(%eax),%eax
c000a611:	8b 40 40             	mov    0x40(%eax),%eax
c000a614:	89 45 c4             	mov    %eax,-0x3c(%ebp)
      ide_read(cur_part->my_disk, indirect_block_table, all_blocks + 12, 1);
c000a617:	8b 45 dc             	mov    -0x24(%ebp),%eax
c000a61a:	8d 50 30             	lea    0x30(%eax),%edx
c000a61d:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a622:	8b 40 08             	mov    0x8(%eax),%eax
c000a625:	6a 01                	push   $0x1
c000a627:	52                   	push   %edx
c000a628:	ff 75 c4             	push   -0x3c(%ebp)
c000a62b:	50                   	push   %eax
c000a62c:	e8 fa b3 ff ff       	call   c0005a2b <ide_read>
c000a631:	83 c4 10             	add    $0x10,%esp
      block_idx = file_has_used_blocks; // 第一个未使用的间接块
c000a634:	8b 45 d0             	mov    -0x30(%ebp),%eax
c000a637:	89 45 e8             	mov    %eax,-0x18(%ebp)

      while (block_idx < file_will_use_blocks) {
c000a63a:	eb 79                	jmp    c000a6b5 <file_write+0x63b>
        block_lba = block_bitmap_malloc(cur_part);
c000a63c:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a641:	83 ec 0c             	sub    $0xc,%esp
c000a644:	50                   	push   %eax
c000a645:	e8 33 f5 ff ff       	call   c0009b7d <block_bitmap_malloc>
c000a64a:	83 c4 10             	add    $0x10,%esp
c000a64d:	89 45 d8             	mov    %eax,-0x28(%ebp)
        if (block_lba == -1) {
c000a650:	83 7d d8 ff          	cmpl   $0xffffffff,-0x28(%ebp)
c000a654:	75 1a                	jne    c000a670 <file_write+0x5f6>
          printk("file_write: block_bitmap_malloc for situation 3 failed\n");
c000a656:	83 ec 0c             	sub    $0xc,%esp
c000a659:	68 88 df 00 c0       	push   $0xc000df88
c000a65e:	e8 51 b0 ff ff       	call   c00056b4 <printk>
c000a663:	83 c4 10             	add    $0x10,%esp
          return -1;
c000a666:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000a66b:	e9 d7 01 00 00       	jmp    c000a847 <file_write+0x7cd>
        }
        all_blocks[block_idx++] = block_lba;
c000a670:	8b 45 e8             	mov    -0x18(%ebp),%eax
c000a673:	8d 50 01             	lea    0x1(%eax),%edx
c000a676:	89 55 e8             	mov    %edx,-0x18(%ebp)
c000a679:	8d 14 85 00 00 00 00 	lea    0x0(,%eax,4),%edx
c000a680:	8b 45 dc             	mov    -0x24(%ebp),%eax
c000a683:	01 c2                	add    %eax,%edx
c000a685:	8b 45 d8             	mov    -0x28(%ebp),%eax
c000a688:	89 02                	mov    %eax,(%edx)
        block_bitmap_idx = block_lba - cur_part->sb->data_start_lba;
c000a68a:	8b 55 d8             	mov    -0x28(%ebp),%edx
c000a68d:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a692:	8b 40 1c             	mov    0x1c(%eax),%eax
c000a695:	8b 48 28             	mov    0x28(%eax),%ecx
c000a698:	89 d0                	mov    %edx,%eax
c000a69a:	29 c8                	sub    %ecx,%eax
c000a69c:	89 45 d4             	mov    %eax,-0x2c(%ebp)
        bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
c000a69f:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a6a4:	83 ec 04             	sub    $0x4,%esp
c000a6a7:	6a 01                	push   $0x1
c000a6a9:	ff 75 d4             	push   -0x2c(%ebp)
c000a6ac:	50                   	push   %eax
c000a6ad:	e8 1d f5 ff ff       	call   c0009bcf <bitmap_sync>
c000a6b2:	83 c4 10             	add    $0x10,%esp
      while (block_idx < file_will_use_blocks) {
c000a6b5:	8b 45 e8             	mov    -0x18(%ebp),%eax
c000a6b8:	3b 45 cc             	cmp    -0x34(%ebp),%eax
c000a6bb:	0f 82 7b ff ff ff    	jb     c000a63c <file_write+0x5c2>
      }
      // 同步一级间接块表到磁盘
      ide_write(cur_part->my_disk, indirect_block_table, all_blocks + 12, 1);
c000a6c1:	8b 45 dc             	mov    -0x24(%ebp),%eax
c000a6c4:	8d 50 30             	lea    0x30(%eax),%edx
c000a6c7:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a6cc:	8b 40 08             	mov    0x8(%eax),%eax
c000a6cf:	6a 01                	push   $0x1
c000a6d1:	52                   	push   %edx
c000a6d2:	ff 75 c4             	push   -0x3c(%ebp)
c000a6d5:	50                   	push   %eax
c000a6d6:	e8 c4 b4 ff ff       	call   c0005b9f <ide_write>
c000a6db:	83 c4 10             	add    $0x10,%esp
    }
  }

  /* 用到的块地址已收集到all_blocks中，下面开始写数据 */
  bool first_write_block = true;
c000a6de:	c7 45 e4 01 00 00 00 	movl   $0x1,-0x1c(%ebp)
  file->fd_pos = file->fd_inode->i_size - 1;
c000a6e5:	8b 45 08             	mov    0x8(%ebp),%eax
c000a6e8:	8b 40 08             	mov    0x8(%eax),%eax
c000a6eb:	8b 40 04             	mov    0x4(%eax),%eax
c000a6ee:	8d 50 ff             	lea    -0x1(%eax),%edx
c000a6f1:	8b 45 08             	mov    0x8(%ebp),%eax
c000a6f4:	89 10                	mov    %edx,(%eax)
  while (bytes_written < count) {
c000a6f6:	e9 06 01 00 00       	jmp    c000a801 <file_write+0x787>
    memset(io_buf, 0, BLOCK_SIZE);
c000a6fb:	83 ec 04             	sub    $0x4,%esp
c000a6fe:	68 00 02 00 00       	push   $0x200
c000a703:	6a 00                	push   $0x0
c000a705:	ff 75 e0             	push   -0x20(%ebp)
c000a708:	e8 a1 7c ff ff       	call   c00023ae <memset>
c000a70d:	83 c4 10             	add    $0x10,%esp
    sec_idx = file->fd_inode->i_size / BLOCK_SIZE;
c000a710:	8b 45 08             	mov    0x8(%ebp),%eax
c000a713:	8b 40 08             	mov    0x8(%eax),%eax
c000a716:	8b 40 04             	mov    0x4(%eax),%eax
c000a719:	c1 e8 09             	shr    $0x9,%eax
c000a71c:	89 45 c0             	mov    %eax,-0x40(%ebp)
    sec_lba = all_blocks[sec_idx];
c000a71f:	8b 45 c0             	mov    -0x40(%ebp),%eax
c000a722:	8d 14 85 00 00 00 00 	lea    0x0(,%eax,4),%edx
c000a729:	8b 45 dc             	mov    -0x24(%ebp),%eax
c000a72c:	01 d0                	add    %edx,%eax
c000a72e:	8b 00                	mov    (%eax),%eax
c000a730:	89 45 bc             	mov    %eax,-0x44(%ebp)
    sec_off_bytes = file->fd_inode->i_size % BLOCK_SIZE;
c000a733:	8b 45 08             	mov    0x8(%ebp),%eax
c000a736:	8b 40 08             	mov    0x8(%eax),%eax
c000a739:	8b 40 04             	mov    0x4(%eax),%eax
c000a73c:	25 ff 01 00 00       	and    $0x1ff,%eax
c000a741:	89 45 b8             	mov    %eax,-0x48(%ebp)
    sec_left_bytes = BLOCK_SIZE - sec_off_bytes;
c000a744:	b8 00 02 00 00       	mov    $0x200,%eax
c000a749:	2b 45 b8             	sub    -0x48(%ebp),%eax
c000a74c:	89 45 b4             	mov    %eax,-0x4c(%ebp)
    /* 判断此次写入磁盘的数据大小 */
    chunk_size = size_left < sec_left_bytes ? size_left : sec_left_bytes;
c000a74f:	8b 55 b4             	mov    -0x4c(%ebp),%edx
c000a752:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000a755:	39 c2                	cmp    %eax,%edx
c000a757:	0f 46 c2             	cmovbe %edx,%eax
c000a75a:	89 45 b0             	mov    %eax,-0x50(%ebp)
    if (first_write_block) {
c000a75d:	83 7d e4 00          	cmpl   $0x0,-0x1c(%ebp)
c000a761:	74 20                	je     c000a783 <file_write+0x709>
      ide_read(cur_part->my_disk, sec_lba, io_buf, 1);
c000a763:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a768:	8b 40 08             	mov    0x8(%eax),%eax
c000a76b:	6a 01                	push   $0x1
c000a76d:	ff 75 e0             	push   -0x20(%ebp)
c000a770:	ff 75 bc             	push   -0x44(%ebp)
c000a773:	50                   	push   %eax
c000a774:	e8 b2 b2 ff ff       	call   c0005a2b <ide_read>
c000a779:	83 c4 10             	add    $0x10,%esp
      first_write_block = false;
c000a77c:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%ebp)
    }
    memcpy(io_buf + sec_off_bytes, src, chunk_size);
c000a783:	8b 55 e0             	mov    -0x20(%ebp),%edx
c000a786:	8b 45 b8             	mov    -0x48(%ebp),%eax
c000a789:	01 d0                	add    %edx,%eax
c000a78b:	83 ec 04             	sub    $0x4,%esp
c000a78e:	ff 75 b0             	push   -0x50(%ebp)
c000a791:	ff 75 f4             	push   -0xc(%ebp)
c000a794:	50                   	push   %eax
c000a795:	e8 67 7c ff ff       	call   c0002401 <memcpy>
c000a79a:	83 c4 10             	add    $0x10,%esp
    ide_write(cur_part->my_disk, sec_lba, io_buf, 1);
c000a79d:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a7a2:	8b 40 08             	mov    0x8(%eax),%eax
c000a7a5:	6a 01                	push   $0x1
c000a7a7:	ff 75 e0             	push   -0x20(%ebp)
c000a7aa:	ff 75 bc             	push   -0x44(%ebp)
c000a7ad:	50                   	push   %eax
c000a7ae:	e8 ec b3 ff ff       	call   c0005b9f <ide_write>
c000a7b3:	83 c4 10             	add    $0x10,%esp
    printk("file write at lba 0x%x\n", sec_lba); // 调试，完成后去掉
c000a7b6:	83 ec 08             	sub    $0x8,%esp
c000a7b9:	ff 75 bc             	push   -0x44(%ebp)
c000a7bc:	68 c0 df 00 c0       	push   $0xc000dfc0
c000a7c1:	e8 ee ae ff ff       	call   c00056b4 <printk>
c000a7c6:	83 c4 10             	add    $0x10,%esp
    src += chunk_size;                    // 指针推移到下个新数据
c000a7c9:	8b 45 b0             	mov    -0x50(%ebp),%eax
c000a7cc:	01 45 f4             	add    %eax,-0xc(%ebp)
    file->fd_inode->i_size += chunk_size; // 更新文件大小
c000a7cf:	8b 45 08             	mov    0x8(%ebp),%eax
c000a7d2:	8b 40 08             	mov    0x8(%eax),%eax
c000a7d5:	8b 48 04             	mov    0x4(%eax),%ecx
c000a7d8:	8b 45 08             	mov    0x8(%ebp),%eax
c000a7db:	8b 40 08             	mov    0x8(%eax),%eax
c000a7de:	8b 55 b0             	mov    -0x50(%ebp),%edx
c000a7e1:	01 ca                	add    %ecx,%edx
c000a7e3:	89 50 04             	mov    %edx,0x4(%eax)
    file->fd_pos += chunk_size;
c000a7e6:	8b 45 08             	mov    0x8(%ebp),%eax
c000a7e9:	8b 10                	mov    (%eax),%edx
c000a7eb:	8b 45 b0             	mov    -0x50(%ebp),%eax
c000a7ee:	01 c2                	add    %eax,%edx
c000a7f0:	8b 45 08             	mov    0x8(%ebp),%eax
c000a7f3:	89 10                	mov    %edx,(%eax)
    bytes_written += chunk_size;
c000a7f5:	8b 45 b0             	mov    -0x50(%ebp),%eax
c000a7f8:	01 45 f0             	add    %eax,-0x10(%ebp)
    size_left -= chunk_size;
c000a7fb:	8b 45 b0             	mov    -0x50(%ebp),%eax
c000a7fe:	29 45 ec             	sub    %eax,-0x14(%ebp)
  while (bytes_written < count) {
c000a801:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000a804:	3b 45 10             	cmp    0x10(%ebp),%eax
c000a807:	0f 82 ee fe ff ff    	jb     c000a6fb <file_write+0x681>
  }
  inode_sync(cur_part, file->fd_inode, io_buf);
c000a80d:	8b 45 08             	mov    0x8(%ebp),%eax
c000a810:	8b 50 08             	mov    0x8(%eax),%edx
c000a813:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a818:	83 ec 04             	sub    $0x4,%esp
c000a81b:	ff 75 e0             	push   -0x20(%ebp)
c000a81e:	52                   	push   %edx
c000a81f:	50                   	push   %eax
c000a820:	e8 39 dd ff ff       	call   c000855e <inode_sync>
c000a825:	83 c4 10             	add    $0x10,%esp
  sys_free(all_blocks);
c000a828:	83 ec 0c             	sub    $0xc,%esp
c000a82b:	ff 75 dc             	push   -0x24(%ebp)
c000a82e:	e8 10 8e ff ff       	call   c0003643 <sys_free>
c000a833:	83 c4 10             	add    $0x10,%esp
  sys_free(io_buf);
c000a836:	83 ec 0c             	sub    $0xc,%esp
c000a839:	ff 75 e0             	push   -0x20(%ebp)
c000a83c:	e8 02 8e ff ff       	call   c0003643 <sys_free>
c000a841:	83 c4 10             	add    $0x10,%esp
  return bytes_written;
c000a844:	8b 45 f0             	mov    -0x10(%ebp),%eax
}
c000a847:	c9                   	leave  
c000a848:	c3                   	ret    

c000a849 <file_read>:

// 从文件中读取count个字节写入buf，成功返回读出字节数
int32_t file_read(struct file *file, void *buf, uint32_t count) {
c000a849:	55                   	push   %ebp
c000a84a:	89 e5                	mov    %esp,%ebp
c000a84c:	83 ec 48             	sub    $0x48,%esp
  uint8_t *buf_dst = (uint8_t *)buf;
c000a84f:	8b 45 0c             	mov    0xc(%ebp),%eax
c000a852:	89 45 f4             	mov    %eax,-0xc(%ebp)
  uint32_t size = count, size_left = size;
c000a855:	8b 45 10             	mov    0x10(%ebp),%eax
c000a858:	89 45 f0             	mov    %eax,-0x10(%ebp)
c000a85b:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000a85e:	89 45 ec             	mov    %eax,-0x14(%ebp)

  // 要读取字节数超过了文件可读剩余量
  if ((file->fd_pos + count) > file->fd_inode->i_size) {
c000a861:	8b 45 08             	mov    0x8(%ebp),%eax
c000a864:	8b 10                	mov    (%eax),%edx
c000a866:	8b 45 10             	mov    0x10(%ebp),%eax
c000a869:	01 c2                	add    %eax,%edx
c000a86b:	8b 45 08             	mov    0x8(%ebp),%eax
c000a86e:	8b 40 08             	mov    0x8(%eax),%eax
c000a871:	8b 40 04             	mov    0x4(%eax),%eax
c000a874:	39 c2                	cmp    %eax,%edx
c000a876:	76 2b                	jbe    c000a8a3 <file_read+0x5a>
    size = file->fd_inode->i_size - file->fd_pos; // 用剩余量作为待读取字节数
c000a878:	8b 45 08             	mov    0x8(%ebp),%eax
c000a87b:	8b 40 08             	mov    0x8(%eax),%eax
c000a87e:	8b 50 04             	mov    0x4(%eax),%edx
c000a881:	8b 45 08             	mov    0x8(%ebp),%eax
c000a884:	8b 08                	mov    (%eax),%ecx
c000a886:	89 d0                	mov    %edx,%eax
c000a888:	29 c8                	sub    %ecx,%eax
c000a88a:	89 45 f0             	mov    %eax,-0x10(%ebp)
    size_left = size;
c000a88d:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000a890:	89 45 ec             	mov    %eax,-0x14(%ebp)
    if (size == 0) { // 到文件尾，返回-1
c000a893:	83 7d f0 00          	cmpl   $0x0,-0x10(%ebp)
c000a897:	75 0a                	jne    c000a8a3 <file_read+0x5a>
      return -1;
c000a899:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000a89e:	e9 4e 03 00 00       	jmp    c000abf1 <file_read+0x3a8>
    }
  }

  uint8_t *io_buf = sys_malloc(BLOCK_SIZE);
c000a8a3:	83 ec 0c             	sub    $0xc,%esp
c000a8a6:	68 00 02 00 00       	push   $0x200
c000a8ab:	e8 74 87 ff ff       	call   c0003024 <sys_malloc>
c000a8b0:	83 c4 10             	add    $0x10,%esp
c000a8b3:	89 45 e0             	mov    %eax,-0x20(%ebp)
  if (io_buf == NULL) {
c000a8b6:	83 7d e0 00          	cmpl   $0x0,-0x20(%ebp)
c000a8ba:	75 10                	jne    c000a8cc <file_read+0x83>
    printk("file_read: sys_malloc for io_buf failed\n");
c000a8bc:	83 ec 0c             	sub    $0xc,%esp
c000a8bf:	68 d8 df 00 c0       	push   $0xc000dfd8
c000a8c4:	e8 eb ad ff ff       	call   c00056b4 <printk>
c000a8c9:	83 c4 10             	add    $0x10,%esp
  }
  uint32_t *all_blocks = (uint32_t *)sys_malloc(BLOCK_SIZE + 48);
c000a8cc:	83 ec 0c             	sub    $0xc,%esp
c000a8cf:	68 30 02 00 00       	push   $0x230
c000a8d4:	e8 4b 87 ff ff       	call   c0003024 <sys_malloc>
c000a8d9:	83 c4 10             	add    $0x10,%esp
c000a8dc:	89 45 dc             	mov    %eax,-0x24(%ebp)
  if (all_blocks == NULL) {
c000a8df:	83 7d dc 00          	cmpl   $0x0,-0x24(%ebp)
c000a8e3:	75 1a                	jne    c000a8ff <file_read+0xb6>
    printk("file_read: sys_malloc for all_blocks failed\n");
c000a8e5:	83 ec 0c             	sub    $0xc,%esp
c000a8e8:	68 04 e0 00 c0       	push   $0xc000e004
c000a8ed:	e8 c2 ad ff ff       	call   c00056b4 <printk>
c000a8f2:	83 c4 10             	add    $0x10,%esp
    return -1;
c000a8f5:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000a8fa:	e9 f2 02 00 00       	jmp    c000abf1 <file_read+0x3a8>
  }

  uint32_t block_read_start_idx = // 数据所在块的起始地址
      file->fd_pos / BLOCK_SIZE;
c000a8ff:	8b 45 08             	mov    0x8(%ebp),%eax
c000a902:	8b 00                	mov    (%eax),%eax
  uint32_t block_read_start_idx = // 数据所在块的起始地址
c000a904:	c1 e8 09             	shr    $0x9,%eax
c000a907:	89 45 d8             	mov    %eax,-0x28(%ebp)
  uint32_t block_read_end_idx = // 数据所在块的终止地址
      (file->fd_pos + size) / BLOCK_SIZE;
c000a90a:	8b 45 08             	mov    0x8(%ebp),%eax
c000a90d:	8b 10                	mov    (%eax),%edx
c000a90f:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000a912:	01 d0                	add    %edx,%eax
  uint32_t block_read_end_idx = // 数据所在块的终止地址
c000a914:	c1 e8 09             	shr    $0x9,%eax
c000a917:	89 45 d4             	mov    %eax,-0x2c(%ebp)
  uint32_t read_blocks = // 增量为0表示数据在同一个块
c000a91a:	8b 45 d8             	mov    -0x28(%ebp),%eax
c000a91d:	2b 45 d4             	sub    -0x2c(%ebp),%eax
c000a920:	89 45 d0             	mov    %eax,-0x30(%ebp)
      block_read_start_idx - block_read_end_idx;
  ASSERT(block_read_start_idx < 139 && block_read_end_idx < 139);
c000a923:	81 7d d8 8a 00 00 00 	cmpl   $0x8a,-0x28(%ebp)
c000a92a:	77 09                	ja     c000a935 <file_read+0xec>
c000a92c:	81 7d d4 8a 00 00 00 	cmpl   $0x8a,-0x2c(%ebp)
c000a933:	76 1c                	jbe    c000a951 <file_read+0x108>
c000a935:	68 34 e0 00 c0       	push   $0xc000e034
c000a93a:	68 a4 e0 00 c0       	push   $0xc000e0a4
c000a93f:	68 a8 01 00 00       	push   $0x1a8
c000a944:	68 51 de 00 c0       	push   $0xc000de51
c000a949:	e8 8a 79 ff ff       	call   c00022d8 <panic_spin>
c000a94e:	83 c4 10             	add    $0x10,%esp

  int32_t indirect_block_table; // 一级间接表地址
  uint32_t block_idx;           // 待读的块地址

  /* 开始构建all_blocks块地址数组 */
  if (read_blocks == 0) { // 同个块
c000a951:	83 7d d0 00          	cmpl   $0x0,-0x30(%ebp)
c000a955:	0f 85 84 00 00 00    	jne    c000a9df <file_read+0x196>
    ASSERT(block_read_end_idx == block_read_start_idx);
c000a95b:	8b 45 d4             	mov    -0x2c(%ebp),%eax
c000a95e:	3b 45 d8             	cmp    -0x28(%ebp),%eax
c000a961:	74 1c                	je     c000a97f <file_read+0x136>
c000a963:	68 6c e0 00 c0       	push   $0xc000e06c
c000a968:	68 a4 e0 00 c0       	push   $0xc000e0a4
c000a96d:	68 af 01 00 00       	push   $0x1af
c000a972:	68 51 de 00 c0       	push   $0xc000de51
c000a977:	e8 5c 79 ff ff       	call   c00022d8 <panic_spin>
c000a97c:	83 c4 10             	add    $0x10,%esp
    if (block_read_end_idx < 12) { // 待读数据在12个直接块内
c000a97f:	83 7d d4 0b          	cmpl   $0xb,-0x2c(%ebp)
c000a983:	77 2b                	ja     c000a9b0 <file_read+0x167>
      block_idx = block_read_end_idx;
c000a985:	8b 45 d4             	mov    -0x2c(%ebp),%eax
c000a988:	89 45 e8             	mov    %eax,-0x18(%ebp)
      all_blocks[block_idx] = file->fd_inode->i_sectors[block_idx];
c000a98b:	8b 45 08             	mov    0x8(%ebp),%eax
c000a98e:	8b 40 08             	mov    0x8(%eax),%eax
c000a991:	8b 55 e8             	mov    -0x18(%ebp),%edx
c000a994:	8d 0c 95 00 00 00 00 	lea    0x0(,%edx,4),%ecx
c000a99b:	8b 55 dc             	mov    -0x24(%ebp),%edx
c000a99e:	01 ca                	add    %ecx,%edx
c000a9a0:	8b 4d e8             	mov    -0x18(%ebp),%ecx
c000a9a3:	83 c1 04             	add    $0x4,%ecx
c000a9a6:	8b 04 88             	mov    (%eax,%ecx,4),%eax
c000a9a9:	89 02                	mov    %eax,(%edx)
c000a9ab:	e9 5c 01 00 00       	jmp    c000ab0c <file_read+0x2c3>
    } else { // 用到一级间接块表，需将表中间接块读进来
      indirect_block_table = file->fd_inode->i_sectors[12];
c000a9b0:	8b 45 08             	mov    0x8(%ebp),%eax
c000a9b3:	8b 40 08             	mov    0x8(%eax),%eax
c000a9b6:	8b 40 40             	mov    0x40(%eax),%eax
c000a9b9:	89 45 cc             	mov    %eax,-0x34(%ebp)
      ide_read(cur_part->my_disk, indirect_block_table, all_blocks + 12, 1);
c000a9bc:	8b 45 dc             	mov    -0x24(%ebp),%eax
c000a9bf:	8d 48 30             	lea    0x30(%eax),%ecx
c000a9c2:	8b 55 cc             	mov    -0x34(%ebp),%edx
c000a9c5:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000a9ca:	8b 40 08             	mov    0x8(%eax),%eax
c000a9cd:	6a 01                	push   $0x1
c000a9cf:	51                   	push   %ecx
c000a9d0:	52                   	push   %edx
c000a9d1:	50                   	push   %eax
c000a9d2:	e8 54 b0 ff ff       	call   c0005a2b <ide_read>
c000a9d7:	83 c4 10             	add    $0x10,%esp
c000a9da:	e9 2d 01 00 00       	jmp    c000ab0c <file_read+0x2c3>
    }
  } else {                         // 读多个块
    if (block_read_end_idx < 12) { /* 1、起始块和终止块属于直接块 */
c000a9df:	83 7d d4 0b          	cmpl   $0xb,-0x2c(%ebp)
c000a9e3:	77 39                	ja     c000aa1e <file_read+0x1d5>
      block_idx = block_read_start_idx;
c000a9e5:	8b 45 d8             	mov    -0x28(%ebp),%eax
c000a9e8:	89 45 e8             	mov    %eax,-0x18(%ebp)
      while (block_idx <= block_read_end_idx) {
c000a9eb:	eb 24                	jmp    c000aa11 <file_read+0x1c8>
        all_blocks[block_idx] = file->fd_inode->i_sectors[block_idx];
c000a9ed:	8b 45 08             	mov    0x8(%ebp),%eax
c000a9f0:	8b 40 08             	mov    0x8(%eax),%eax
c000a9f3:	8b 55 e8             	mov    -0x18(%ebp),%edx
c000a9f6:	8d 0c 95 00 00 00 00 	lea    0x0(,%edx,4),%ecx
c000a9fd:	8b 55 dc             	mov    -0x24(%ebp),%edx
c000aa00:	01 ca                	add    %ecx,%edx
c000aa02:	8b 4d e8             	mov    -0x18(%ebp),%ecx
c000aa05:	83 c1 04             	add    $0x4,%ecx
c000aa08:	8b 04 88             	mov    (%eax,%ecx,4),%eax
c000aa0b:	89 02                	mov    %eax,(%edx)
        block_idx++;
c000aa0d:	83 45 e8 01          	addl   $0x1,-0x18(%ebp)
      while (block_idx <= block_read_end_idx) {
c000aa11:	8b 45 e8             	mov    -0x18(%ebp),%eax
c000aa14:	3b 45 d4             	cmp    -0x2c(%ebp),%eax
c000aa17:	76 d4                	jbe    c000a9ed <file_read+0x1a4>
c000aa19:	e9 ee 00 00 00       	jmp    c000ab0c <file_read+0x2c3>
      }
    } else /* 2、待读入数据跨越直接块和间接块 */
      if (block_read_start_idx < 12 && block_read_end_idx >= 12) {
c000aa1e:	83 7d d8 0b          	cmpl   $0xb,-0x28(%ebp)
c000aa22:	0f 87 91 00 00 00    	ja     c000aab9 <file_read+0x270>
c000aa28:	83 7d d4 0b          	cmpl   $0xb,-0x2c(%ebp)
c000aa2c:	0f 86 87 00 00 00    	jbe    c000aab9 <file_read+0x270>
        block_idx = block_read_start_idx;
c000aa32:	8b 45 d8             	mov    -0x28(%ebp),%eax
c000aa35:	89 45 e8             	mov    %eax,-0x18(%ebp)
        while (block_idx < 12) { // 先将直接块地址写入all_blocks
c000aa38:	eb 24                	jmp    c000aa5e <file_read+0x215>
          all_blocks[block_idx] = file->fd_inode->i_sectors[block_idx];
c000aa3a:	8b 45 08             	mov    0x8(%ebp),%eax
c000aa3d:	8b 40 08             	mov    0x8(%eax),%eax
c000aa40:	8b 55 e8             	mov    -0x18(%ebp),%edx
c000aa43:	8d 0c 95 00 00 00 00 	lea    0x0(,%edx,4),%ecx
c000aa4a:	8b 55 dc             	mov    -0x24(%ebp),%edx
c000aa4d:	01 ca                	add    %ecx,%edx
c000aa4f:	8b 4d e8             	mov    -0x18(%ebp),%ecx
c000aa52:	83 c1 04             	add    $0x4,%ecx
c000aa55:	8b 04 88             	mov    (%eax,%ecx,4),%eax
c000aa58:	89 02                	mov    %eax,(%edx)
          block_idx++;
c000aa5a:	83 45 e8 01          	addl   $0x1,-0x18(%ebp)
        while (block_idx < 12) { // 先将直接块地址写入all_blocks
c000aa5e:	83 7d e8 0b          	cmpl   $0xb,-0x18(%ebp)
c000aa62:	76 d6                	jbe    c000aa3a <file_read+0x1f1>
        }
        ASSERT(file->fd_inode->i_sectors[12] != 0);
c000aa64:	8b 45 08             	mov    0x8(%ebp),%eax
c000aa67:	8b 40 08             	mov    0x8(%eax),%eax
c000aa6a:	8b 40 40             	mov    0x40(%eax),%eax
c000aa6d:	85 c0                	test   %eax,%eax
c000aa6f:	75 1c                	jne    c000aa8d <file_read+0x244>
c000aa71:	68 78 de 00 c0       	push   $0xc000de78
c000aa76:	68 a4 e0 00 c0       	push   $0xc000e0a4
c000aa7b:	68 c5 01 00 00       	push   $0x1c5
c000aa80:	68 51 de 00 c0       	push   $0xc000de51
c000aa85:	e8 4e 78 ff ff       	call   c00022d8 <panic_spin>
c000aa8a:	83 c4 10             	add    $0x10,%esp
        indirect_block_table = file->fd_inode->i_sectors[12];
c000aa8d:	8b 45 08             	mov    0x8(%ebp),%eax
c000aa90:	8b 40 08             	mov    0x8(%eax),%eax
c000aa93:	8b 40 40             	mov    0x40(%eax),%eax
c000aa96:	89 45 cc             	mov    %eax,-0x34(%ebp)
        // 将一级间接块表读进来写入all_blocks第13个块位置之后
        ide_read(cur_part->my_disk, indirect_block_table, all_blocks + 12, 1);
c000aa99:	8b 45 dc             	mov    -0x24(%ebp),%eax
c000aa9c:	8d 48 30             	lea    0x30(%eax),%ecx
c000aa9f:	8b 55 cc             	mov    -0x34(%ebp),%edx
c000aaa2:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000aaa7:	8b 40 08             	mov    0x8(%eax),%eax
c000aaaa:	6a 01                	push   $0x1
c000aaac:	51                   	push   %ecx
c000aaad:	52                   	push   %edx
c000aaae:	50                   	push   %eax
c000aaaf:	e8 77 af ff ff       	call   c0005a2b <ide_read>
c000aab4:	83 c4 10             	add    $0x10,%esp
c000aab7:	eb 53                	jmp    c000ab0c <file_read+0x2c3>
      } else {
        /* 3、数据在间接块中 */
        ASSERT(file->fd_inode->i_sectors[12] != 0);
c000aab9:	8b 45 08             	mov    0x8(%ebp),%eax
c000aabc:	8b 40 08             	mov    0x8(%eax),%eax
c000aabf:	8b 40 40             	mov    0x40(%eax),%eax
c000aac2:	85 c0                	test   %eax,%eax
c000aac4:	75 1c                	jne    c000aae2 <file_read+0x299>
c000aac6:	68 78 de 00 c0       	push   $0xc000de78
c000aacb:	68 a4 e0 00 c0       	push   $0xc000e0a4
c000aad0:	68 cb 01 00 00       	push   $0x1cb
c000aad5:	68 51 de 00 c0       	push   $0xc000de51
c000aada:	e8 f9 77 ff ff       	call   c00022d8 <panic_spin>
c000aadf:	83 c4 10             	add    $0x10,%esp
        indirect_block_table = file->fd_inode->i_sectors[12];
c000aae2:	8b 45 08             	mov    0x8(%ebp),%eax
c000aae5:	8b 40 08             	mov    0x8(%eax),%eax
c000aae8:	8b 40 40             	mov    0x40(%eax),%eax
c000aaeb:	89 45 cc             	mov    %eax,-0x34(%ebp)
        ide_read(cur_part->my_disk, indirect_block_table, all_blocks + 12, 1);
c000aaee:	8b 45 dc             	mov    -0x24(%ebp),%eax
c000aaf1:	8d 48 30             	lea    0x30(%eax),%ecx
c000aaf4:	8b 55 cc             	mov    -0x34(%ebp),%edx
c000aaf7:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000aafc:	8b 40 08             	mov    0x8(%eax),%eax
c000aaff:	6a 01                	push   $0x1
c000ab01:	51                   	push   %ecx
c000ab02:	52                   	push   %edx
c000ab03:	50                   	push   %eax
c000ab04:	e8 22 af ff ff       	call   c0005a2b <ide_read>
c000ab09:	83 c4 10             	add    $0x10,%esp
      }
  }

  /* 用到的块地址已收集到all_blocks中，开始读数据 */
  uint32_t sec_idx, sec_lba, sec_off_bytes, sec_left_bytes, chunk_size;
  uint32_t bytes_read = 0;
c000ab0c:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%ebp)

  while (bytes_read < size) { // 读完为止
c000ab13:	e9 ae 00 00 00       	jmp    c000abc6 <file_read+0x37d>
    sec_idx = file->fd_pos / BLOCK_SIZE;
c000ab18:	8b 45 08             	mov    0x8(%ebp),%eax
c000ab1b:	8b 00                	mov    (%eax),%eax
c000ab1d:	c1 e8 09             	shr    $0x9,%eax
c000ab20:	89 45 c8             	mov    %eax,-0x38(%ebp)
    sec_lba = all_blocks[sec_idx];
c000ab23:	8b 45 c8             	mov    -0x38(%ebp),%eax
c000ab26:	8d 14 85 00 00 00 00 	lea    0x0(,%eax,4),%edx
c000ab2d:	8b 45 dc             	mov    -0x24(%ebp),%eax
c000ab30:	01 d0                	add    %edx,%eax
c000ab32:	8b 00                	mov    (%eax),%eax
c000ab34:	89 45 c4             	mov    %eax,-0x3c(%ebp)
    sec_off_bytes = file->fd_pos % BLOCK_SIZE;
c000ab37:	8b 45 08             	mov    0x8(%ebp),%eax
c000ab3a:	8b 00                	mov    (%eax),%eax
c000ab3c:	25 ff 01 00 00       	and    $0x1ff,%eax
c000ab41:	89 45 c0             	mov    %eax,-0x40(%ebp)
    sec_left_bytes = BLOCK_SIZE - sec_off_bytes;
c000ab44:	b8 00 02 00 00       	mov    $0x200,%eax
c000ab49:	2b 45 c0             	sub    -0x40(%ebp),%eax
c000ab4c:	89 45 bc             	mov    %eax,-0x44(%ebp)
    chunk_size = size_left < sec_left_bytes
c000ab4f:	8b 55 bc             	mov    -0x44(%ebp),%edx
c000ab52:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000ab55:	39 c2                	cmp    %eax,%edx
c000ab57:	0f 46 c2             	cmovbe %edx,%eax
c000ab5a:	89 45 b8             	mov    %eax,-0x48(%ebp)
                     ? size_left
                     : sec_left_bytes; // 待读入的数据大小
    memset(io_buf, 0, BLOCK_SIZE);
c000ab5d:	83 ec 04             	sub    $0x4,%esp
c000ab60:	68 00 02 00 00       	push   $0x200
c000ab65:	6a 00                	push   $0x0
c000ab67:	ff 75 e0             	push   -0x20(%ebp)
c000ab6a:	e8 3f 78 ff ff       	call   c00023ae <memset>
c000ab6f:	83 c4 10             	add    $0x10,%esp
    ide_read(cur_part->my_disk, sec_lba, io_buf, 1);
c000ab72:	a1 d8 29 01 c0       	mov    0xc00129d8,%eax
c000ab77:	8b 40 08             	mov    0x8(%eax),%eax
c000ab7a:	6a 01                	push   $0x1
c000ab7c:	ff 75 e0             	push   -0x20(%ebp)
c000ab7f:	ff 75 c4             	push   -0x3c(%ebp)
c000ab82:	50                   	push   %eax
c000ab83:	e8 a3 ae ff ff       	call   c0005a2b <ide_read>
c000ab88:	83 c4 10             	add    $0x10,%esp
    memcpy(buf_dst, io_buf + sec_off_bytes, chunk_size);
c000ab8b:	8b 55 e0             	mov    -0x20(%ebp),%edx
c000ab8e:	8b 45 c0             	mov    -0x40(%ebp),%eax
c000ab91:	01 d0                	add    %edx,%eax
c000ab93:	83 ec 04             	sub    $0x4,%esp
c000ab96:	ff 75 b8             	push   -0x48(%ebp)
c000ab99:	50                   	push   %eax
c000ab9a:	ff 75 f4             	push   -0xc(%ebp)
c000ab9d:	e8 5f 78 ff ff       	call   c0002401 <memcpy>
c000aba2:	83 c4 10             	add    $0x10,%esp

    buf_dst += chunk_size;
c000aba5:	8b 45 b8             	mov    -0x48(%ebp),%eax
c000aba8:	01 45 f4             	add    %eax,-0xc(%ebp)
    file->fd_pos += chunk_size;
c000abab:	8b 45 08             	mov    0x8(%ebp),%eax
c000abae:	8b 10                	mov    (%eax),%edx
c000abb0:	8b 45 b8             	mov    -0x48(%ebp),%eax
c000abb3:	01 c2                	add    %eax,%edx
c000abb5:	8b 45 08             	mov    0x8(%ebp),%eax
c000abb8:	89 10                	mov    %edx,(%eax)
    bytes_read += chunk_size;
c000abba:	8b 45 b8             	mov    -0x48(%ebp),%eax
c000abbd:	01 45 e4             	add    %eax,-0x1c(%ebp)
    size_left -= chunk_size;
c000abc0:	8b 45 b8             	mov    -0x48(%ebp),%eax
c000abc3:	29 45 ec             	sub    %eax,-0x14(%ebp)
  while (bytes_read < size) { // 读完为止
c000abc6:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c000abc9:	3b 45 f0             	cmp    -0x10(%ebp),%eax
c000abcc:	0f 82 46 ff ff ff    	jb     c000ab18 <file_read+0x2cf>
  }
  sys_free(all_blocks);
c000abd2:	83 ec 0c             	sub    $0xc,%esp
c000abd5:	ff 75 dc             	push   -0x24(%ebp)
c000abd8:	e8 66 8a ff ff       	call   c0003643 <sys_free>
c000abdd:	83 c4 10             	add    $0x10,%esp
  sys_free(io_buf);
c000abe0:	83 ec 0c             	sub    $0xc,%esp
c000abe3:	ff 75 e0             	push   -0x20(%ebp)
c000abe6:	e8 58 8a ff ff       	call   c0003643 <sys_free>
c000abeb:	83 c4 10             	add    $0x10,%esp
  return bytes_read;
c000abee:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c000abf1:	c9                   	leave  
c000abf2:	c3                   	ret    

c000abf3 <copy_pcb_vaddrbitmap_stack0>:

extern void intr_exit(void);

// 将父进程pcb和虚拟地址位图拷贝给子进程
static int32_t copy_pcb_vaddrbitmap_stack0(struct task_struct *child_thread,
                                           struct task_struct *parent_thread) {
c000abf3:	55                   	push   %ebp
c000abf4:	89 e5                	mov    %esp,%ebp
c000abf6:	83 ec 18             	sub    $0x18,%esp
  // 1、复制pcb所在页，再单独修改
  memcpy(child_thread, parent_thread, PG_SIZE);
c000abf9:	83 ec 04             	sub    $0x4,%esp
c000abfc:	68 00 10 00 00       	push   $0x1000
c000ac01:	ff 75 0c             	push   0xc(%ebp)
c000ac04:	ff 75 08             	push   0x8(%ebp)
c000ac07:	e8 f5 77 ff ff       	call   c0002401 <memcpy>
c000ac0c:	83 c4 10             	add    $0x10,%esp
  child_thread->pid = fork_pid();
c000ac0f:	e8 57 95 ff ff       	call   c000416b <fork_pid>
c000ac14:	8b 55 08             	mov    0x8(%ebp),%edx
c000ac17:	66 89 42 04          	mov    %ax,0x4(%edx)
  child_thread->elapsed_ticks = 0;
c000ac1b:	8b 45 08             	mov    0x8(%ebp),%eax
c000ac1e:	c7 40 20 00 00 00 00 	movl   $0x0,0x20(%eax)
  child_thread->status = TASK_READY;
c000ac25:	8b 45 08             	mov    0x8(%ebp),%eax
c000ac28:	c7 40 08 01 00 00 00 	movl   $0x1,0x8(%eax)
  child_thread->ticks = child_thread->priority; // 把新进程时间片充满
c000ac2f:	8b 45 08             	mov    0x8(%ebp),%eax
c000ac32:	0f b6 50 1c          	movzbl 0x1c(%eax),%edx
c000ac36:	8b 45 08             	mov    0x8(%ebp),%eax
c000ac39:	88 50 1d             	mov    %dl,0x1d(%eax)
  child_thread->parent_pid = parent_thread->pid;
c000ac3c:	8b 45 0c             	mov    0xc(%ebp),%eax
c000ac3f:	0f b7 50 04          	movzwl 0x4(%eax),%edx
c000ac43:	8b 45 08             	mov    0x8(%ebp),%eax
c000ac46:	66 89 90 10 01 00 00 	mov    %dx,0x110(%eax)
  child_thread->general_tag.next = child_thread->general_tag.prev = NULL;
c000ac4d:	8b 45 08             	mov    0x8(%ebp),%eax
c000ac50:	c7 40 24 00 00 00 00 	movl   $0x0,0x24(%eax)
c000ac57:	8b 45 08             	mov    0x8(%ebp),%eax
c000ac5a:	8b 50 24             	mov    0x24(%eax),%edx
c000ac5d:	8b 45 08             	mov    0x8(%ebp),%eax
c000ac60:	89 50 28             	mov    %edx,0x28(%eax)
  child_thread->all_list_tag.next = child_thread->all_list_tag.prev = NULL;
c000ac63:	8b 45 08             	mov    0x8(%ebp),%eax
c000ac66:	c7 40 2c 00 00 00 00 	movl   $0x0,0x2c(%eax)
c000ac6d:	8b 45 08             	mov    0x8(%ebp),%eax
c000ac70:	8b 50 2c             	mov    0x2c(%eax),%edx
c000ac73:	8b 45 08             	mov    0x8(%ebp),%eax
c000ac76:	89 50 30             	mov    %edx,0x30(%eax)
  block_desc_init(child_thread->u_block_desc);
c000ac79:	8b 45 08             	mov    0x8(%ebp),%eax
c000ac7c:	83 c0 44             	add    $0x44,%eax
c000ac7f:	83 ec 0c             	sub    $0xc,%esp
c000ac82:	50                   	push   %eax
c000ac83:	e8 a1 8d ff ff       	call   c0003a29 <block_desc_init>
c000ac88:	83 c4 10             	add    $0x10,%esp
  // 2、复制父进程虚拟地址池的位图
  uint32_t bitmap_pg_cnt =
c000ac8b:	c7 45 f4 17 00 00 00 	movl   $0x17,-0xc(%ebp)
      DIV_ROUND_UP((0xc0000000 - USER_VADDR_START) / PG_SIZE / 8, PG_SIZE);
  void *vaddr_btmp = get_kernel_pages(bitmap_pg_cnt);
c000ac92:	83 ec 0c             	sub    $0xc,%esp
c000ac95:	ff 75 f4             	push   -0xc(%ebp)
c000ac98:	e8 0c 81 ff ff       	call   c0002da9 <get_kernel_pages>
c000ac9d:	83 c4 10             	add    $0x10,%esp
c000aca0:	89 45 f0             	mov    %eax,-0x10(%ebp)
  memcpy(vaddr_btmp, child_thread->userprog_vaddr.vaddr_bitmap.bits,
c000aca3:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000aca6:	c1 e0 0c             	shl    $0xc,%eax
c000aca9:	89 c2                	mov    %eax,%edx
c000acab:	8b 45 08             	mov    0x8(%ebp),%eax
c000acae:	8b 40 3c             	mov    0x3c(%eax),%eax
c000acb1:	83 ec 04             	sub    $0x4,%esp
c000acb4:	52                   	push   %edx
c000acb5:	50                   	push   %eax
c000acb6:	ff 75 f0             	push   -0x10(%ebp)
c000acb9:	e8 43 77 ff ff       	call   c0002401 <memcpy>
c000acbe:	83 c4 10             	add    $0x10,%esp
         bitmap_pg_cnt * PG_SIZE); // 让位图指针指向自己的位图
  child_thread->userprog_vaddr.vaddr_bitmap.bits = vaddr_btmp;
c000acc1:	8b 45 08             	mov    0x8(%ebp),%eax
c000acc4:	8b 55 f0             	mov    -0x10(%ebp),%edx
c000acc7:	89 50 3c             	mov    %edx,0x3c(%eax)

  // 【调试用】pcb.name长度16，避免strcat越界
  ASSERT(strlen(child_thread->name) < 11);
c000acca:	8b 45 08             	mov    0x8(%ebp),%eax
c000accd:	83 c0 0c             	add    $0xc,%eax
c000acd0:	83 ec 0c             	sub    $0xc,%esp
c000acd3:	50                   	push   %eax
c000acd4:	e8 61 78 ff ff       	call   c000253a <strlen>
c000acd9:	83 c4 10             	add    $0x10,%esp
c000acdc:	83 f8 0a             	cmp    $0xa,%eax
c000acdf:	76 19                	jbe    c000acfa <copy_pcb_vaddrbitmap_stack0+0x107>
c000ace1:	68 b0 e0 00 c0       	push   $0xc000e0b0
c000ace6:	68 b8 e1 00 c0       	push   $0xc000e1b8
c000aceb:	6a 24                	push   $0x24
c000aced:	68 d0 e0 00 c0       	push   $0xc000e0d0
c000acf2:	e8 e1 75 ff ff       	call   c00022d8 <panic_spin>
c000acf7:	83 c4 10             	add    $0x10,%esp
  strcat(child_thread->name, "_fork");
c000acfa:	8b 45 08             	mov    0x8(%ebp),%eax
c000acfd:	83 c0 0c             	add    $0xc,%eax
c000ad00:	83 ec 08             	sub    $0x8,%esp
c000ad03:	68 e0 e0 00 c0       	push   $0xc000e0e0
c000ad08:	50                   	push   %eax
c000ad09:	e8 a2 79 ff ff       	call   c00026b0 <strcat>
c000ad0e:	83 c4 10             	add    $0x10,%esp
  return 0;
c000ad11:	b8 00 00 00 00       	mov    $0x0,%eax
}
c000ad16:	c9                   	leave  
c000ad17:	c3                   	ret    

c000ad18 <copy_body_stack3>:

// 复制子进程的进程体（代码和数据）及用户栈
static void copy_body_stack3(struct task_struct *child_thread,
                             struct task_struct *parent_thread,
                             void *buf_page) {
c000ad18:	55                   	push   %ebp
c000ad19:	89 e5                	mov    %esp,%ebp
c000ad1b:	83 ec 28             	sub    $0x28,%esp
  uint8_t *vaddr_btmp = parent_thread->userprog_vaddr.vaddr_bitmap.bits;
c000ad1e:	8b 45 0c             	mov    0xc(%ebp),%eax
c000ad21:	8b 40 3c             	mov    0x3c(%eax),%eax
c000ad24:	89 45 ec             	mov    %eax,-0x14(%ebp)
  uint32_t btmp_bytes_len =
c000ad27:	8b 45 0c             	mov    0xc(%ebp),%eax
c000ad2a:	8b 40 38             	mov    0x38(%eax),%eax
c000ad2d:	89 45 e8             	mov    %eax,-0x18(%ebp)
      parent_thread->userprog_vaddr.vaddr_bitmap.btmp_bytes_len;
  uint32_t vaddr_start = parent_thread->userprog_vaddr.vaddr_start;
c000ad30:	8b 45 0c             	mov    0xc(%ebp),%eax
c000ad33:	8b 40 40             	mov    0x40(%eax),%eax
c000ad36:	89 45 e4             	mov    %eax,-0x1c(%ebp)
  uint32_t idx_byte = 0;
c000ad39:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  uint32_t idx_bit = 0;
c000ad40:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
  uint32_t prog_vaddr = 0;
c000ad47:	c7 45 e0 00 00 00 00 	movl   $0x0,-0x20(%ebp)

  // 在父进程的用户空间中查找已有数据的页
  while (idx_byte < btmp_bytes_len) {
c000ad4e:	e9 c5 00 00 00       	jmp    c000ae18 <copy_body_stack3+0x100>
    if (vaddr_btmp[idx_byte]) {
c000ad53:	8b 55 ec             	mov    -0x14(%ebp),%edx
c000ad56:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000ad59:	01 d0                	add    %edx,%eax
c000ad5b:	0f b6 00             	movzbl (%eax),%eax
c000ad5e:	84 c0                	test   %al,%al
c000ad60:	0f 84 ae 00 00 00    	je     c000ae14 <copy_body_stack3+0xfc>
      idx_bit = 0;
c000ad66:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
      while (idx_bit < 8) {
c000ad6d:	e9 98 00 00 00       	jmp    c000ae0a <copy_body_stack3+0xf2>
        if ((BITMAP_MASK << idx_bit) & vaddr_btmp[idx_byte]) {
c000ad72:	8b 55 ec             	mov    -0x14(%ebp),%edx
c000ad75:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000ad78:	01 d0                	add    %edx,%eax
c000ad7a:	0f b6 00             	movzbl (%eax),%eax
c000ad7d:	0f b6 d0             	movzbl %al,%edx
c000ad80:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000ad83:	89 c1                	mov    %eax,%ecx
c000ad85:	d3 fa                	sar    %cl,%edx
c000ad87:	89 d0                	mov    %edx,%eax
c000ad89:	83 e0 01             	and    $0x1,%eax
c000ad8c:	85 c0                	test   %eax,%eax
c000ad8e:	74 76                	je     c000ae06 <copy_body_stack3+0xee>
          prog_vaddr = (idx_byte * 8 + idx_bit) * PG_SIZE + vaddr_start;
c000ad90:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000ad93:	8d 14 c5 00 00 00 00 	lea    0x0(,%eax,8),%edx
c000ad9a:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000ad9d:	01 d0                	add    %edx,%eax
c000ad9f:	c1 e0 0c             	shl    $0xc,%eax
c000ada2:	89 c2                	mov    %eax,%edx
c000ada4:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c000ada7:	01 d0                	add    %edx,%eax
c000ada9:	89 45 e0             	mov    %eax,-0x20(%ebp)
          // 1、将父进程数据复制到内核缓冲区
          memcpy(buf_page, (void *)prog_vaddr, PG_SIZE);
c000adac:	8b 45 e0             	mov    -0x20(%ebp),%eax
c000adaf:	83 ec 04             	sub    $0x4,%esp
c000adb2:	68 00 10 00 00       	push   $0x1000
c000adb7:	50                   	push   %eax
c000adb8:	ff 75 10             	push   0x10(%ebp)
c000adbb:	e8 41 76 ff ff       	call   c0002401 <memcpy>
c000adc0:	83 c4 10             	add    $0x10,%esp
          // 2、将页表切换到子进程，避免下面申请内存函数将pte和pde安装到父进程的页表中
          page_dir_activate(child_thread);
c000adc3:	83 ec 0c             	sub    $0xc,%esp
c000adc6:	ff 75 08             	push   0x8(%ebp)
c000adc9:	e8 6f a2 ff ff       	call   c000503d <page_dir_activate>
c000adce:	83 c4 10             	add    $0x10,%esp
          // 3、申请虚拟地址
          get_a_page_without_opvaddrbitmap(PF_USER, prog_vaddr);
c000add1:	83 ec 08             	sub    $0x8,%esp
c000add4:	ff 75 e0             	push   -0x20(%ebp)
c000add7:	6a 02                	push   $0x2
c000add9:	e8 bc 81 ff ff       	call   c0002f9a <get_a_page_without_opvaddrbitmap>
c000adde:	83 c4 10             	add    $0x10,%esp
          // 4、从内核缓冲区中将父进程数据复制到子进程用户空间
          memcpy((void *)prog_vaddr, buf_page, PG_SIZE);
c000ade1:	8b 45 e0             	mov    -0x20(%ebp),%eax
c000ade4:	83 ec 04             	sub    $0x4,%esp
c000ade7:	68 00 10 00 00       	push   $0x1000
c000adec:	ff 75 10             	push   0x10(%ebp)
c000adef:	50                   	push   %eax
c000adf0:	e8 0c 76 ff ff       	call   c0002401 <memcpy>
c000adf5:	83 c4 10             	add    $0x10,%esp
          // 5、恢复父进程页表
          page_dir_activate(parent_thread);
c000adf8:	83 ec 0c             	sub    $0xc,%esp
c000adfb:	ff 75 0c             	push   0xc(%ebp)
c000adfe:	e8 3a a2 ff ff       	call   c000503d <page_dir_activate>
c000ae03:	83 c4 10             	add    $0x10,%esp
        }
        idx_bit++;
c000ae06:	83 45 f0 01          	addl   $0x1,-0x10(%ebp)
      while (idx_bit < 8) {
c000ae0a:	83 7d f0 07          	cmpl   $0x7,-0x10(%ebp)
c000ae0e:	0f 86 5e ff ff ff    	jbe    c000ad72 <copy_body_stack3+0x5a>
      }
    }
    idx_byte++;
c000ae14:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
  while (idx_byte < btmp_bytes_len) {
c000ae18:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000ae1b:	3b 45 e8             	cmp    -0x18(%ebp),%eax
c000ae1e:	0f 82 2f ff ff ff    	jb     c000ad53 <copy_body_stack3+0x3b>
  }
}
c000ae24:	90                   	nop
c000ae25:	90                   	nop
c000ae26:	c9                   	leave  
c000ae27:	c3                   	ret    

c000ae28 <build_child_stack>:

// 为子进程构建thread_stack和修改返回值
static int32_t build_child_stack(struct task_struct *child_thread) {
c000ae28:	55                   	push   %ebp
c000ae29:	89 e5                	mov    %esp,%ebp
c000ae2b:	83 ec 20             	sub    $0x20,%esp
  struct intr_stack *intr_0_stack =
      (struct intr_stack *)((uint32_t)child_thread + PG_SIZE -
c000ae2e:	8b 45 08             	mov    0x8(%ebp),%eax
c000ae31:	05 b4 0f 00 00       	add    $0xfb4,%eax
  struct intr_stack *intr_0_stack =
c000ae36:	89 45 fc             	mov    %eax,-0x4(%ebp)
                            sizeof(struct intr_stack));
  intr_0_stack->eax = 0; // fork后子进程返0
c000ae39:	8b 45 fc             	mov    -0x4(%ebp),%eax
c000ae3c:	c7 40 20 00 00 00 00 	movl   $0x0,0x20(%eax)

  // 为switch_to构建thread_stack，将其构建在紧临intr_stack下的空间
  uint32_t *ret_addr_in_thread_stack = (uint32_t *)intr_0_stack - 1;
c000ae43:	8b 45 fc             	mov    -0x4(%ebp),%eax
c000ae46:	83 e8 04             	sub    $0x4,%eax
c000ae49:	89 45 f8             	mov    %eax,-0x8(%ebp)
  uint32_t *esi_ptr_in_thread_stack = (uint32_t *)intr_0_stack - 2;
c000ae4c:	8b 45 fc             	mov    -0x4(%ebp),%eax
c000ae4f:	83 e8 08             	sub    $0x8,%eax
c000ae52:	89 45 f4             	mov    %eax,-0xc(%ebp)
  uint32_t *edi_ptr_in_thread_stack = (uint32_t *)intr_0_stack - 3;
c000ae55:	8b 45 fc             	mov    -0x4(%ebp),%eax
c000ae58:	83 e8 0c             	sub    $0xc,%eax
c000ae5b:	89 45 f0             	mov    %eax,-0x10(%ebp)
  uint32_t *ebx_ptr_in_thread_stack = (uint32_t *)intr_0_stack - 4;
c000ae5e:	8b 45 fc             	mov    -0x4(%ebp),%eax
c000ae61:	83 e8 10             	sub    $0x10,%eax
c000ae64:	89 45 ec             	mov    %eax,-0x14(%ebp)
  uint32_t *ebp_ptr_in_thread_stack = (uint32_t *)intr_0_stack - 5;
c000ae67:	8b 45 fc             	mov    -0x4(%ebp),%eax
c000ae6a:	83 e8 14             	sub    $0x14,%eax
c000ae6d:	89 45 e8             	mov    %eax,-0x18(%ebp)

  *ret_addr_in_thread_stack = // switch_to返回地址更新为intr_exit，直接从中断返回
      (uint32_t)intr_exit;
c000ae70:	ba 90 1b 00 c0       	mov    $0xc0001b90,%edx
  *ret_addr_in_thread_stack = // switch_to返回地址更新为intr_exit，直接从中断返回
c000ae75:	8b 45 f8             	mov    -0x8(%ebp),%eax
c000ae78:	89 10                	mov    %edx,(%eax)
  *ebp_ptr_in_thread_stack = *ebx_ptr_in_thread_stack =
      *edi_ptr_in_thread_stack = *esi_ptr_in_thread_stack = 0;
c000ae7a:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000ae7d:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
c000ae83:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000ae86:	8b 10                	mov    (%eax),%edx
c000ae88:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000ae8b:	89 10                	mov    %edx,(%eax)
c000ae8d:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000ae90:	8b 10                	mov    (%eax),%edx
  *ebp_ptr_in_thread_stack = *ebx_ptr_in_thread_stack =
c000ae92:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000ae95:	89 10                	mov    %edx,(%eax)
c000ae97:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000ae9a:	8b 10                	mov    (%eax),%edx
c000ae9c:	8b 45 e8             	mov    -0x18(%ebp),%eax
c000ae9f:	89 10                	mov    %edx,(%eax)

  // 把构建的thread_stack栈顶作为swtich_to恢复数据时的栈顶
  child_thread->self_kstack = ebp_ptr_in_thread_stack;
c000aea1:	8b 45 08             	mov    0x8(%ebp),%eax
c000aea4:	8b 55 e8             	mov    -0x18(%ebp),%edx
c000aea7:	89 10                	mov    %edx,(%eax)
  return 0;
c000aea9:	b8 00 00 00 00       	mov    $0x0,%eax
}
c000aeae:	c9                   	leave  
c000aeaf:	c3                   	ret    

c000aeb0 <update_inode_open_cnts>:

// fork之后更新inode打开数
static void update_inode_open_cnts(struct task_struct *thread) {
c000aeb0:	55                   	push   %ebp
c000aeb1:	89 e5                	mov    %esp,%ebp
c000aeb3:	83 ec 18             	sub    $0x18,%esp
  int32_t local_fd = 3, global_fd = 0;
c000aeb6:	c7 45 f4 03 00 00 00 	movl   $0x3,-0xc(%ebp)
c000aebd:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
  while (local_fd < MAX_FILES_OPEN_PER_PROC) {
c000aec4:	eb 55                	jmp    c000af1b <update_inode_open_cnts+0x6b>
    global_fd = thread->fd_table[local_fd];
c000aec6:	8b 45 08             	mov    0x8(%ebp),%eax
c000aec9:	8b 55 f4             	mov    -0xc(%ebp),%edx
c000aecc:	83 c2 38             	add    $0x38,%edx
c000aecf:	8b 44 90 0c          	mov    0xc(%eax,%edx,4),%eax
c000aed3:	89 45 f0             	mov    %eax,-0x10(%ebp)
    ASSERT(global_fd < MAX_FILE_OPEN);
c000aed6:	83 7d f0 1f          	cmpl   $0x1f,-0x10(%ebp)
c000aeda:	7e 19                	jle    c000aef5 <update_inode_open_cnts+0x45>
c000aedc:	68 e6 e0 00 c0       	push   $0xc000e0e6
c000aee1:	68 d4 e1 00 c0       	push   $0xc000e1d4
c000aee6:	6a 6b                	push   $0x6b
c000aee8:	68 d0 e0 00 c0       	push   $0xc000e0d0
c000aeed:	e8 e6 73 ff ff       	call   c00022d8 <panic_spin>
c000aef2:	83 c4 10             	add    $0x10,%esp
    if (global_fd != -1) {
c000aef5:	83 7d f0 ff          	cmpl   $0xffffffff,-0x10(%ebp)
c000aef9:	74 1c                	je     c000af17 <update_inode_open_cnts+0x67>
      file_table[global_fd].fd_inode->i_open_cnt++;
c000aefb:	8b 55 f0             	mov    -0x10(%ebp),%edx
c000aefe:	89 d0                	mov    %edx,%eax
c000af00:	01 c0                	add    %eax,%eax
c000af02:	01 d0                	add    %edx,%eax
c000af04:	c1 e0 02             	shl    $0x2,%eax
c000af07:	05 08 2c 01 c0       	add    $0xc0012c08,%eax
c000af0c:	8b 00                	mov    (%eax),%eax
c000af0e:	8b 50 08             	mov    0x8(%eax),%edx
c000af11:	83 c2 01             	add    $0x1,%edx
c000af14:	89 50 08             	mov    %edx,0x8(%eax)
    }
    local_fd++;
c000af17:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
  while (local_fd < MAX_FILES_OPEN_PER_PROC) {
c000af1b:	83 7d f4 07          	cmpl   $0x7,-0xc(%ebp)
c000af1f:	7e a5                	jle    c000aec6 <update_inode_open_cnts+0x16>
  }
}
c000af21:	90                   	nop
c000af22:	90                   	nop
c000af23:	c9                   	leave  
c000af24:	c3                   	ret    

c000af25 <copy_process>:

// 复制父进程本身所占资源给子进程
static int32_t copy_process(struct task_struct *child_thread,
                            struct task_struct *parent_thread) {
c000af25:	55                   	push   %ebp
c000af26:	89 e5                	mov    %esp,%ebp
c000af28:	83 ec 18             	sub    $0x18,%esp
  void *buf_page = get_kernel_pages(1); // 内核缓冲区
c000af2b:	83 ec 0c             	sub    $0xc,%esp
c000af2e:	6a 01                	push   $0x1
c000af30:	e8 74 7e ff ff       	call   c0002da9 <get_kernel_pages>
c000af35:	83 c4 10             	add    $0x10,%esp
c000af38:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (buf_page == NULL) {
c000af3b:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
c000af3f:	75 0a                	jne    c000af4b <copy_process+0x26>
    return -1;
c000af41:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000af46:	e9 80 00 00 00       	jmp    c000afcb <copy_process+0xa6>
  }

  // 1、复制父进程[pcb、虚拟地址位图、内核栈]-> 子进程
  if (copy_pcb_vaddrbitmap_stack0(child_thread, parent_thread) == -1) {
c000af4b:	83 ec 08             	sub    $0x8,%esp
c000af4e:	ff 75 0c             	push   0xc(%ebp)
c000af51:	ff 75 08             	push   0x8(%ebp)
c000af54:	e8 9a fc ff ff       	call   c000abf3 <copy_pcb_vaddrbitmap_stack0>
c000af59:	83 c4 10             	add    $0x10,%esp
c000af5c:	83 f8 ff             	cmp    $0xffffffff,%eax
c000af5f:	75 07                	jne    c000af68 <copy_process+0x43>
    return -1;
c000af61:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000af66:	eb 63                	jmp    c000afcb <copy_process+0xa6>
  }
  // 2、为子进程创建页表
  child_thread->pgdir = create_page_dir();
c000af68:	e8 53 a1 ff ff       	call   c00050c0 <create_page_dir>
c000af6d:	8b 55 08             	mov    0x8(%ebp),%edx
c000af70:	89 42 34             	mov    %eax,0x34(%edx)
  if (child_thread->pgdir == NULL) {
c000af73:	8b 45 08             	mov    0x8(%ebp),%eax
c000af76:	8b 40 34             	mov    0x34(%eax),%eax
c000af79:	85 c0                	test   %eax,%eax
c000af7b:	75 07                	jne    c000af84 <copy_process+0x5f>
    return -1;
c000af7d:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000af82:	eb 47                	jmp    c000afcb <copy_process+0xa6>
  }
  // 3、复制父进程[进程体、用户栈]给子进程
  copy_body_stack3(child_thread, parent_thread, buf_page);
c000af84:	83 ec 04             	sub    $0x4,%esp
c000af87:	ff 75 f4             	push   -0xc(%ebp)
c000af8a:	ff 75 0c             	push   0xc(%ebp)
c000af8d:	ff 75 08             	push   0x8(%ebp)
c000af90:	e8 83 fd ff ff       	call   c000ad18 <copy_body_stack3>
c000af95:	83 c4 10             	add    $0x10,%esp
  // 4、构建子进程thread_stack和修改返回值
  build_child_stack(child_thread);
c000af98:	83 ec 0c             	sub    $0xc,%esp
c000af9b:	ff 75 08             	push   0x8(%ebp)
c000af9e:	e8 85 fe ff ff       	call   c000ae28 <build_child_stack>
c000afa3:	83 c4 10             	add    $0x10,%esp
  // 5、更新文件inode打开数
  update_inode_open_cnts(child_thread);
c000afa6:	83 ec 0c             	sub    $0xc,%esp
c000afa9:	ff 75 08             	push   0x8(%ebp)
c000afac:	e8 ff fe ff ff       	call   c000aeb0 <update_inode_open_cnts>
c000afb1:	83 c4 10             	add    $0x10,%esp

  mfree_page(PF_KERNEL, buf_page, 1);
c000afb4:	83 ec 04             	sub    $0x4,%esp
c000afb7:	6a 01                	push   $0x1
c000afb9:	ff 75 f4             	push   -0xc(%ebp)
c000afbc:	6a 01                	push   $0x1
c000afbe:	e8 bf 84 ff ff       	call   c0003482 <mfree_page>
c000afc3:	83 c4 10             	add    $0x10,%esp
  return 0;
c000afc6:	b8 00 00 00 00       	mov    $0x0,%eax
}
c000afcb:	c9                   	leave  
c000afcc:	c3                   	ret    

c000afcd <sys_fork>:

pid_t sys_fork(void) {
c000afcd:	55                   	push   %ebp
c000afce:	89 e5                	mov    %esp,%ebp
c000afd0:	83 ec 18             	sub    $0x18,%esp
  struct task_struct *parent_thread = running_thread();
c000afd3:	e8 37 8b ff ff       	call   c0003b0f <running_thread>
c000afd8:	89 45 f4             	mov    %eax,-0xc(%ebp)
  struct task_struct *child_thread = // 为子进程pcb获取一页内核空间
      get_kernel_pages(1);
c000afdb:	83 ec 0c             	sub    $0xc,%esp
c000afde:	6a 01                	push   $0x1
c000afe0:	e8 c4 7d ff ff       	call   c0002da9 <get_kernel_pages>
c000afe5:	83 c4 10             	add    $0x10,%esp
c000afe8:	89 45 f0             	mov    %eax,-0x10(%ebp)
  if (child_thread == NULL) {
c000afeb:	83 7d f0 00          	cmpl   $0x0,-0x10(%ebp)
c000afef:	75 0a                	jne    c000affb <sys_fork+0x2e>
    return -1;
c000aff1:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000aff6:	e9 f2 00 00 00       	jmp    c000b0ed <sys_fork+0x120>
  }
  ASSERT(INTR_OFF == intr_get_status() && parent_thread->pgdir != NULL);
c000affb:	e8 a1 69 ff ff       	call   c00019a1 <intr_get_status>
c000b000:	85 c0                	test   %eax,%eax
c000b002:	75 0a                	jne    c000b00e <sys_fork+0x41>
c000b004:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000b007:	8b 40 34             	mov    0x34(%eax),%eax
c000b00a:	85 c0                	test   %eax,%eax
c000b00c:	75 1c                	jne    c000b02a <sys_fork+0x5d>
c000b00e:	68 00 e1 00 c0       	push   $0xc000e100
c000b013:	68 ec e1 00 c0       	push   $0xc000e1ec
c000b018:	68 96 00 00 00       	push   $0x96
c000b01d:	68 d0 e0 00 c0       	push   $0xc000e0d0
c000b022:	e8 b1 72 ff ff       	call   c00022d8 <panic_spin>
c000b027:	83 c4 10             	add    $0x10,%esp

  if (copy_process(child_thread, parent_thread) == // 复制父进程信息到子进程
c000b02a:	83 ec 08             	sub    $0x8,%esp
c000b02d:	ff 75 f4             	push   -0xc(%ebp)
c000b030:	ff 75 f0             	push   -0x10(%ebp)
c000b033:	e8 ed fe ff ff       	call   c000af25 <copy_process>
c000b038:	83 c4 10             	add    $0x10,%esp
c000b03b:	83 f8 ff             	cmp    $0xffffffff,%eax
c000b03e:	75 0a                	jne    c000b04a <sys_fork+0x7d>
      -1) {
    return -1;
c000b040:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000b045:	e9 a3 00 00 00       	jmp    c000b0ed <sys_fork+0x120>
  }
  // 添加到就绪线程队列和所有线程队列
  ASSERT(!elem_find(&thread_ready_list, &child_thread->general_tag));
c000b04a:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000b04d:	83 c0 24             	add    $0x24,%eax
c000b050:	83 ec 08             	sub    $0x8,%esp
c000b053:	50                   	push   %eax
c000b054:	68 fc 1a 01 c0       	push   $0xc0011afc
c000b059:	e8 b3 92 ff ff       	call   c0004311 <elem_find>
c000b05e:	83 c4 10             	add    $0x10,%esp
c000b061:	85 c0                	test   %eax,%eax
c000b063:	74 1c                	je     c000b081 <sys_fork+0xb4>
c000b065:	68 40 e1 00 c0       	push   $0xc000e140
c000b06a:	68 ec e1 00 c0       	push   $0xc000e1ec
c000b06f:	68 9d 00 00 00       	push   $0x9d
c000b074:	68 d0 e0 00 c0       	push   $0xc000e0d0
c000b079:	e8 5a 72 ff ff       	call   c00022d8 <panic_spin>
c000b07e:	83 c4 10             	add    $0x10,%esp
  list_append(&thread_ready_list, &child_thread->general_tag);
c000b081:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000b084:	83 c0 24             	add    $0x24,%eax
c000b087:	83 ec 08             	sub    $0x8,%esp
c000b08a:	50                   	push   %eax
c000b08b:	68 fc 1a 01 c0       	push   $0xc0011afc
c000b090:	e8 02 92 ff ff       	call   c0004297 <list_append>
c000b095:	83 c4 10             	add    $0x10,%esp
  ASSERT(!elem_find(&thread_all_list, &child_thread->all_list_tag));
c000b098:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000b09b:	83 c0 2c             	add    $0x2c,%eax
c000b09e:	83 ec 08             	sub    $0x8,%esp
c000b0a1:	50                   	push   %eax
c000b0a2:	68 0c 1b 01 c0       	push   $0xc0011b0c
c000b0a7:	e8 65 92 ff ff       	call   c0004311 <elem_find>
c000b0ac:	83 c4 10             	add    $0x10,%esp
c000b0af:	85 c0                	test   %eax,%eax
c000b0b1:	74 1c                	je     c000b0cf <sys_fork+0x102>
c000b0b3:	68 7c e1 00 c0       	push   $0xc000e17c
c000b0b8:	68 ec e1 00 c0       	push   $0xc000e1ec
c000b0bd:	68 9f 00 00 00       	push   $0x9f
c000b0c2:	68 d0 e0 00 c0       	push   $0xc000e0d0
c000b0c7:	e8 0c 72 ff ff       	call   c00022d8 <panic_spin>
c000b0cc:	83 c4 10             	add    $0x10,%esp
  list_append(&thread_all_list, &child_thread->all_list_tag);
c000b0cf:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000b0d2:	83 c0 2c             	add    $0x2c,%eax
c000b0d5:	83 ec 08             	sub    $0x8,%esp
c000b0d8:	50                   	push   %eax
c000b0d9:	68 0c 1b 01 c0       	push   $0xc0011b0c
c000b0de:	e8 b4 91 ff ff       	call   c0004297 <list_append>
c000b0e3:	83 c4 10             	add    $0x10,%esp
  return child_thread->pid; // 父进程返回子进程pid
c000b0e6:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000b0e9:	0f b7 40 04          	movzwl 0x4(%eax),%eax
c000b0ed:	c9                   	leave  
c000b0ee:	c3                   	ret    

c000b0ef <print_prompt>:

static char cmd_line[cmd_len] = {0}; // 存储输入命令
char cwd_cache[64] = {0}; // 当前目录缓存（每次cd时会更新此内容

// 输出提示符
void print_prompt(void) { printf("[yers@localhost %s]$ ", cwd_cache); }
c000b0ef:	55                   	push   %ebp
c000b0f0:	89 e5                	mov    %esp,%ebp
c000b0f2:	83 ec 08             	sub    $0x8,%esp
c000b0f5:	83 ec 08             	sub    $0x8,%esp
c000b0f8:	68 80 2d 01 c0       	push   $0xc0012d80
c000b0fd:	68 f8 e1 00 c0       	push   $0xc000e1f8
c000b102:	e8 33 a5 ff ff       	call   c000563a <printf>
c000b107:	83 c4 10             	add    $0x10,%esp
c000b10a:	90                   	nop
c000b10b:	c9                   	leave  
c000b10c:	c3                   	ret    

c000b10d <readline>:

static void readline(char *buf, int32_t count) {
c000b10d:	55                   	push   %ebp
c000b10e:	89 e5                	mov    %esp,%ebp
c000b110:	83 ec 18             	sub    $0x18,%esp
  ASSERT(buf != NULL && count > 0);
c000b113:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c000b117:	74 06                	je     c000b11f <readline+0x12>
c000b119:	83 7d 0c 00          	cmpl   $0x0,0xc(%ebp)
c000b11d:	7f 19                	jg     c000b138 <readline+0x2b>
c000b11f:	68 0e e2 00 c0       	push   $0xc000e20e
c000b124:	68 80 e2 00 c0       	push   $0xc000e280
c000b129:	6a 13                	push   $0x13
c000b12b:	68 27 e2 00 c0       	push   $0xc000e227
c000b130:	e8 a3 71 ff ff       	call   c00022d8 <panic_spin>
c000b135:	83 c4 10             	add    $0x10,%esp
  char *pos = buf;
c000b138:	8b 45 08             	mov    0x8(%ebp),%eax
c000b13b:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while (read(stdin_no, pos, 1) != -1 &&
c000b13e:	eb 6d                	jmp    c000b1ad <readline+0xa0>
         (pos - buf) < count) { // 不出错情况下，直到找到回车符才返回
    switch (*pos) {
c000b140:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000b143:	0f b6 00             	movzbl (%eax),%eax
c000b146:	0f be c0             	movsbl %al,%eax
c000b149:	83 f8 0d             	cmp    $0xd,%eax
c000b14c:	74 14                	je     c000b162 <readline+0x55>
c000b14e:	83 f8 0d             	cmp    $0xd,%eax
c000b151:	7f 41                	jg     c000b194 <readline+0x87>
c000b153:	83 f8 08             	cmp    $0x8,%eax
c000b156:	74 1f                	je     c000b177 <readline+0x6a>
c000b158:	83 f8 0a             	cmp    $0xa,%eax
c000b15b:	75 37                	jne    c000b194 <readline+0x87>
    // 找到回车或换行符后认为键入的命令结束，直接返回
    case '\n':
      return;
c000b15d:	e9 81 00 00 00       	jmp    c000b1e3 <readline+0xd6>
    case '\r':
      *pos = 0; // 添加cmd_line终止字符0
c000b162:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000b165:	c6 00 00             	movb   $0x0,(%eax)
      putchar('\n');
c000b168:	83 ec 0c             	sub    $0xc,%esp
c000b16b:	6a 0a                	push   $0xa
c000b16d:	e8 d1 a1 ff ff       	call   c0005343 <putchar>
c000b172:	83 c4 10             	add    $0x10,%esp
      return;
c000b175:	eb 6c                	jmp    c000b1e3 <readline+0xd6>
    case '\b':// 退格键
      if (buf[0] != '\b') { // 阻止删除非本次输入的信息
c000b177:	8b 45 08             	mov    0x8(%ebp),%eax
c000b17a:	0f b6 00             	movzbl (%eax),%eax
c000b17d:	3c 08                	cmp    $0x8,%al
c000b17f:	74 2c                	je     c000b1ad <readline+0xa0>
        --pos;              // 退回到缓冲区cmd_line中上一个字符
c000b181:	83 6d f4 01          	subl   $0x1,-0xc(%ebp)
        putchar('\b');
c000b185:	83 ec 0c             	sub    $0xc,%esp
c000b188:	6a 08                	push   $0x8
c000b18a:	e8 b4 a1 ff ff       	call   c0005343 <putchar>
c000b18f:	83 c4 10             	add    $0x10,%esp
      }
      break;
c000b192:	eb 19                	jmp    c000b1ad <readline+0xa0>
    default: // 非控制键则输出字符
      putchar(*pos);
c000b194:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000b197:	0f b6 00             	movzbl (%eax),%eax
c000b19a:	0f be c0             	movsbl %al,%eax
c000b19d:	83 ec 0c             	sub    $0xc,%esp
c000b1a0:	50                   	push   %eax
c000b1a1:	e8 9d a1 ff ff       	call   c0005343 <putchar>
c000b1a6:	83 c4 10             	add    $0x10,%esp
      pos++;
c000b1a9:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
  while (read(stdin_no, pos, 1) != -1 &&
c000b1ad:	83 ec 04             	sub    $0x4,%esp
c000b1b0:	6a 01                	push   $0x1
c000b1b2:	ff 75 f4             	push   -0xc(%ebp)
c000b1b5:	6a 00                	push   $0x0
c000b1b7:	e8 65 a1 ff ff       	call   c0005321 <read>
c000b1bc:	83 c4 10             	add    $0x10,%esp
c000b1bf:	83 f8 ff             	cmp    $0xffffffff,%eax
c000b1c2:	74 0f                	je     c000b1d3 <readline+0xc6>
         (pos - buf) < count) { // 不出错情况下，直到找到回车符才返回
c000b1c4:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000b1c7:	2b 45 08             	sub    0x8(%ebp),%eax
  while (read(stdin_no, pos, 1) != -1 &&
c000b1ca:	39 45 0c             	cmp    %eax,0xc(%ebp)
c000b1cd:	0f 8f 6d ff ff ff    	jg     c000b140 <readline+0x33>
    }
  }
  printf("readline: can`t find enter_key in the cmd_line, max num of char is "
c000b1d3:	83 ec 0c             	sub    $0xc,%esp
c000b1d6:	68 38 e2 00 c0       	push   $0xc000e238
c000b1db:	e8 5a a4 ff ff       	call   c000563a <printf>
c000b1e0:	83 c4 10             	add    $0x10,%esp
         "128\n");
}
c000b1e3:	c9                   	leave  
c000b1e4:	c3                   	ret    

c000b1e5 <my_shell>:

void my_shell(void) {
c000b1e5:	55                   	push   %ebp
c000b1e6:	89 e5                	mov    %esp,%ebp
c000b1e8:	83 ec 08             	sub    $0x8,%esp
  cwd_cache[0] = '/';
c000b1eb:	c6 05 80 2d 01 c0 2f 	movb   $0x2f,0xc0012d80
  while (1) {
    print_prompt();
c000b1f2:	e8 f8 fe ff ff       	call   c000b0ef <print_prompt>
    memset(cmd_line, 0, cmd_len);
c000b1f7:	83 ec 04             	sub    $0x4,%esp
c000b1fa:	68 80 00 00 00       	push   $0x80
c000b1ff:	6a 00                	push   $0x0
c000b201:	68 c0 2d 01 c0       	push   $0xc0012dc0
c000b206:	e8 a3 71 ff ff       	call   c00023ae <memset>
c000b20b:	83 c4 10             	add    $0x10,%esp
    readline(cmd_line, cmd_len);
c000b20e:	83 ec 08             	sub    $0x8,%esp
c000b211:	68 80 00 00 00       	push   $0x80
c000b216:	68 c0 2d 01 c0       	push   $0xc0012dc0
c000b21b:	e8 ed fe ff ff       	call   c000b10d <readline>
c000b220:	83 c4 10             	add    $0x10,%esp
    if (cmd_line[0] == 0) { // 若只键入了一个回车
c000b223:	0f b6 05 c0 2d 01 c0 	movzbl 0xc0012dc0,%eax
c000b22a:	84 c0                	test   %al,%al
    print_prompt();
c000b22c:	eb c4                	jmp    c000b1f2 <my_shell+0xd>
