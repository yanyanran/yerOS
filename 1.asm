
kernel.bin：     文件格式 elf32-i386


Disassembly of section .text:

c0001500 <main>:
void u_prog_a(void);
void u_prog_b(void);
int test_var_a = 0;
int test_var_b = 0;

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
c0001514:	68 00 50 00 c0       	push   $0xc0005000
c0001519:	e8 52 05 00 00       	call   c0001a70 <put_str>
c000151e:	83 c4 10             	add    $0x10,%esp
  init_all();
c0001521:	e8 d9 00 00 00       	call   c00015ff <init_all>

  thread_start("k_thread_a", 31, k_thread_a, "argA ");
c0001526:	68 0d 50 00 c0       	push   $0xc000500d
c000152b:	68 89 15 00 c0       	push   $0xc0001589
c0001530:	6a 1f                	push   $0x1f
c0001532:	68 13 50 00 c0       	push   $0xc0005013
c0001537:	e8 41 1d 00 00       	call   c000327d <thread_start>
c000153c:	83 c4 10             	add    $0x10,%esp
  thread_start("k_thread_b", 31, k_thread_b, "argB ");
c000153f:	68 1e 50 00 c0       	push   $0xc000501e
c0001544:	68 b2 15 00 c0       	push   $0xc00015b2
c0001549:	6a 1f                	push   $0x1f
c000154b:	68 24 50 00 c0       	push   $0xc0005024
c0001550:	e8 28 1d 00 00       	call   c000327d <thread_start>
c0001555:	83 c4 10             	add    $0x10,%esp
  process_execute(u_prog_a, "user_prog_a");
c0001558:	83 ec 08             	sub    $0x8,%esp
c000155b:	68 2f 50 00 c0       	push   $0xc000502f
c0001560:	68 db 15 00 c0       	push   $0xc00015db
c0001565:	e8 91 30 00 00       	call   c00045fb <process_execute>
c000156a:	83 c4 10             	add    $0x10,%esp
  process_execute(u_prog_b, "user_prog_b");
c000156d:	83 ec 08             	sub    $0x8,%esp
c0001570:	68 3b 50 00 c0       	push   $0xc000503b
c0001575:	68 ed 15 00 c0       	push   $0xc00015ed
c000157a:	e8 7c 30 00 00       	call   c00045fb <process_execute>
c000157f:	83 c4 10             	add    $0x10,%esp

  intr_enable(); // 开中断
c0001582:	e8 dd 03 00 00       	call   c0001964 <intr_enable>
  while (1) {
c0001587:	eb fe                	jmp    c0001587 <main+0x87>

c0001589 <k_thread_a>:
  };
  return 0;
}

// 线程中运行的函数
void k_thread_a(void *arg) {
c0001589:	55                   	push   %ebp
c000158a:	89 e5                	mov    %esp,%ebp
c000158c:	83 ec 08             	sub    $0x8,%esp
  // char* para = arg;
  while (1) {
    console_put_str(" v_a:0x");
c000158f:	83 ec 0c             	sub    $0xc,%esp
c0001592:	68 47 50 00 c0       	push   $0xc0005047
c0001597:	e8 65 26 00 00       	call   c0003c01 <console_put_str>
c000159c:	83 c4 10             	add    $0x10,%esp
    console_put_int(test_var_a);
c000159f:	a1 60 81 00 c0       	mov    0xc0008160,%eax
c00015a4:	83 ec 0c             	sub    $0xc,%esp
c00015a7:	50                   	push   %eax
c00015a8:	e8 9e 26 00 00       	call   c0003c4b <console_put_int>
c00015ad:	83 c4 10             	add    $0x10,%esp
    console_put_str(" v_a:0x");
c00015b0:	eb dd                	jmp    c000158f <k_thread_a+0x6>

c00015b2 <k_thread_b>:
  }
}

void k_thread_b(void *arg) {
c00015b2:	55                   	push   %ebp
c00015b3:	89 e5                	mov    %esp,%ebp
c00015b5:	83 ec 08             	sub    $0x8,%esp
  // char* para = arg;
  while (1) {
    console_put_str(" v_b:0x");
c00015b8:	83 ec 0c             	sub    $0xc,%esp
c00015bb:	68 4f 50 00 c0       	push   $0xc000504f
c00015c0:	e8 3c 26 00 00       	call   c0003c01 <console_put_str>
c00015c5:	83 c4 10             	add    $0x10,%esp
    console_put_int(test_var_b);
c00015c8:	a1 64 81 00 c0       	mov    0xc0008164,%eax
c00015cd:	83 ec 0c             	sub    $0xc,%esp
c00015d0:	50                   	push   %eax
c00015d1:	e8 75 26 00 00       	call   c0003c4b <console_put_int>
c00015d6:	83 c4 10             	add    $0x10,%esp
    console_put_str(" v_b:0x");
c00015d9:	eb dd                	jmp    c00015b8 <k_thread_b+0x6>

c00015db <u_prog_a>:
  }
}

void u_prog_a(void) {
c00015db:	55                   	push   %ebp
c00015dc:	89 e5                	mov    %esp,%ebp
  while (1) {
    test_var_a++;
c00015de:	a1 60 81 00 c0       	mov    0xc0008160,%eax
c00015e3:	83 c0 01             	add    $0x1,%eax
c00015e6:	a3 60 81 00 c0       	mov    %eax,0xc0008160
c00015eb:	eb f1                	jmp    c00015de <u_prog_a+0x3>

c00015ed <u_prog_b>:
  }
}

void u_prog_b(void) {
c00015ed:	55                   	push   %ebp
c00015ee:	89 e5                	mov    %esp,%ebp
  while (1) {
    test_var_b++;
c00015f0:	a1 64 81 00 c0       	mov    0xc0008164,%eax
c00015f5:	83 c0 01             	add    $0x1,%eax
c00015f8:	a3 64 81 00 c0       	mov    %eax,0xc0008164
c00015fd:	eb f1                	jmp    c00015f0 <u_prog_b+0x3>

c00015ff <init_all>:
#include "thread.h"
#include "timer.h"
#include "tss.h"

// 负责初始化所有模块
void init_all() {
c00015ff:	55                   	push   %ebp
c0001600:	89 e5                	mov    %esp,%ebp
c0001602:	83 ec 08             	sub    $0x8,%esp
  put_str("init_all\n");
c0001605:	83 ec 0c             	sub    $0xc,%esp
c0001608:	68 57 50 00 c0       	push   $0xc0005057
c000160d:	e8 5e 04 00 00       	call   c0001a70 <put_str>
c0001612:	83 c4 10             	add    $0x10,%esp
  idt_init();      // 初始化中断
c0001615:	e8 f4 03 00 00       	call   c0001a0e <idt_init>
  timer_init();    // 初始化PIT
c000161a:	e8 fe 0b 00 00       	call   c000221d <timer_init>
  mem_init();      // 初始化内存池
c000161f:	e8 dd 1a 00 00       	call   c0003101 <mem_init>
  thread_init();   // 初始化线程环境
c0001624:	e8 c6 1e 00 00       	call   c00034ef <thread_init>
  console_init();  // 初始化终端
c0001629:	e8 88 25 00 00       	call   c0003bb6 <console_init>
  keyboard_init(); // 初始化键盘
c000162e:	e8 de 28 00 00       	call   c0003f11 <keyboard_init>
  tss_init();      // 初始化任务状态表
c0001633:	e8 7f 2c 00 00       	call   c00042b7 <tss_init>
c0001638:	90                   	nop
c0001639:	c9                   	leave  
c000163a:	c3                   	ret    

c000163b <outb>:
#ifndef __LIB_IO_H
#define __LIB_IO_H
#include "stdint.h"

// 向端口写入1字节
static inline void outb(uint16_t port, uint8_t data) {
c000163b:	55                   	push   %ebp
c000163c:	89 e5                	mov    %esp,%ebp
c000163e:	83 ec 08             	sub    $0x8,%esp
c0001641:	8b 45 08             	mov    0x8(%ebp),%eax
c0001644:	8b 55 0c             	mov    0xc(%ebp),%edx
c0001647:	66 89 45 fc          	mov    %ax,-0x4(%ebp)
c000164b:	89 d0                	mov    %edx,%eax
c000164d:	88 45 f8             	mov    %al,-0x8(%ebp)
  asm volatile("outb %b0, %w1" ::"a"(data), "Nd"(port));
c0001650:	0f b6 45 f8          	movzbl -0x8(%ebp),%eax
c0001654:	0f b7 55 fc          	movzwl -0x4(%ebp),%edx
c0001658:	ee                   	out    %al,(%dx)
}
c0001659:	90                   	nop
c000165a:	c9                   	leave  
c000165b:	c3                   	ret    

c000165c <pic_init>:
char *intr_name[IDT_DESC_CNT];             // 中断异常名数组
extern intr_handler intr_entry_table[IDT_DESC_CNT]; // 中断入口数组(asm)
intr_handler idt_table[IDT_DESC_CNT]; // 最终中断处理程序数组(c)

// 初始化8259A
static void pic_init() {
c000165c:	55                   	push   %ebp
c000165d:	89 e5                	mov    %esp,%ebp
c000165f:	83 ec 08             	sub    $0x8,%esp
  // 初始化主片
  outb(PIC_M_CTRL, 0x11); // ICW1: 边沿触发,级联8259, 需要ICW4
c0001662:	6a 11                	push   $0x11
c0001664:	6a 20                	push   $0x20
c0001666:	e8 d0 ff ff ff       	call   c000163b <outb>
c000166b:	83 c4 08             	add    $0x8,%esp
  outb(PIC_M_DATA, 0x20); // ICW2: 起始中断向量号0x20,也就是IR[0-7]为0x20～0x27
c000166e:	6a 20                	push   $0x20
c0001670:	6a 21                	push   $0x21
c0001672:	e8 c4 ff ff ff       	call   c000163b <outb>
c0001677:	83 c4 08             	add    $0x8,%esp
  outb(PIC_M_DATA, 0x04); // ICW3: IR2接从片
c000167a:	6a 04                	push   $0x4
c000167c:	6a 21                	push   $0x21
c000167e:	e8 b8 ff ff ff       	call   c000163b <outb>
c0001683:	83 c4 08             	add    $0x8,%esp
  outb(PIC_M_DATA, 0x01); // ICW4: 8086模式正常EOI
c0001686:	6a 01                	push   $0x1
c0001688:	6a 21                	push   $0x21
c000168a:	e8 ac ff ff ff       	call   c000163b <outb>
c000168f:	83 c4 08             	add    $0x8,%esp

  // 初始化从片
  outb(PIC_S_CTRL, 0x11);
c0001692:	6a 11                	push   $0x11
c0001694:	68 a0 00 00 00       	push   $0xa0
c0001699:	e8 9d ff ff ff       	call   c000163b <outb>
c000169e:	83 c4 08             	add    $0x8,%esp
  outb(PIC_S_DATA, 0x28); // ICW2: 起始中断向量号0x28,也就是IR[8-15]为0x28～0x2F
c00016a1:	6a 28                	push   $0x28
c00016a3:	68 a1 00 00 00       	push   $0xa1
c00016a8:	e8 8e ff ff ff       	call   c000163b <outb>
c00016ad:	83 c4 08             	add    $0x8,%esp
  outb(PIC_S_DATA, 0x02); // ICW3: 设置从片连接到主片的IR2引脚
c00016b0:	6a 02                	push   $0x2
c00016b2:	68 a1 00 00 00       	push   $0xa1
c00016b7:	e8 7f ff ff ff       	call   c000163b <outb>
c00016bc:	83 c4 08             	add    $0x8,%esp
  outb(PIC_S_DATA, 0x01);
c00016bf:	6a 01                	push   $0x1
c00016c1:	68 a1 00 00 00       	push   $0xa1
c00016c6:	e8 70 ff ff ff       	call   c000163b <outb>
c00016cb:	83 c4 08             	add    $0x8,%esp

  // 打开键盘、时钟中断
  outb(PIC_M_DATA, 0xfc);
c00016ce:	68 fc 00 00 00       	push   $0xfc
c00016d3:	6a 21                	push   $0x21
c00016d5:	e8 61 ff ff ff       	call   c000163b <outb>
c00016da:	83 c4 08             	add    $0x8,%esp
  outb(PIC_S_DATA, 0xff);
c00016dd:	68 ff 00 00 00       	push   $0xff
c00016e2:	68 a1 00 00 00       	push   $0xa1
c00016e7:	e8 4f ff ff ff       	call   c000163b <outb>
c00016ec:	83 c4 08             	add    $0x8,%esp

  put_str("   pic_init done\n");
c00016ef:	83 ec 0c             	sub    $0xc,%esp
c00016f2:	68 64 50 00 c0       	push   $0xc0005064
c00016f7:	e8 74 03 00 00       	call   c0001a70 <put_str>
c00016fc:	83 c4 10             	add    $0x10,%esp
}
c00016ff:	90                   	nop
c0001700:	c9                   	leave  
c0001701:	c3                   	ret    

c0001702 <make_idt_desc>:

// 创建中断门描述符
static void make_idt_desc(struct gate_desc *p_gdesc, uint8_t attr,
                          intr_handler function) {
c0001702:	55                   	push   %ebp
c0001703:	89 e5                	mov    %esp,%ebp
c0001705:	83 ec 04             	sub    $0x4,%esp
c0001708:	8b 45 0c             	mov    0xc(%ebp),%eax
c000170b:	88 45 fc             	mov    %al,-0x4(%ebp)
  p_gdesc->func_offset_low_word = (uint32_t)function & 0x0000FFFF;
c000170e:	8b 45 10             	mov    0x10(%ebp),%eax
c0001711:	89 c2                	mov    %eax,%edx
c0001713:	8b 45 08             	mov    0x8(%ebp),%eax
c0001716:	66 89 10             	mov    %dx,(%eax)
  p_gdesc->selector = SELECTOR_K_CODE;
c0001719:	8b 45 08             	mov    0x8(%ebp),%eax
c000171c:	66 c7 40 02 08 00    	movw   $0x8,0x2(%eax)
  p_gdesc->dcount = 0;
c0001722:	8b 45 08             	mov    0x8(%ebp),%eax
c0001725:	c6 40 04 00          	movb   $0x0,0x4(%eax)
  p_gdesc->attribute = attr;
c0001729:	8b 45 08             	mov    0x8(%ebp),%eax
c000172c:	0f b6 55 fc          	movzbl -0x4(%ebp),%edx
c0001730:	88 50 05             	mov    %dl,0x5(%eax)
  p_gdesc->func_offset_high_word = ((uint32_t)function & 0xFFFF0000) >> 16;
c0001733:	8b 45 10             	mov    0x10(%ebp),%eax
c0001736:	c1 e8 10             	shr    $0x10,%eax
c0001739:	89 c2                	mov    %eax,%edx
c000173b:	8b 45 08             	mov    0x8(%ebp),%eax
c000173e:	66 89 50 06          	mov    %dx,0x6(%eax)
}
c0001742:	90                   	nop
c0001743:	c9                   	leave  
c0001744:	c3                   	ret    

c0001745 <idt_desc_init>:

// 初始化填充IDT
static void idt_desc_init(void) {
c0001745:	55                   	push   %ebp
c0001746:	89 e5                	mov    %esp,%ebp
c0001748:	83 ec 18             	sub    $0x18,%esp
  int i;
  for (i = 0; i < IDT_DESC_CNT; i++) {
c000174b:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
c0001752:	eb 29                	jmp    c000177d <idt_desc_init+0x38>
    make_idt_desc(&idt[i], IDT_DESC_ATTR_DPL0, intr_entry_table[i]);
c0001754:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0001757:	8b 04 85 08 80 00 c0 	mov    -0x3fff7ff8(,%eax,4),%eax
c000175e:	8b 55 f4             	mov    -0xc(%ebp),%edx
c0001761:	c1 e2 03             	shl    $0x3,%edx
c0001764:	81 c2 00 83 00 c0    	add    $0xc0008300,%edx
c000176a:	50                   	push   %eax
c000176b:	68 8e 00 00 00       	push   $0x8e
c0001770:	52                   	push   %edx
c0001771:	e8 8c ff ff ff       	call   c0001702 <make_idt_desc>
c0001776:	83 c4 0c             	add    $0xc,%esp
  for (i = 0; i < IDT_DESC_CNT; i++) {
c0001779:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
c000177d:	83 7d f4 2f          	cmpl   $0x2f,-0xc(%ebp)
c0001781:	7e d1                	jle    c0001754 <idt_desc_init+0xf>
  }
  put_str("   idt_desc_init done\n");
c0001783:	83 ec 0c             	sub    $0xc,%esp
c0001786:	68 76 50 00 c0       	push   $0xc0005076
c000178b:	e8 e0 02 00 00       	call   c0001a70 <put_str>
c0001790:	83 c4 10             	add    $0x10,%esp
}
c0001793:	90                   	nop
c0001794:	c9                   	leave  
c0001795:	c3                   	ret    

c0001796 <general_intr_handler>:

// 通用中断处理函数（异常处理）
static void general_intr_handler(uint8_t vec_nr) {
c0001796:	55                   	push   %ebp
c0001797:	89 e5                	mov    %esp,%ebp
c0001799:	83 ec 28             	sub    $0x28,%esp
c000179c:	8b 45 08             	mov    0x8(%ebp),%eax
c000179f:	88 45 e4             	mov    %al,-0x1c(%ebp)
  // 伪中断无需处理，0x2f是从片8259A上最后一个IRQ引脚，作保留项
  if (vec_nr == 0x27 || vec_nr == 0x2f) {
c00017a2:	80 7d e4 27          	cmpb   $0x27,-0x1c(%ebp)
c00017a6:	0f 84 bf 00 00 00    	je     c000186b <general_intr_handler+0xd5>
c00017ac:	80 7d e4 2f          	cmpb   $0x2f,-0x1c(%ebp)
c00017b0:	0f 84 b5 00 00 00    	je     c000186b <general_intr_handler+0xd5>
    return;
  }
  set_cursor(0); // 光标置0
c00017b6:	83 ec 0c             	sub    $0xc,%esp
c00017b9:	6a 00                	push   $0x0
c00017bb:	e8 7e 03 00 00       	call   c0001b3e <set_cursor>
c00017c0:	83 c4 10             	add    $0x10,%esp
  int cursor_pos = 0;
c00017c3:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  while (cursor_pos < 320) { // 4行空格
c00017ca:	eb 11                	jmp    c00017dd <general_intr_handler+0x47>
    put_char(' ');
c00017cc:	83 ec 0c             	sub    $0xc,%esp
c00017cf:	6a 20                	push   $0x20
c00017d1:	e8 b8 02 00 00       	call   c0001a8e <put_char>
c00017d6:	83 c4 10             	add    $0x10,%esp
    cursor_pos++;
c00017d9:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
  while (cursor_pos < 320) { // 4行空格
c00017dd:	81 7d f4 3f 01 00 00 	cmpl   $0x13f,-0xc(%ebp)
c00017e4:	7e e6                	jle    c00017cc <general_intr_handler+0x36>
  }

  set_cursor(0);
c00017e6:	83 ec 0c             	sub    $0xc,%esp
c00017e9:	6a 00                	push   $0x0
c00017eb:	e8 4e 03 00 00       	call   c0001b3e <set_cursor>
c00017f0:	83 c4 10             	add    $0x10,%esp
  put_str("!!!       excetion messge begin          !!!\n");
c00017f3:	83 ec 0c             	sub    $0xc,%esp
c00017f6:	68 90 50 00 c0       	push   $0xc0005090
c00017fb:	e8 70 02 00 00       	call   c0001a70 <put_str>
c0001800:	83 c4 10             	add    $0x10,%esp
  set_cursor(88); // 第2行第8个地方开始打印
c0001803:	83 ec 0c             	sub    $0xc,%esp
c0001806:	6a 58                	push   $0x58
c0001808:	e8 31 03 00 00       	call   c0001b3e <set_cursor>
c000180d:	83 c4 10             	add    $0x10,%esp
  put_str(intr_name[vec_nr]);
c0001810:	0f b6 45 e4          	movzbl -0x1c(%ebp),%eax
c0001814:	8b 04 85 80 81 00 c0 	mov    -0x3fff7e80(,%eax,4),%eax
c000181b:	83 ec 0c             	sub    $0xc,%esp
c000181e:	50                   	push   %eax
c000181f:	e8 4c 02 00 00       	call   c0001a70 <put_str>
c0001824:	83 c4 10             	add    $0x10,%esp
  if (vec_nr == 14) { // pagefault缺页异常，将缺失地址打印出来并悬停
c0001827:	80 7d e4 0e          	cmpb   $0xe,-0x1c(%ebp)
c000182b:	75 2c                	jne    c0001859 <general_intr_handler+0xc3>
    int page_fault_vaddr = 0;
c000182d:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
    asm("movl %%cr2, %0" : "=r"(page_fault_vaddr)); // cr2存放造成pagefault地址
c0001834:	0f 20 d0             	mov    %cr2,%eax
c0001837:	89 45 f0             	mov    %eax,-0x10(%ebp)

    put_str("\npage fault addr is ");
c000183a:	83 ec 0c             	sub    $0xc,%esp
c000183d:	68 be 50 00 c0       	push   $0xc00050be
c0001842:	e8 29 02 00 00       	call   c0001a70 <put_str>
c0001847:	83 c4 10             	add    $0x10,%esp
    put_int(page_fault_vaddr);
c000184a:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000184d:	83 ec 0c             	sub    $0xc,%esp
c0001850:	50                   	push   %eax
c0001851:	e8 06 03 00 00       	call   c0001b5c <put_int>
c0001856:	83 c4 10             	add    $0x10,%esp
  }

  put_str("\n!!!       excetion messge end          !!!\n");
c0001859:	83 ec 0c             	sub    $0xc,%esp
c000185c:	68 d4 50 00 c0       	push   $0xc00050d4
c0001861:	e8 0a 02 00 00       	call   c0001a70 <put_str>
c0001866:	83 c4 10             	add    $0x10,%esp
  while (1)
c0001869:	eb fe                	jmp    c0001869 <general_intr_handler+0xd3>
    return;
c000186b:	90                   	nop
    ; // 到这不再会被中断
}
c000186c:	c9                   	leave  
c000186d:	c3                   	ret    

c000186e <exception_init>:

// 完成一般中断处理函数的注册、异常名的注册
static void exception_init(void) {
c000186e:	55                   	push   %ebp
c000186f:	89 e5                	mov    %esp,%ebp
c0001871:	83 ec 10             	sub    $0x10,%esp
  int i;
  // idt_table中的函数在进入中断后根据中断向量号调用
  for (i = 0; i < IDT_DESC_CNT; i++) {
c0001874:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%ebp)
c000187b:	eb 20                	jmp    c000189d <exception_init+0x2f>
    idt_table[i] = general_intr_handler; // 默认，以后注册具体处理函数
c000187d:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0001880:	c7 04 85 40 82 00 c0 	movl   $0xc0001796,-0x3fff7dc0(,%eax,4)
c0001887:	96 17 00 c0 
    intr_name[i] = "unknown";
c000188b:	8b 45 fc             	mov    -0x4(%ebp),%eax
c000188e:	c7 04 85 80 81 00 c0 	movl   $0xc0005101,-0x3fff7e80(,%eax,4)
c0001895:	01 51 00 c0 
  for (i = 0; i < IDT_DESC_CNT; i++) {
c0001899:	83 45 fc 01          	addl   $0x1,-0x4(%ebp)
c000189d:	83 7d fc 2f          	cmpl   $0x2f,-0x4(%ebp)
c00018a1:	7e da                	jle    c000187d <exception_init+0xf>
  }

  // 20个异常（0x00-0x13）
  intr_name[0] = "#DE Divide Error";
c00018a3:	c7 05 80 81 00 c0 09 	movl   $0xc0005109,0xc0008180
c00018aa:	51 00 c0 
  intr_name[1] = "#DB Debug Exception";
c00018ad:	c7 05 84 81 00 c0 1a 	movl   $0xc000511a,0xc0008184
c00018b4:	51 00 c0 
  intr_name[2] = "NMI Interrupt";
c00018b7:	c7 05 88 81 00 c0 2e 	movl   $0xc000512e,0xc0008188
c00018be:	51 00 c0 
  intr_name[3] = "#BP Breakpoint Exception";
c00018c1:	c7 05 8c 81 00 c0 3c 	movl   $0xc000513c,0xc000818c
c00018c8:	51 00 c0 
  intr_name[4] = "#OF Overflow Exception";
c00018cb:	c7 05 90 81 00 c0 55 	movl   $0xc0005155,0xc0008190
c00018d2:	51 00 c0 
  intr_name[5] = "#BR BOUND Range Exceeded Exception";
c00018d5:	c7 05 94 81 00 c0 6c 	movl   $0xc000516c,0xc0008194
c00018dc:	51 00 c0 
  intr_name[6] = "#UD Invalid Opcode Exception";
c00018df:	c7 05 98 81 00 c0 8f 	movl   $0xc000518f,0xc0008198
c00018e6:	51 00 c0 
  intr_name[7] = "#NM Device Not Available Exception";
c00018e9:	c7 05 9c 81 00 c0 ac 	movl   $0xc00051ac,0xc000819c
c00018f0:	51 00 c0 
  intr_name[8] = "#DF Double Fault Exception";
c00018f3:	c7 05 a0 81 00 c0 cf 	movl   $0xc00051cf,0xc00081a0
c00018fa:	51 00 c0 
  intr_name[9] = "Coprocessor Segment Overrun";
c00018fd:	c7 05 a4 81 00 c0 ea 	movl   $0xc00051ea,0xc00081a4
c0001904:	51 00 c0 
  intr_name[10] = "#TS Invalid TSS Exception";
c0001907:	c7 05 a8 81 00 c0 06 	movl   $0xc0005206,0xc00081a8
c000190e:	52 00 c0 
  intr_name[11] = "#NP Segment Not Present";
c0001911:	c7 05 ac 81 00 c0 20 	movl   $0xc0005220,0xc00081ac
c0001918:	52 00 c0 
  intr_name[12] = "#SS Stack Fault Exception";
c000191b:	c7 05 b0 81 00 c0 38 	movl   $0xc0005238,0xc00081b0
c0001922:	52 00 c0 
  intr_name[13] = "#GP General Protection Exception";
c0001925:	c7 05 b4 81 00 c0 54 	movl   $0xc0005254,0xc00081b4
c000192c:	52 00 c0 
  intr_name[14] = "#PF Page-Fault Exception";
c000192f:	c7 05 b8 81 00 c0 75 	movl   $0xc0005275,0xc00081b8
c0001936:	52 00 c0 
  // intr_name[15] 第15项是intel保留项，未使用
  intr_name[16] = "#MF x87 FPU Floating-Point Error";
c0001939:	c7 05 c0 81 00 c0 90 	movl   $0xc0005290,0xc00081c0
c0001940:	52 00 c0 
  intr_name[17] = "#AC Alignment Check Exception";
c0001943:	c7 05 c4 81 00 c0 b1 	movl   $0xc00052b1,0xc00081c4
c000194a:	52 00 c0 
  intr_name[18] = "#MC Machine-Check Exception";
c000194d:	c7 05 c8 81 00 c0 cf 	movl   $0xc00052cf,0xc00081c8
c0001954:	52 00 c0 
  intr_name[19] = "#XF SIMD Floating-Point Exception";
c0001957:	c7 05 cc 81 00 c0 ec 	movl   $0xc00052ec,0xc00081cc
c000195e:	52 00 c0 
}
c0001961:	90                   	nop
c0001962:	c9                   	leave  
c0001963:	c3                   	ret    

c0001964 <intr_enable>:

// 开中断，并返回开中断前的状态
enum intr_status intr_enable() {
c0001964:	55                   	push   %ebp
c0001965:	89 e5                	mov    %esp,%ebp
c0001967:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status;
  if (INTR_ON == intr_get_status()) {
c000196a:	e8 82 00 00 00       	call   c00019f1 <intr_get_status>
c000196f:	83 f8 01             	cmp    $0x1,%eax
c0001972:	75 0c                	jne    c0001980 <intr_enable+0x1c>
    old_status = INTR_ON;
c0001974:	c7 45 f4 01 00 00 00 	movl   $0x1,-0xc(%ebp)
    return old_status;
c000197b:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000197e:	eb 0b                	jmp    c000198b <intr_enable+0x27>
  } else {
    old_status = INTR_OFF;
c0001980:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
    asm volatile("sti"); // 开中断，sti指令将IF位置1
c0001987:	fb                   	sti    
    return old_status;
c0001988:	8b 45 f4             	mov    -0xc(%ebp),%eax
  }
}
c000198b:	c9                   	leave  
c000198c:	c3                   	ret    

c000198d <intr_disable>:

// 关中断，并返回关中断前的状态
enum intr_status intr_disable() {
c000198d:	55                   	push   %ebp
c000198e:	89 e5                	mov    %esp,%ebp
c0001990:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status;
  if (INTR_ON == intr_get_status()) {
c0001993:	e8 59 00 00 00       	call   c00019f1 <intr_get_status>
c0001998:	83 f8 01             	cmp    $0x1,%eax
c000199b:	75 0d                	jne    c00019aa <intr_disable+0x1d>
    old_status = INTR_ON;
c000199d:	c7 45 f4 01 00 00 00 	movl   $0x1,-0xc(%ebp)
    asm volatile("cli" ::: "memory"); // 关中断，cli指令将IF位置0
c00019a4:	fa                   	cli    
    return old_status;
c00019a5:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00019a8:	eb 0a                	jmp    c00019b4 <intr_disable+0x27>
  } else {
    old_status = INTR_OFF;
c00019aa:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
    return old_status;
c00019b1:	8b 45 f4             	mov    -0xc(%ebp),%eax
  }
}
c00019b4:	c9                   	leave  
c00019b5:	c3                   	ret    

c00019b6 <register_handler>:

// 注册中断处理函数
void register_handler(uint8_t vector_no, intr_handler func) {
c00019b6:	55                   	push   %ebp
c00019b7:	89 e5                	mov    %esp,%ebp
c00019b9:	83 ec 04             	sub    $0x4,%esp
c00019bc:	8b 45 08             	mov    0x8(%ebp),%eax
c00019bf:	88 45 fc             	mov    %al,-0x4(%ebp)
  idt_table[vector_no] = func;
c00019c2:	0f b6 45 fc          	movzbl -0x4(%ebp),%eax
c00019c6:	8b 55 0c             	mov    0xc(%ebp),%edx
c00019c9:	89 14 85 40 82 00 c0 	mov    %edx,-0x3fff7dc0(,%eax,4)
}
c00019d0:	90                   	nop
c00019d1:	c9                   	leave  
c00019d2:	c3                   	ret    

c00019d3 <intr_set_status>:

// 将中断状态设置为status
enum intr_status intr_set_status(enum intr_status status) {
c00019d3:	55                   	push   %ebp
c00019d4:	89 e5                	mov    %esp,%ebp
c00019d6:	83 ec 08             	sub    $0x8,%esp
  return status & INTR_ON ? intr_enable() : intr_disable();
c00019d9:	8b 45 08             	mov    0x8(%ebp),%eax
c00019dc:	83 e0 01             	and    $0x1,%eax
c00019df:	85 c0                	test   %eax,%eax
c00019e1:	74 07                	je     c00019ea <intr_set_status+0x17>
c00019e3:	e8 7c ff ff ff       	call   c0001964 <intr_enable>
c00019e8:	eb 05                	jmp    c00019ef <intr_set_status+0x1c>
c00019ea:	e8 9e ff ff ff       	call   c000198d <intr_disable>
}
c00019ef:	c9                   	leave  
c00019f0:	c3                   	ret    

c00019f1 <intr_get_status>:

// 获取当前中断状态
enum intr_status intr_get_status() {
c00019f1:	55                   	push   %ebp
c00019f2:	89 e5                	mov    %esp,%ebp
c00019f4:	83 ec 10             	sub    $0x10,%esp
  uint32_t eflags = 0;
c00019f7:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%ebp)
  GET_EFLAGS(eflags);
c00019fe:	9c                   	pushf  
c00019ff:	58                   	pop    %eax
c0001a00:	89 45 fc             	mov    %eax,-0x4(%ebp)
  return (EFLAGS_IF & eflags) ? INTR_ON : INTR_OFF; // 判断eflags中的IF位
c0001a03:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0001a06:	c1 e8 09             	shr    $0x9,%eax
c0001a09:	83 e0 01             	and    $0x1,%eax
}
c0001a0c:	c9                   	leave  
c0001a0d:	c3                   	ret    

c0001a0e <idt_init>:

// 完成有关中断的所有初始化工作
void idt_init() {
c0001a0e:	55                   	push   %ebp
c0001a0f:	89 e5                	mov    %esp,%ebp
c0001a11:	83 ec 18             	sub    $0x18,%esp
  put_str("idt_init start\n");
c0001a14:	83 ec 0c             	sub    $0xc,%esp
c0001a17:	68 0e 53 00 c0       	push   $0xc000530e
c0001a1c:	e8 4f 00 00 00       	call   c0001a70 <put_str>
c0001a21:	83 c4 10             	add    $0x10,%esp
  idt_desc_init();  // 初始化IDT
c0001a24:	e8 1c fd ff ff       	call   c0001745 <idt_desc_init>
  exception_init(); // 异常名初始化并注册通常的中断处理函数
c0001a29:	e8 40 fe ff ff       	call   c000186e <exception_init>
  pic_init();       // 初始化8259A
c0001a2e:	e8 29 fc ff ff       	call   c000165c <pic_init>

  // 加载IDT
  uint64_t idt_operand =
      ((sizeof(idt) - 1) | ((uint64_t)((uint32_t)idt << 16)));
c0001a33:	b8 00 83 00 c0       	mov    $0xc0008300,%eax
c0001a38:	c1 e0 10             	shl    $0x10,%eax
c0001a3b:	0d 7f 01 00 00       	or     $0x17f,%eax
c0001a40:	ba 00 00 00 00       	mov    $0x0,%edx
  uint64_t idt_operand =
c0001a45:	89 45 f0             	mov    %eax,-0x10(%ebp)
c0001a48:	89 55 f4             	mov    %edx,-0xc(%ebp)
  asm volatile("lidt %0" ::"m"(idt_operand));
c0001a4b:	0f 01 5d f0          	lidtl  -0x10(%ebp)
  put_str("idt_init done\n");
c0001a4f:	83 ec 0c             	sub    $0xc,%esp
c0001a52:	68 1e 53 00 c0       	push   $0xc000531e
c0001a57:	e8 14 00 00 00       	call   c0001a70 <put_str>
c0001a5c:	83 c4 10             	add    $0x10,%esp
c0001a5f:	90                   	nop
c0001a60:	c9                   	leave  
c0001a61:	c3                   	ret    
c0001a62:	66 90                	xchg   %ax,%ax
c0001a64:	66 90                	xchg   %ax,%ax
c0001a66:	66 90                	xchg   %ax,%ax
c0001a68:	66 90                	xchg   %ax,%ax
c0001a6a:	66 90                	xchg   %ax,%ax
c0001a6c:	66 90                	xchg   %ax,%ax
c0001a6e:	66 90                	xchg   %ax,%ax

c0001a70 <put_str>:
c0001a70:	53                   	push   %ebx
c0001a71:	51                   	push   %ecx
c0001a72:	31 c9                	xor    %ecx,%ecx
c0001a74:	8b 5c 24 0c          	mov    0xc(%esp),%ebx

c0001a78 <put_str.goon>:
c0001a78:	8a 0b                	mov    (%ebx),%cl
c0001a7a:	80 f9 00             	cmp    $0x0,%cl
c0001a7d:	74 0c                	je     c0001a8b <put_str.str_over>
c0001a7f:	51                   	push   %ecx
c0001a80:	e8 09 00 00 00       	call   c0001a8e <put_char>
c0001a85:	83 c4 04             	add    $0x4,%esp
c0001a88:	43                   	inc    %ebx
c0001a89:	eb ed                	jmp    c0001a78 <put_str.goon>

c0001a8b <put_str.str_over>:
c0001a8b:	59                   	pop    %ecx
c0001a8c:	5b                   	pop    %ebx
c0001a8d:	c3                   	ret    

c0001a8e <put_char>:
c0001a8e:	60                   	pusha  
c0001a8f:	66 b8 18 00          	mov    $0x18,%ax
c0001a93:	8e e8                	mov    %eax,%gs
c0001a95:	66 ba d4 03          	mov    $0x3d4,%dx
c0001a99:	b0 0e                	mov    $0xe,%al
c0001a9b:	ee                   	out    %al,(%dx)
c0001a9c:	66 ba d5 03          	mov    $0x3d5,%dx
c0001aa0:	ec                   	in     (%dx),%al
c0001aa1:	88 c4                	mov    %al,%ah
c0001aa3:	66 ba d4 03          	mov    $0x3d4,%dx
c0001aa7:	b0 0f                	mov    $0xf,%al
c0001aa9:	ee                   	out    %al,(%dx)
c0001aaa:	66 ba d5 03          	mov    $0x3d5,%dx
c0001aae:	ec                   	in     (%dx),%al
c0001aaf:	66 89 c3             	mov    %ax,%bx
c0001ab2:	8b 4c 24 24          	mov    0x24(%esp),%ecx
c0001ab6:	80 f9 0d             	cmp    $0xd,%cl
c0001ab9:	74 3c                	je     c0001af7 <put_char.is_carriage_return>
c0001abb:	80 f9 0a             	cmp    $0xa,%cl
c0001abe:	74 37                	je     c0001af7 <put_char.is_carriage_return>
c0001ac0:	80 f9 08             	cmp    $0x8,%cl
c0001ac3:	74 02                	je     c0001ac7 <put_char.back_space>
c0001ac5:	eb 16                	jmp    c0001add <put_char.put_other>

c0001ac7 <put_char.back_space>:
c0001ac7:	66 4b                	dec    %bx
c0001ac9:	66 d1 e3             	shl    %bx
c0001acc:	65 67 c6 07 20       	movb   $0x20,%gs:(%bx)
c0001ad1:	66 43                	inc    %bx
c0001ad3:	65 67 c6 07 07       	movb   $0x7,%gs:(%bx)
c0001ad8:	66 d1 eb             	shr    %bx
c0001adb:	eb 61                	jmp    c0001b3e <set_cursor>

c0001add <put_char.put_other>:
c0001add:	66 d1 e3             	shl    %bx
c0001ae0:	65 67 88 0f          	mov    %cl,%gs:(%bx)
c0001ae4:	66 43                	inc    %bx
c0001ae6:	65 67 c6 07 07       	movb   $0x7,%gs:(%bx)
c0001aeb:	66 d1 eb             	shr    %bx
c0001aee:	66 43                	inc    %bx
c0001af0:	66 81 fb d0 07       	cmp    $0x7d0,%bx
c0001af5:	7c 47                	jl     c0001b3e <set_cursor>

c0001af7 <put_char.is_carriage_return>:
c0001af7:	66 31 d2             	xor    %dx,%dx
c0001afa:	66 89 d8             	mov    %bx,%ax
c0001afd:	66 be 50 00          	mov    $0x50,%si
c0001b01:	66 f7 f6             	div    %si
c0001b04:	66 29 d3             	sub    %dx,%bx

c0001b07 <put_char.is_carriage_return_end>:
c0001b07:	66 83 c3 50          	add    $0x50,%bx
c0001b0b:	66 81 fb d0 07       	cmp    $0x7d0,%bx

c0001b10 <put_char.is_line_feed_end>:
c0001b10:	7c 2c                	jl     c0001b3e <set_cursor>

c0001b12 <put_char.roll_screen>:
c0001b12:	fc                   	cld    
c0001b13:	b9 c0 03 00 00       	mov    $0x3c0,%ecx
c0001b18:	be a0 80 0b c0       	mov    $0xc00b80a0,%esi
c0001b1d:	bf 00 80 0b c0       	mov    $0xc00b8000,%edi
c0001b22:	f3 a5                	rep movsl %ds:(%esi),%es:(%edi)
c0001b24:	bb 00 0f 00 00       	mov    $0xf00,%ebx
c0001b29:	b9 50 00 00 00       	mov    $0x50,%ecx

c0001b2e <put_char.cls>:
c0001b2e:	65 c7 03 20 07 00 00 	movl   $0x720,%gs:(%ebx)
c0001b35:	83 c3 02             	add    $0x2,%ebx
c0001b38:	e2 f4                	loop   c0001b2e <put_char.cls>
c0001b3a:	66 bb 80 07          	mov    $0x780,%bx

c0001b3e <set_cursor>:
c0001b3e:	66 ba d4 03          	mov    $0x3d4,%dx
c0001b42:	b0 0e                	mov    $0xe,%al
c0001b44:	ee                   	out    %al,(%dx)
c0001b45:	66 ba d5 03          	mov    $0x3d5,%dx
c0001b49:	88 f8                	mov    %bh,%al
c0001b4b:	ee                   	out    %al,(%dx)
c0001b4c:	66 ba d4 03          	mov    $0x3d4,%dx
c0001b50:	b0 0f                	mov    $0xf,%al
c0001b52:	ee                   	out    %al,(%dx)
c0001b53:	66 ba d5 03          	mov    $0x3d5,%dx
c0001b57:	88 d8                	mov    %bl,%al
c0001b59:	ee                   	out    %al,(%dx)

c0001b5a <set_cursor.put_char_done>:
c0001b5a:	61                   	popa   
c0001b5b:	c3                   	ret    

c0001b5c <put_int>:
c0001b5c:	60                   	pusha  
c0001b5d:	89 e5                	mov    %esp,%ebp
c0001b5f:	8b 45 24             	mov    0x24(%ebp),%eax
c0001b62:	89 c2                	mov    %eax,%edx
c0001b64:	bf 07 00 00 00       	mov    $0x7,%edi
c0001b69:	b9 08 00 00 00       	mov    $0x8,%ecx
c0001b6e:	bb 00 80 00 c0       	mov    $0xc0008000,%ebx

c0001b73 <put_int.16based_4bits>:
c0001b73:	83 e2 0f             	and    $0xf,%edx
c0001b76:	83 fa 09             	cmp    $0x9,%edx
c0001b79:	7f 05                	jg     c0001b80 <put_int.is_A2F>
c0001b7b:	83 c2 30             	add    $0x30,%edx
c0001b7e:	eb 06                	jmp    c0001b86 <put_int.store>

c0001b80 <put_int.is_A2F>:
c0001b80:	83 ea 0a             	sub    $0xa,%edx
c0001b83:	83 c2 41             	add    $0x41,%edx

c0001b86 <put_int.store>:
c0001b86:	88 14 3b             	mov    %dl,(%ebx,%edi,1)
c0001b89:	4f                   	dec    %edi
c0001b8a:	c1 e8 04             	shr    $0x4,%eax
c0001b8d:	89 c2                	mov    %eax,%edx
c0001b8f:	e2 e2                	loop   c0001b73 <put_int.16based_4bits>

c0001b91 <put_int.ready_to_print>:
c0001b91:	47                   	inc    %edi

c0001b92 <put_int.skip_prefix_0>:
c0001b92:	83 ff 08             	cmp    $0x8,%edi
c0001b95:	74 0f                	je     c0001ba6 <put_int.full0>

c0001b97 <put_int.go_on_skip>:
c0001b97:	8a 8f 00 80 00 c0    	mov    -0x3fff8000(%edi),%cl
c0001b9d:	47                   	inc    %edi
c0001b9e:	80 f9 30             	cmp    $0x30,%cl
c0001ba1:	74 ef                	je     c0001b92 <put_int.skip_prefix_0>
c0001ba3:	4f                   	dec    %edi
c0001ba4:	eb 02                	jmp    c0001ba8 <put_int.put_each_num>

c0001ba6 <put_int.full0>:
c0001ba6:	b1 30                	mov    $0x30,%cl

c0001ba8 <put_int.put_each_num>:
c0001ba8:	51                   	push   %ecx
c0001ba9:	e8 e0 fe ff ff       	call   c0001a8e <put_char>
c0001bae:	83 c4 04             	add    $0x4,%esp
c0001bb1:	47                   	inc    %edi
c0001bb2:	8a 8f 00 80 00 c0    	mov    -0x3fff8000(%edi),%cl
c0001bb8:	83 ff 08             	cmp    $0x8,%edi
c0001bbb:	7c eb                	jl     c0001ba8 <put_int.put_each_num>
c0001bbd:	61                   	popa   
c0001bbe:	c3                   	ret    
c0001bbf:	90                   	nop

c0001bc0 <intr_exit>:
c0001bc0:	83 c4 04             	add    $0x4,%esp
c0001bc3:	61                   	popa   
c0001bc4:	0f a9                	pop    %gs
c0001bc6:	0f a1                	pop    %fs
c0001bc8:	07                   	pop    %es
c0001bc9:	1f                   	pop    %ds
c0001bca:	83 c4 04             	add    $0x4,%esp
c0001bcd:	cf                   	iret   

c0001bce <intr0x00entry>:
c0001bce:	6a 00                	push   $0x0
c0001bd0:	1e                   	push   %ds
c0001bd1:	06                   	push   %es
c0001bd2:	0f a0                	push   %fs
c0001bd4:	0f a8                	push   %gs
c0001bd6:	60                   	pusha  
c0001bd7:	b0 20                	mov    $0x20,%al
c0001bd9:	e6 a0                	out    %al,$0xa0
c0001bdb:	e6 20                	out    %al,$0x20
c0001bdd:	6a 00                	push   $0x0
c0001bdf:	ff 15 40 82 00 c0    	call   *0xc0008240
c0001be5:	eb d9                	jmp    c0001bc0 <intr_exit>

c0001be7 <intr0x01entry>:
c0001be7:	6a 00                	push   $0x0
c0001be9:	1e                   	push   %ds
c0001bea:	06                   	push   %es
c0001beb:	0f a0                	push   %fs
c0001bed:	0f a8                	push   %gs
c0001bef:	60                   	pusha  
c0001bf0:	b0 20                	mov    $0x20,%al
c0001bf2:	e6 a0                	out    %al,$0xa0
c0001bf4:	e6 20                	out    %al,$0x20
c0001bf6:	6a 01                	push   $0x1
c0001bf8:	ff 15 44 82 00 c0    	call   *0xc0008244
c0001bfe:	eb c0                	jmp    c0001bc0 <intr_exit>

c0001c00 <intr0x02entry>:
c0001c00:	6a 00                	push   $0x0
c0001c02:	1e                   	push   %ds
c0001c03:	06                   	push   %es
c0001c04:	0f a0                	push   %fs
c0001c06:	0f a8                	push   %gs
c0001c08:	60                   	pusha  
c0001c09:	b0 20                	mov    $0x20,%al
c0001c0b:	e6 a0                	out    %al,$0xa0
c0001c0d:	e6 20                	out    %al,$0x20
c0001c0f:	6a 02                	push   $0x2
c0001c11:	ff 15 48 82 00 c0    	call   *0xc0008248
c0001c17:	eb a7                	jmp    c0001bc0 <intr_exit>

c0001c19 <intr0x03entry>:
c0001c19:	6a 00                	push   $0x0
c0001c1b:	1e                   	push   %ds
c0001c1c:	06                   	push   %es
c0001c1d:	0f a0                	push   %fs
c0001c1f:	0f a8                	push   %gs
c0001c21:	60                   	pusha  
c0001c22:	b0 20                	mov    $0x20,%al
c0001c24:	e6 a0                	out    %al,$0xa0
c0001c26:	e6 20                	out    %al,$0x20
c0001c28:	6a 03                	push   $0x3
c0001c2a:	ff 15 4c 82 00 c0    	call   *0xc000824c
c0001c30:	eb 8e                	jmp    c0001bc0 <intr_exit>

c0001c32 <intr0x04entry>:
c0001c32:	6a 00                	push   $0x0
c0001c34:	1e                   	push   %ds
c0001c35:	06                   	push   %es
c0001c36:	0f a0                	push   %fs
c0001c38:	0f a8                	push   %gs
c0001c3a:	60                   	pusha  
c0001c3b:	b0 20                	mov    $0x20,%al
c0001c3d:	e6 a0                	out    %al,$0xa0
c0001c3f:	e6 20                	out    %al,$0x20
c0001c41:	6a 04                	push   $0x4
c0001c43:	ff 15 50 82 00 c0    	call   *0xc0008250
c0001c49:	e9 72 ff ff ff       	jmp    c0001bc0 <intr_exit>

c0001c4e <intr0x05entry>:
c0001c4e:	6a 00                	push   $0x0
c0001c50:	1e                   	push   %ds
c0001c51:	06                   	push   %es
c0001c52:	0f a0                	push   %fs
c0001c54:	0f a8                	push   %gs
c0001c56:	60                   	pusha  
c0001c57:	b0 20                	mov    $0x20,%al
c0001c59:	e6 a0                	out    %al,$0xa0
c0001c5b:	e6 20                	out    %al,$0x20
c0001c5d:	6a 05                	push   $0x5
c0001c5f:	ff 15 54 82 00 c0    	call   *0xc0008254
c0001c65:	e9 56 ff ff ff       	jmp    c0001bc0 <intr_exit>

c0001c6a <intr0x06entry>:
c0001c6a:	6a 00                	push   $0x0
c0001c6c:	1e                   	push   %ds
c0001c6d:	06                   	push   %es
c0001c6e:	0f a0                	push   %fs
c0001c70:	0f a8                	push   %gs
c0001c72:	60                   	pusha  
c0001c73:	b0 20                	mov    $0x20,%al
c0001c75:	e6 a0                	out    %al,$0xa0
c0001c77:	e6 20                	out    %al,$0x20
c0001c79:	6a 06                	push   $0x6
c0001c7b:	ff 15 58 82 00 c0    	call   *0xc0008258
c0001c81:	e9 3a ff ff ff       	jmp    c0001bc0 <intr_exit>

c0001c86 <intr0x07entry>:
c0001c86:	6a 00                	push   $0x0
c0001c88:	1e                   	push   %ds
c0001c89:	06                   	push   %es
c0001c8a:	0f a0                	push   %fs
c0001c8c:	0f a8                	push   %gs
c0001c8e:	60                   	pusha  
c0001c8f:	b0 20                	mov    $0x20,%al
c0001c91:	e6 a0                	out    %al,$0xa0
c0001c93:	e6 20                	out    %al,$0x20
c0001c95:	6a 07                	push   $0x7
c0001c97:	ff 15 5c 82 00 c0    	call   *0xc000825c
c0001c9d:	e9 1e ff ff ff       	jmp    c0001bc0 <intr_exit>

c0001ca2 <intr0x08entry>:
c0001ca2:	90                   	nop
c0001ca3:	1e                   	push   %ds
c0001ca4:	06                   	push   %es
c0001ca5:	0f a0                	push   %fs
c0001ca7:	0f a8                	push   %gs
c0001ca9:	60                   	pusha  
c0001caa:	b0 20                	mov    $0x20,%al
c0001cac:	e6 a0                	out    %al,$0xa0
c0001cae:	e6 20                	out    %al,$0x20
c0001cb0:	6a 08                	push   $0x8
c0001cb2:	ff 15 60 82 00 c0    	call   *0xc0008260
c0001cb8:	e9 03 ff ff ff       	jmp    c0001bc0 <intr_exit>

c0001cbd <intr0x09entry>:
c0001cbd:	6a 00                	push   $0x0
c0001cbf:	1e                   	push   %ds
c0001cc0:	06                   	push   %es
c0001cc1:	0f a0                	push   %fs
c0001cc3:	0f a8                	push   %gs
c0001cc5:	60                   	pusha  
c0001cc6:	b0 20                	mov    $0x20,%al
c0001cc8:	e6 a0                	out    %al,$0xa0
c0001cca:	e6 20                	out    %al,$0x20
c0001ccc:	6a 09                	push   $0x9
c0001cce:	ff 15 64 82 00 c0    	call   *0xc0008264
c0001cd4:	e9 e7 fe ff ff       	jmp    c0001bc0 <intr_exit>

c0001cd9 <intr0x0aentry>:
c0001cd9:	90                   	nop
c0001cda:	1e                   	push   %ds
c0001cdb:	06                   	push   %es
c0001cdc:	0f a0                	push   %fs
c0001cde:	0f a8                	push   %gs
c0001ce0:	60                   	pusha  
c0001ce1:	b0 20                	mov    $0x20,%al
c0001ce3:	e6 a0                	out    %al,$0xa0
c0001ce5:	e6 20                	out    %al,$0x20
c0001ce7:	6a 0a                	push   $0xa
c0001ce9:	ff 15 68 82 00 c0    	call   *0xc0008268
c0001cef:	e9 cc fe ff ff       	jmp    c0001bc0 <intr_exit>

c0001cf4 <intr0x0bentry>:
c0001cf4:	90                   	nop
c0001cf5:	1e                   	push   %ds
c0001cf6:	06                   	push   %es
c0001cf7:	0f a0                	push   %fs
c0001cf9:	0f a8                	push   %gs
c0001cfb:	60                   	pusha  
c0001cfc:	b0 20                	mov    $0x20,%al
c0001cfe:	e6 a0                	out    %al,$0xa0
c0001d00:	e6 20                	out    %al,$0x20
c0001d02:	6a 0b                	push   $0xb
c0001d04:	ff 15 6c 82 00 c0    	call   *0xc000826c
c0001d0a:	e9 b1 fe ff ff       	jmp    c0001bc0 <intr_exit>

c0001d0f <intr0x0centry>:
c0001d0f:	90                   	nop
c0001d10:	1e                   	push   %ds
c0001d11:	06                   	push   %es
c0001d12:	0f a0                	push   %fs
c0001d14:	0f a8                	push   %gs
c0001d16:	60                   	pusha  
c0001d17:	b0 20                	mov    $0x20,%al
c0001d19:	e6 a0                	out    %al,$0xa0
c0001d1b:	e6 20                	out    %al,$0x20
c0001d1d:	6a 0c                	push   $0xc
c0001d1f:	ff 15 70 82 00 c0    	call   *0xc0008270
c0001d25:	e9 96 fe ff ff       	jmp    c0001bc0 <intr_exit>

c0001d2a <intr0x0dentry>:
c0001d2a:	90                   	nop
c0001d2b:	1e                   	push   %ds
c0001d2c:	06                   	push   %es
c0001d2d:	0f a0                	push   %fs
c0001d2f:	0f a8                	push   %gs
c0001d31:	60                   	pusha  
c0001d32:	b0 20                	mov    $0x20,%al
c0001d34:	e6 a0                	out    %al,$0xa0
c0001d36:	e6 20                	out    %al,$0x20
c0001d38:	6a 0d                	push   $0xd
c0001d3a:	ff 15 74 82 00 c0    	call   *0xc0008274
c0001d40:	e9 7b fe ff ff       	jmp    c0001bc0 <intr_exit>

c0001d45 <intr0x0eentry>:
c0001d45:	90                   	nop
c0001d46:	1e                   	push   %ds
c0001d47:	06                   	push   %es
c0001d48:	0f a0                	push   %fs
c0001d4a:	0f a8                	push   %gs
c0001d4c:	60                   	pusha  
c0001d4d:	b0 20                	mov    $0x20,%al
c0001d4f:	e6 a0                	out    %al,$0xa0
c0001d51:	e6 20                	out    %al,$0x20
c0001d53:	6a 0e                	push   $0xe
c0001d55:	ff 15 78 82 00 c0    	call   *0xc0008278
c0001d5b:	e9 60 fe ff ff       	jmp    c0001bc0 <intr_exit>

c0001d60 <intr0x0fentry>:
c0001d60:	6a 00                	push   $0x0
c0001d62:	1e                   	push   %ds
c0001d63:	06                   	push   %es
c0001d64:	0f a0                	push   %fs
c0001d66:	0f a8                	push   %gs
c0001d68:	60                   	pusha  
c0001d69:	b0 20                	mov    $0x20,%al
c0001d6b:	e6 a0                	out    %al,$0xa0
c0001d6d:	e6 20                	out    %al,$0x20
c0001d6f:	6a 0f                	push   $0xf
c0001d71:	ff 15 7c 82 00 c0    	call   *0xc000827c
c0001d77:	e9 44 fe ff ff       	jmp    c0001bc0 <intr_exit>

c0001d7c <intr0x10entry>:
c0001d7c:	6a 00                	push   $0x0
c0001d7e:	1e                   	push   %ds
c0001d7f:	06                   	push   %es
c0001d80:	0f a0                	push   %fs
c0001d82:	0f a8                	push   %gs
c0001d84:	60                   	pusha  
c0001d85:	b0 20                	mov    $0x20,%al
c0001d87:	e6 a0                	out    %al,$0xa0
c0001d89:	e6 20                	out    %al,$0x20
c0001d8b:	6a 10                	push   $0x10
c0001d8d:	ff 15 80 82 00 c0    	call   *0xc0008280
c0001d93:	e9 28 fe ff ff       	jmp    c0001bc0 <intr_exit>

c0001d98 <intr0x11entry>:
c0001d98:	90                   	nop
c0001d99:	1e                   	push   %ds
c0001d9a:	06                   	push   %es
c0001d9b:	0f a0                	push   %fs
c0001d9d:	0f a8                	push   %gs
c0001d9f:	60                   	pusha  
c0001da0:	b0 20                	mov    $0x20,%al
c0001da2:	e6 a0                	out    %al,$0xa0
c0001da4:	e6 20                	out    %al,$0x20
c0001da6:	6a 11                	push   $0x11
c0001da8:	ff 15 84 82 00 c0    	call   *0xc0008284
c0001dae:	e9 0d fe ff ff       	jmp    c0001bc0 <intr_exit>

c0001db3 <intr0x12entry>:
c0001db3:	6a 00                	push   $0x0
c0001db5:	1e                   	push   %ds
c0001db6:	06                   	push   %es
c0001db7:	0f a0                	push   %fs
c0001db9:	0f a8                	push   %gs
c0001dbb:	60                   	pusha  
c0001dbc:	b0 20                	mov    $0x20,%al
c0001dbe:	e6 a0                	out    %al,$0xa0
c0001dc0:	e6 20                	out    %al,$0x20
c0001dc2:	6a 12                	push   $0x12
c0001dc4:	ff 15 88 82 00 c0    	call   *0xc0008288
c0001dca:	e9 f1 fd ff ff       	jmp    c0001bc0 <intr_exit>

c0001dcf <intr0x13entry>:
c0001dcf:	6a 00                	push   $0x0
c0001dd1:	1e                   	push   %ds
c0001dd2:	06                   	push   %es
c0001dd3:	0f a0                	push   %fs
c0001dd5:	0f a8                	push   %gs
c0001dd7:	60                   	pusha  
c0001dd8:	b0 20                	mov    $0x20,%al
c0001dda:	e6 a0                	out    %al,$0xa0
c0001ddc:	e6 20                	out    %al,$0x20
c0001dde:	6a 13                	push   $0x13
c0001de0:	ff 15 8c 82 00 c0    	call   *0xc000828c
c0001de6:	e9 d5 fd ff ff       	jmp    c0001bc0 <intr_exit>

c0001deb <intr0x14entry>:
c0001deb:	6a 00                	push   $0x0
c0001ded:	1e                   	push   %ds
c0001dee:	06                   	push   %es
c0001def:	0f a0                	push   %fs
c0001df1:	0f a8                	push   %gs
c0001df3:	60                   	pusha  
c0001df4:	b0 20                	mov    $0x20,%al
c0001df6:	e6 a0                	out    %al,$0xa0
c0001df8:	e6 20                	out    %al,$0x20
c0001dfa:	6a 14                	push   $0x14
c0001dfc:	ff 15 90 82 00 c0    	call   *0xc0008290
c0001e02:	e9 b9 fd ff ff       	jmp    c0001bc0 <intr_exit>

c0001e07 <intr0x15entry>:
c0001e07:	6a 00                	push   $0x0
c0001e09:	1e                   	push   %ds
c0001e0a:	06                   	push   %es
c0001e0b:	0f a0                	push   %fs
c0001e0d:	0f a8                	push   %gs
c0001e0f:	60                   	pusha  
c0001e10:	b0 20                	mov    $0x20,%al
c0001e12:	e6 a0                	out    %al,$0xa0
c0001e14:	e6 20                	out    %al,$0x20
c0001e16:	6a 15                	push   $0x15
c0001e18:	ff 15 94 82 00 c0    	call   *0xc0008294
c0001e1e:	e9 9d fd ff ff       	jmp    c0001bc0 <intr_exit>

c0001e23 <intr0x16entry>:
c0001e23:	6a 00                	push   $0x0
c0001e25:	1e                   	push   %ds
c0001e26:	06                   	push   %es
c0001e27:	0f a0                	push   %fs
c0001e29:	0f a8                	push   %gs
c0001e2b:	60                   	pusha  
c0001e2c:	b0 20                	mov    $0x20,%al
c0001e2e:	e6 a0                	out    %al,$0xa0
c0001e30:	e6 20                	out    %al,$0x20
c0001e32:	6a 16                	push   $0x16
c0001e34:	ff 15 98 82 00 c0    	call   *0xc0008298
c0001e3a:	e9 81 fd ff ff       	jmp    c0001bc0 <intr_exit>

c0001e3f <intr0x17entry>:
c0001e3f:	6a 00                	push   $0x0
c0001e41:	1e                   	push   %ds
c0001e42:	06                   	push   %es
c0001e43:	0f a0                	push   %fs
c0001e45:	0f a8                	push   %gs
c0001e47:	60                   	pusha  
c0001e48:	b0 20                	mov    $0x20,%al
c0001e4a:	e6 a0                	out    %al,$0xa0
c0001e4c:	e6 20                	out    %al,$0x20
c0001e4e:	6a 17                	push   $0x17
c0001e50:	ff 15 9c 82 00 c0    	call   *0xc000829c
c0001e56:	e9 65 fd ff ff       	jmp    c0001bc0 <intr_exit>

c0001e5b <intr0x18entry>:
c0001e5b:	6a 00                	push   $0x0
c0001e5d:	1e                   	push   %ds
c0001e5e:	06                   	push   %es
c0001e5f:	0f a0                	push   %fs
c0001e61:	0f a8                	push   %gs
c0001e63:	60                   	pusha  
c0001e64:	b0 20                	mov    $0x20,%al
c0001e66:	e6 a0                	out    %al,$0xa0
c0001e68:	e6 20                	out    %al,$0x20
c0001e6a:	6a 18                	push   $0x18
c0001e6c:	ff 15 a0 82 00 c0    	call   *0xc00082a0
c0001e72:	e9 49 fd ff ff       	jmp    c0001bc0 <intr_exit>

c0001e77 <intr0x19entry>:
c0001e77:	6a 00                	push   $0x0
c0001e79:	1e                   	push   %ds
c0001e7a:	06                   	push   %es
c0001e7b:	0f a0                	push   %fs
c0001e7d:	0f a8                	push   %gs
c0001e7f:	60                   	pusha  
c0001e80:	b0 20                	mov    $0x20,%al
c0001e82:	e6 a0                	out    %al,$0xa0
c0001e84:	e6 20                	out    %al,$0x20
c0001e86:	6a 19                	push   $0x19
c0001e88:	ff 15 a4 82 00 c0    	call   *0xc00082a4
c0001e8e:	e9 2d fd ff ff       	jmp    c0001bc0 <intr_exit>

c0001e93 <intr0x1aentry>:
c0001e93:	6a 00                	push   $0x0
c0001e95:	1e                   	push   %ds
c0001e96:	06                   	push   %es
c0001e97:	0f a0                	push   %fs
c0001e99:	0f a8                	push   %gs
c0001e9b:	60                   	pusha  
c0001e9c:	b0 20                	mov    $0x20,%al
c0001e9e:	e6 a0                	out    %al,$0xa0
c0001ea0:	e6 20                	out    %al,$0x20
c0001ea2:	6a 1a                	push   $0x1a
c0001ea4:	ff 15 a8 82 00 c0    	call   *0xc00082a8
c0001eaa:	e9 11 fd ff ff       	jmp    c0001bc0 <intr_exit>

c0001eaf <intr0x1bentry>:
c0001eaf:	6a 00                	push   $0x0
c0001eb1:	1e                   	push   %ds
c0001eb2:	06                   	push   %es
c0001eb3:	0f a0                	push   %fs
c0001eb5:	0f a8                	push   %gs
c0001eb7:	60                   	pusha  
c0001eb8:	b0 20                	mov    $0x20,%al
c0001eba:	e6 a0                	out    %al,$0xa0
c0001ebc:	e6 20                	out    %al,$0x20
c0001ebe:	6a 1b                	push   $0x1b
c0001ec0:	ff 15 ac 82 00 c0    	call   *0xc00082ac
c0001ec6:	e9 f5 fc ff ff       	jmp    c0001bc0 <intr_exit>

c0001ecb <intr0x1centry>:
c0001ecb:	6a 00                	push   $0x0
c0001ecd:	1e                   	push   %ds
c0001ece:	06                   	push   %es
c0001ecf:	0f a0                	push   %fs
c0001ed1:	0f a8                	push   %gs
c0001ed3:	60                   	pusha  
c0001ed4:	b0 20                	mov    $0x20,%al
c0001ed6:	e6 a0                	out    %al,$0xa0
c0001ed8:	e6 20                	out    %al,$0x20
c0001eda:	6a 1c                	push   $0x1c
c0001edc:	ff 15 b0 82 00 c0    	call   *0xc00082b0
c0001ee2:	e9 d9 fc ff ff       	jmp    c0001bc0 <intr_exit>

c0001ee7 <intr0x1dentry>:
c0001ee7:	6a 00                	push   $0x0
c0001ee9:	1e                   	push   %ds
c0001eea:	06                   	push   %es
c0001eeb:	0f a0                	push   %fs
c0001eed:	0f a8                	push   %gs
c0001eef:	60                   	pusha  
c0001ef0:	b0 20                	mov    $0x20,%al
c0001ef2:	e6 a0                	out    %al,$0xa0
c0001ef4:	e6 20                	out    %al,$0x20
c0001ef6:	6a 1d                	push   $0x1d
c0001ef8:	ff 15 b4 82 00 c0    	call   *0xc00082b4
c0001efe:	e9 bd fc ff ff       	jmp    c0001bc0 <intr_exit>

c0001f03 <intr0x1eentry>:
c0001f03:	90                   	nop
c0001f04:	1e                   	push   %ds
c0001f05:	06                   	push   %es
c0001f06:	0f a0                	push   %fs
c0001f08:	0f a8                	push   %gs
c0001f0a:	60                   	pusha  
c0001f0b:	b0 20                	mov    $0x20,%al
c0001f0d:	e6 a0                	out    %al,$0xa0
c0001f0f:	e6 20                	out    %al,$0x20
c0001f11:	6a 1e                	push   $0x1e
c0001f13:	ff 15 b8 82 00 c0    	call   *0xc00082b8
c0001f19:	e9 a2 fc ff ff       	jmp    c0001bc0 <intr_exit>

c0001f1e <intr0x1fentry>:
c0001f1e:	6a 00                	push   $0x0
c0001f20:	1e                   	push   %ds
c0001f21:	06                   	push   %es
c0001f22:	0f a0                	push   %fs
c0001f24:	0f a8                	push   %gs
c0001f26:	60                   	pusha  
c0001f27:	b0 20                	mov    $0x20,%al
c0001f29:	e6 a0                	out    %al,$0xa0
c0001f2b:	e6 20                	out    %al,$0x20
c0001f2d:	6a 1f                	push   $0x1f
c0001f2f:	ff 15 bc 82 00 c0    	call   *0xc00082bc
c0001f35:	e9 86 fc ff ff       	jmp    c0001bc0 <intr_exit>

c0001f3a <intr0x20entry>:
c0001f3a:	6a 00                	push   $0x0
c0001f3c:	1e                   	push   %ds
c0001f3d:	06                   	push   %es
c0001f3e:	0f a0                	push   %fs
c0001f40:	0f a8                	push   %gs
c0001f42:	60                   	pusha  
c0001f43:	b0 20                	mov    $0x20,%al
c0001f45:	e6 a0                	out    %al,$0xa0
c0001f47:	e6 20                	out    %al,$0x20
c0001f49:	6a 20                	push   $0x20
c0001f4b:	ff 15 c0 82 00 c0    	call   *0xc00082c0
c0001f51:	e9 6a fc ff ff       	jmp    c0001bc0 <intr_exit>

c0001f56 <intr0x21entry>:
c0001f56:	6a 00                	push   $0x0
c0001f58:	1e                   	push   %ds
c0001f59:	06                   	push   %es
c0001f5a:	0f a0                	push   %fs
c0001f5c:	0f a8                	push   %gs
c0001f5e:	60                   	pusha  
c0001f5f:	b0 20                	mov    $0x20,%al
c0001f61:	e6 a0                	out    %al,$0xa0
c0001f63:	e6 20                	out    %al,$0x20
c0001f65:	6a 21                	push   $0x21
c0001f67:	ff 15 c4 82 00 c0    	call   *0xc00082c4
c0001f6d:	e9 4e fc ff ff       	jmp    c0001bc0 <intr_exit>

c0001f72 <intr0x22entry>:
c0001f72:	6a 00                	push   $0x0
c0001f74:	1e                   	push   %ds
c0001f75:	06                   	push   %es
c0001f76:	0f a0                	push   %fs
c0001f78:	0f a8                	push   %gs
c0001f7a:	60                   	pusha  
c0001f7b:	b0 20                	mov    $0x20,%al
c0001f7d:	e6 a0                	out    %al,$0xa0
c0001f7f:	e6 20                	out    %al,$0x20
c0001f81:	6a 22                	push   $0x22
c0001f83:	ff 15 c8 82 00 c0    	call   *0xc00082c8
c0001f89:	e9 32 fc ff ff       	jmp    c0001bc0 <intr_exit>

c0001f8e <intr0x23entry>:
c0001f8e:	6a 00                	push   $0x0
c0001f90:	1e                   	push   %ds
c0001f91:	06                   	push   %es
c0001f92:	0f a0                	push   %fs
c0001f94:	0f a8                	push   %gs
c0001f96:	60                   	pusha  
c0001f97:	b0 20                	mov    $0x20,%al
c0001f99:	e6 a0                	out    %al,$0xa0
c0001f9b:	e6 20                	out    %al,$0x20
c0001f9d:	6a 23                	push   $0x23
c0001f9f:	ff 15 cc 82 00 c0    	call   *0xc00082cc
c0001fa5:	e9 16 fc ff ff       	jmp    c0001bc0 <intr_exit>

c0001faa <intr0x24entry>:
c0001faa:	6a 00                	push   $0x0
c0001fac:	1e                   	push   %ds
c0001fad:	06                   	push   %es
c0001fae:	0f a0                	push   %fs
c0001fb0:	0f a8                	push   %gs
c0001fb2:	60                   	pusha  
c0001fb3:	b0 20                	mov    $0x20,%al
c0001fb5:	e6 a0                	out    %al,$0xa0
c0001fb7:	e6 20                	out    %al,$0x20
c0001fb9:	6a 24                	push   $0x24
c0001fbb:	ff 15 d0 82 00 c0    	call   *0xc00082d0
c0001fc1:	e9 fa fb ff ff       	jmp    c0001bc0 <intr_exit>

c0001fc6 <intr0x25entry>:
c0001fc6:	6a 00                	push   $0x0
c0001fc8:	1e                   	push   %ds
c0001fc9:	06                   	push   %es
c0001fca:	0f a0                	push   %fs
c0001fcc:	0f a8                	push   %gs
c0001fce:	60                   	pusha  
c0001fcf:	b0 20                	mov    $0x20,%al
c0001fd1:	e6 a0                	out    %al,$0xa0
c0001fd3:	e6 20                	out    %al,$0x20
c0001fd5:	6a 25                	push   $0x25
c0001fd7:	ff 15 d4 82 00 c0    	call   *0xc00082d4
c0001fdd:	e9 de fb ff ff       	jmp    c0001bc0 <intr_exit>

c0001fe2 <intr0x26entry>:
c0001fe2:	6a 00                	push   $0x0
c0001fe4:	1e                   	push   %ds
c0001fe5:	06                   	push   %es
c0001fe6:	0f a0                	push   %fs
c0001fe8:	0f a8                	push   %gs
c0001fea:	60                   	pusha  
c0001feb:	b0 20                	mov    $0x20,%al
c0001fed:	e6 a0                	out    %al,$0xa0
c0001fef:	e6 20                	out    %al,$0x20
c0001ff1:	6a 26                	push   $0x26
c0001ff3:	ff 15 d8 82 00 c0    	call   *0xc00082d8
c0001ff9:	e9 c2 fb ff ff       	jmp    c0001bc0 <intr_exit>

c0001ffe <intr0x27entry>:
c0001ffe:	6a 00                	push   $0x0
c0002000:	1e                   	push   %ds
c0002001:	06                   	push   %es
c0002002:	0f a0                	push   %fs
c0002004:	0f a8                	push   %gs
c0002006:	60                   	pusha  
c0002007:	b0 20                	mov    $0x20,%al
c0002009:	e6 a0                	out    %al,$0xa0
c000200b:	e6 20                	out    %al,$0x20
c000200d:	6a 27                	push   $0x27
c000200f:	ff 15 dc 82 00 c0    	call   *0xc00082dc
c0002015:	e9 a6 fb ff ff       	jmp    c0001bc0 <intr_exit>

c000201a <intr0x28entry>:
c000201a:	6a 00                	push   $0x0
c000201c:	1e                   	push   %ds
c000201d:	06                   	push   %es
c000201e:	0f a0                	push   %fs
c0002020:	0f a8                	push   %gs
c0002022:	60                   	pusha  
c0002023:	b0 20                	mov    $0x20,%al
c0002025:	e6 a0                	out    %al,$0xa0
c0002027:	e6 20                	out    %al,$0x20
c0002029:	6a 28                	push   $0x28
c000202b:	ff 15 e0 82 00 c0    	call   *0xc00082e0
c0002031:	e9 8a fb ff ff       	jmp    c0001bc0 <intr_exit>

c0002036 <intr0x29entry>:
c0002036:	6a 00                	push   $0x0
c0002038:	1e                   	push   %ds
c0002039:	06                   	push   %es
c000203a:	0f a0                	push   %fs
c000203c:	0f a8                	push   %gs
c000203e:	60                   	pusha  
c000203f:	b0 20                	mov    $0x20,%al
c0002041:	e6 a0                	out    %al,$0xa0
c0002043:	e6 20                	out    %al,$0x20
c0002045:	6a 29                	push   $0x29
c0002047:	ff 15 e4 82 00 c0    	call   *0xc00082e4
c000204d:	e9 6e fb ff ff       	jmp    c0001bc0 <intr_exit>

c0002052 <intr0x2aentry>:
c0002052:	6a 00                	push   $0x0
c0002054:	1e                   	push   %ds
c0002055:	06                   	push   %es
c0002056:	0f a0                	push   %fs
c0002058:	0f a8                	push   %gs
c000205a:	60                   	pusha  
c000205b:	b0 20                	mov    $0x20,%al
c000205d:	e6 a0                	out    %al,$0xa0
c000205f:	e6 20                	out    %al,$0x20
c0002061:	6a 2a                	push   $0x2a
c0002063:	ff 15 e8 82 00 c0    	call   *0xc00082e8
c0002069:	e9 52 fb ff ff       	jmp    c0001bc0 <intr_exit>

c000206e <intr0x2bentry>:
c000206e:	6a 00                	push   $0x0
c0002070:	1e                   	push   %ds
c0002071:	06                   	push   %es
c0002072:	0f a0                	push   %fs
c0002074:	0f a8                	push   %gs
c0002076:	60                   	pusha  
c0002077:	b0 20                	mov    $0x20,%al
c0002079:	e6 a0                	out    %al,$0xa0
c000207b:	e6 20                	out    %al,$0x20
c000207d:	6a 2b                	push   $0x2b
c000207f:	ff 15 ec 82 00 c0    	call   *0xc00082ec
c0002085:	e9 36 fb ff ff       	jmp    c0001bc0 <intr_exit>

c000208a <intr0x2centry>:
c000208a:	6a 00                	push   $0x0
c000208c:	1e                   	push   %ds
c000208d:	06                   	push   %es
c000208e:	0f a0                	push   %fs
c0002090:	0f a8                	push   %gs
c0002092:	60                   	pusha  
c0002093:	b0 20                	mov    $0x20,%al
c0002095:	e6 a0                	out    %al,$0xa0
c0002097:	e6 20                	out    %al,$0x20
c0002099:	6a 2c                	push   $0x2c
c000209b:	ff 15 f0 82 00 c0    	call   *0xc00082f0
c00020a1:	e9 1a fb ff ff       	jmp    c0001bc0 <intr_exit>

c00020a6 <intr0x2dentry>:
c00020a6:	6a 00                	push   $0x0
c00020a8:	1e                   	push   %ds
c00020a9:	06                   	push   %es
c00020aa:	0f a0                	push   %fs
c00020ac:	0f a8                	push   %gs
c00020ae:	60                   	pusha  
c00020af:	b0 20                	mov    $0x20,%al
c00020b1:	e6 a0                	out    %al,$0xa0
c00020b3:	e6 20                	out    %al,$0x20
c00020b5:	6a 2d                	push   $0x2d
c00020b7:	ff 15 f4 82 00 c0    	call   *0xc00082f4
c00020bd:	e9 fe fa ff ff       	jmp    c0001bc0 <intr_exit>

c00020c2 <intr0x2eentry>:
c00020c2:	6a 00                	push   $0x0
c00020c4:	1e                   	push   %ds
c00020c5:	06                   	push   %es
c00020c6:	0f a0                	push   %fs
c00020c8:	0f a8                	push   %gs
c00020ca:	60                   	pusha  
c00020cb:	b0 20                	mov    $0x20,%al
c00020cd:	e6 a0                	out    %al,$0xa0
c00020cf:	e6 20                	out    %al,$0x20
c00020d1:	6a 2e                	push   $0x2e
c00020d3:	ff 15 f8 82 00 c0    	call   *0xc00082f8
c00020d9:	e9 e2 fa ff ff       	jmp    c0001bc0 <intr_exit>

c00020de <intr0x2fentry>:
c00020de:	6a 00                	push   $0x0
c00020e0:	1e                   	push   %ds
c00020e1:	06                   	push   %es
c00020e2:	0f a0                	push   %fs
c00020e4:	0f a8                	push   %gs
c00020e6:	60                   	pusha  
c00020e7:	b0 20                	mov    $0x20,%al
c00020e9:	e6 a0                	out    %al,$0xa0
c00020eb:	e6 20                	out    %al,$0x20
c00020ed:	6a 2f                	push   $0x2f
c00020ef:	ff 15 fc 82 00 c0    	call   *0xc00082fc
c00020f5:	e9 c6 fa ff ff       	jmp    c0001bc0 <intr_exit>

c00020fa <outb>:
static inline void outb(uint16_t port, uint8_t data) {
c00020fa:	55                   	push   %ebp
c00020fb:	89 e5                	mov    %esp,%ebp
c00020fd:	83 ec 08             	sub    $0x8,%esp
c0002100:	8b 45 08             	mov    0x8(%ebp),%eax
c0002103:	8b 55 0c             	mov    0xc(%ebp),%edx
c0002106:	66 89 45 fc          	mov    %ax,-0x4(%ebp)
c000210a:	89 d0                	mov    %edx,%eax
c000210c:	88 45 f8             	mov    %al,-0x8(%ebp)
  asm volatile("outb %b0, %w1" ::"a"(data), "Nd"(port));
c000210f:	0f b6 45 f8          	movzbl -0x8(%ebp),%eax
c0002113:	0f b7 55 fc          	movzwl -0x4(%ebp),%edx
c0002117:	ee                   	out    %al,(%dx)
}
c0002118:	90                   	nop
c0002119:	c9                   	leave  
c000211a:	c3                   	ret    

c000211b <frequency_set>:
#define PIT_CONTROL_PORT 0x43

uint32_t ticks; // 内核发生的总中断次数（系统运行时长）

static void frequency_set(uint8_t counter_port, uint8_t counter_no, uint8_t rwl,
                          uint8_t counter_mode, uint16_t counter_value) {
c000211b:	55                   	push   %ebp
c000211c:	89 e5                	mov    %esp,%ebp
c000211e:	57                   	push   %edi
c000211f:	56                   	push   %esi
c0002120:	53                   	push   %ebx
c0002121:	83 ec 14             	sub    $0x14,%esp
c0002124:	8b 75 08             	mov    0x8(%ebp),%esi
c0002127:	8b 5d 0c             	mov    0xc(%ebp),%ebx
c000212a:	8b 4d 10             	mov    0x10(%ebp),%ecx
c000212d:	8b 55 14             	mov    0x14(%ebp),%edx
c0002130:	8b 7d 18             	mov    0x18(%ebp),%edi
c0002133:	89 f0                	mov    %esi,%eax
c0002135:	88 45 f0             	mov    %al,-0x10(%ebp)
c0002138:	88 5d ec             	mov    %bl,-0x14(%ebp)
c000213b:	88 4d e8             	mov    %cl,-0x18(%ebp)
c000213e:	88 55 e4             	mov    %dl,-0x1c(%ebp)
c0002141:	89 f8                	mov    %edi,%eax
c0002143:	66 89 45 e0          	mov    %ax,-0x20(%ebp)
  // 往控制字寄存器端口0x43中写入控制字
  outb(PIT_CONTROL_PORT,
       (uint8_t)(counter_no << 6 | rwl << 4 | counter_mode << 1));
c0002147:	0f b6 45 ec          	movzbl -0x14(%ebp),%eax
c000214b:	c1 e0 06             	shl    $0x6,%eax
c000214e:	89 c2                	mov    %eax,%edx
c0002150:	0f b6 45 e8          	movzbl -0x18(%ebp),%eax
c0002154:	c1 e0 04             	shl    $0x4,%eax
c0002157:	09 c2                	or     %eax,%edx
c0002159:	0f b6 45 e4          	movzbl -0x1c(%ebp),%eax
c000215d:	01 c0                	add    %eax,%eax
c000215f:	09 d0                	or     %edx,%eax
  outb(PIT_CONTROL_PORT,
c0002161:	0f b6 c0             	movzbl %al,%eax
c0002164:	50                   	push   %eax
c0002165:	6a 43                	push   $0x43
c0002167:	e8 8e ff ff ff       	call   c00020fa <outb>
c000216c:	83 c4 08             	add    $0x8,%esp
  // 先写入counter_value低8位，再写高8位
  outb(counter_port, (uint8_t)counter_value);
c000216f:	0f b7 45 e0          	movzwl -0x20(%ebp),%eax
c0002173:	0f b6 d0             	movzbl %al,%edx
c0002176:	0f b6 45 f0          	movzbl -0x10(%ebp),%eax
c000217a:	52                   	push   %edx
c000217b:	50                   	push   %eax
c000217c:	e8 79 ff ff ff       	call   c00020fa <outb>
c0002181:	83 c4 08             	add    $0x8,%esp
  outb(counter_port, (uint8_t)counter_value >> 8);
c0002184:	0f b7 45 e0          	movzwl -0x20(%ebp),%eax
c0002188:	0f b6 c0             	movzbl %al,%eax
c000218b:	c1 f8 08             	sar    $0x8,%eax
c000218e:	0f b6 d0             	movzbl %al,%edx
c0002191:	0f b6 45 f0          	movzbl -0x10(%ebp),%eax
c0002195:	52                   	push   %edx
c0002196:	50                   	push   %eax
c0002197:	e8 5e ff ff ff       	call   c00020fa <outb>
c000219c:	83 c4 08             	add    $0x8,%esp
}
c000219f:	90                   	nop
c00021a0:	8d 65 f4             	lea    -0xc(%ebp),%esp
c00021a3:	5b                   	pop    %ebx
c00021a4:	5e                   	pop    %esi
c00021a5:	5f                   	pop    %edi
c00021a6:	5d                   	pop    %ebp
c00021a7:	c3                   	ret    

c00021a8 <intr_timer_handler>:

// 时钟中断处理函数
static void intr_timer_handler(void) {
c00021a8:	55                   	push   %ebp
c00021a9:	89 e5                	mov    %esp,%ebp
c00021ab:	83 ec 18             	sub    $0x18,%esp
  struct task_struct *cur_thread = running_thread();
c00021ae:	e8 8f 0f 00 00       	call   c0003142 <running_thread>
c00021b3:	89 45 f4             	mov    %eax,-0xc(%ebp)
  ASSERT(cur_thread->stack_magic == 0x20021112);
c00021b6:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00021b9:	8b 40 40             	mov    0x40(%eax),%eax
c00021bc:	3d 12 11 02 20       	cmp    $0x20021112,%eax
c00021c1:	74 19                	je     c00021dc <intr_timer_handler+0x34>
c00021c3:	68 30 53 00 c0       	push   $0xc0005330
c00021c8:	68 88 53 00 c0       	push   $0xc0005388
c00021cd:	6a 20                	push   $0x20
c00021cf:	68 56 53 00 c0       	push   $0xc0005356
c00021d4:	e8 97 00 00 00       	call   c0002270 <panic_spin>
c00021d9:	83 c4 10             	add    $0x10,%esp
  cur_thread->elapsed_ticks++; // 记录此线程占用cpu时间
c00021dc:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00021df:	8b 40 1c             	mov    0x1c(%eax),%eax
c00021e2:	8d 50 01             	lea    0x1(%eax),%edx
c00021e5:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00021e8:	89 50 1c             	mov    %edx,0x1c(%eax)
  ticks++;
c00021eb:	a1 80 84 00 c0       	mov    0xc0008480,%eax
c00021f0:	83 c0 01             	add    $0x1,%eax
c00021f3:	a3 80 84 00 c0       	mov    %eax,0xc0008480

  if (cur_thread->ticks == 0) { // 时间片用完，调度新进程上cpu
c00021f8:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00021fb:	0f b6 40 19          	movzbl 0x19(%eax),%eax
c00021ff:	84 c0                	test   %al,%al
c0002201:	75 07                	jne    c000220a <intr_timer_handler+0x62>
    schedule();
c0002203:	e8 c8 11 00 00       	call   c00033d0 <schedule>
  } else {
    cur_thread->ticks--;
  }
}
c0002208:	eb 10                	jmp    c000221a <intr_timer_handler+0x72>
    cur_thread->ticks--;
c000220a:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000220d:	0f b6 40 19          	movzbl 0x19(%eax),%eax
c0002211:	8d 50 ff             	lea    -0x1(%eax),%edx
c0002214:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002217:	88 50 19             	mov    %dl,0x19(%eax)
}
c000221a:	90                   	nop
c000221b:	c9                   	leave  
c000221c:	c3                   	ret    

c000221d <timer_init>:

// 初始化PIT8253
void timer_init() {
c000221d:	55                   	push   %ebp
c000221e:	89 e5                	mov    %esp,%ebp
c0002220:	83 ec 08             	sub    $0x8,%esp
  put_str("timer_init start\n");
c0002223:	83 ec 0c             	sub    $0xc,%esp
c0002226:	68 65 53 00 c0       	push   $0xc0005365
c000222b:	e8 40 f8 ff ff       	call   c0001a70 <put_str>
c0002230:	83 c4 10             	add    $0x10,%esp
  // 设置8253定时周期-> 发中断周期
  frequency_set(CONTRER0_PORT, COUNTER0_NO, READ_WRITE_LATCH, COUNTER_MODE,
c0002233:	83 ec 0c             	sub    $0xc,%esp
c0002236:	68 9b 2e 00 00       	push   $0x2e9b
c000223b:	6a 02                	push   $0x2
c000223d:	6a 03                	push   $0x3
c000223f:	6a 00                	push   $0x0
c0002241:	6a 40                	push   $0x40
c0002243:	e8 d3 fe ff ff       	call   c000211b <frequency_set>
c0002248:	83 c4 20             	add    $0x20,%esp
                COUNTER0_VALUE);
  register_handler(0x20, intr_timer_handler); // 注册时钟中断处理函数
c000224b:	83 ec 08             	sub    $0x8,%esp
c000224e:	68 a8 21 00 c0       	push   $0xc00021a8
c0002253:	6a 20                	push   $0x20
c0002255:	e8 5c f7 ff ff       	call   c00019b6 <register_handler>
c000225a:	83 c4 10             	add    $0x10,%esp
  put_str("timer_init done\n");
c000225d:	83 ec 0c             	sub    $0xc,%esp
c0002260:	68 77 53 00 c0       	push   $0xc0005377
c0002265:	e8 06 f8 ff ff       	call   c0001a70 <put_str>
c000226a:	83 c4 10             	add    $0x10,%esp
c000226d:	90                   	nop
c000226e:	c9                   	leave  
c000226f:	c3                   	ret    

c0002270 <panic_spin>:
#include "interrupt.h"
#include "print.h"

// 打印文件名、行号、函数名、条件并使程序悬停
void panic_spin(char *filename, int line, const char *func,
                const char *condition) {
c0002270:	55                   	push   %ebp
c0002271:	89 e5                	mov    %esp,%ebp
c0002273:	83 ec 08             	sub    $0x8,%esp
  intr_disable(); // 因为有时候会单独调用 panic_spin，所以在此处关中断
c0002276:	e8 12 f7 ff ff       	call   c000198d <intr_disable>
  put_str("\n\n\n!!!!! error !!!!!\n");
c000227b:	83 ec 0c             	sub    $0xc,%esp
c000227e:	68 9b 53 00 c0       	push   $0xc000539b
c0002283:	e8 e8 f7 ff ff       	call   c0001a70 <put_str>
c0002288:	83 c4 10             	add    $0x10,%esp
  put_str("filename:");
c000228b:	83 ec 0c             	sub    $0xc,%esp
c000228e:	68 b1 53 00 c0       	push   $0xc00053b1
c0002293:	e8 d8 f7 ff ff       	call   c0001a70 <put_str>
c0002298:	83 c4 10             	add    $0x10,%esp
  put_str(filename);
c000229b:	83 ec 0c             	sub    $0xc,%esp
c000229e:	ff 75 08             	push   0x8(%ebp)
c00022a1:	e8 ca f7 ff ff       	call   c0001a70 <put_str>
c00022a6:	83 c4 10             	add    $0x10,%esp
  put_str("\n");
c00022a9:	83 ec 0c             	sub    $0xc,%esp
c00022ac:	68 bb 53 00 c0       	push   $0xc00053bb
c00022b1:	e8 ba f7 ff ff       	call   c0001a70 <put_str>
c00022b6:	83 c4 10             	add    $0x10,%esp

  put_str("line:0x");
c00022b9:	83 ec 0c             	sub    $0xc,%esp
c00022bc:	68 bd 53 00 c0       	push   $0xc00053bd
c00022c1:	e8 aa f7 ff ff       	call   c0001a70 <put_str>
c00022c6:	83 c4 10             	add    $0x10,%esp
  put_int(line);
c00022c9:	8b 45 0c             	mov    0xc(%ebp),%eax
c00022cc:	83 ec 0c             	sub    $0xc,%esp
c00022cf:	50                   	push   %eax
c00022d0:	e8 87 f8 ff ff       	call   c0001b5c <put_int>
c00022d5:	83 c4 10             	add    $0x10,%esp
  put_str("\n");
c00022d8:	83 ec 0c             	sub    $0xc,%esp
c00022db:	68 bb 53 00 c0       	push   $0xc00053bb
c00022e0:	e8 8b f7 ff ff       	call   c0001a70 <put_str>
c00022e5:	83 c4 10             	add    $0x10,%esp

  put_str("function:");
c00022e8:	83 ec 0c             	sub    $0xc,%esp
c00022eb:	68 c5 53 00 c0       	push   $0xc00053c5
c00022f0:	e8 7b f7 ff ff       	call   c0001a70 <put_str>
c00022f5:	83 c4 10             	add    $0x10,%esp
  put_str((char *)func);
c00022f8:	83 ec 0c             	sub    $0xc,%esp
c00022fb:	ff 75 10             	push   0x10(%ebp)
c00022fe:	e8 6d f7 ff ff       	call   c0001a70 <put_str>
c0002303:	83 c4 10             	add    $0x10,%esp
  put_str("\n");
c0002306:	83 ec 0c             	sub    $0xc,%esp
c0002309:	68 bb 53 00 c0       	push   $0xc00053bb
c000230e:	e8 5d f7 ff ff       	call   c0001a70 <put_str>
c0002313:	83 c4 10             	add    $0x10,%esp

  put_str("condition:");
c0002316:	83 ec 0c             	sub    $0xc,%esp
c0002319:	68 cf 53 00 c0       	push   $0xc00053cf
c000231e:	e8 4d f7 ff ff       	call   c0001a70 <put_str>
c0002323:	83 c4 10             	add    $0x10,%esp
  put_str((char *)condition);
c0002326:	83 ec 0c             	sub    $0xc,%esp
c0002329:	ff 75 14             	push   0x14(%ebp)
c000232c:	e8 3f f7 ff ff       	call   c0001a70 <put_str>
c0002331:	83 c4 10             	add    $0x10,%esp
  put_str("\n");
c0002334:	83 ec 0c             	sub    $0xc,%esp
c0002337:	68 bb 53 00 c0       	push   $0xc00053bb
c000233c:	e8 2f f7 ff ff       	call   c0001a70 <put_str>
c0002341:	83 c4 10             	add    $0x10,%esp
  while (1) {
c0002344:	eb fe                	jmp    c0002344 <panic_spin+0xd4>

c0002346 <memset>:
#include "debug.h"
#include "global.h"

// 内存区域的数据初始化（内存分配时的数据清零）=>
// 将dst_起始的size个字节置为value
void memset(void *dst_, uint8_t value, uint32_t size) {
c0002346:	55                   	push   %ebp
c0002347:	89 e5                	mov    %esp,%ebp
c0002349:	83 ec 28             	sub    $0x28,%esp
c000234c:	8b 45 0c             	mov    0xc(%ebp),%eax
c000234f:	88 45 e4             	mov    %al,-0x1c(%ebp)
  ASSERT(dst_ != NULL);
c0002352:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c0002356:	75 19                	jne    c0002371 <memset+0x2b>
c0002358:	68 dc 53 00 c0       	push   $0xc00053dc
c000235d:	68 38 54 00 c0       	push   $0xc0005438
c0002362:	6a 08                	push   $0x8
c0002364:	68 e9 53 00 c0       	push   $0xc00053e9
c0002369:	e8 02 ff ff ff       	call   c0002270 <panic_spin>
c000236e:	83 c4 10             	add    $0x10,%esp
  uint8_t *dst = (uint8_t *)dst_;
c0002371:	8b 45 08             	mov    0x8(%ebp),%eax
c0002374:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while (size-- > 0) {
c0002377:	eb 0f                	jmp    c0002388 <memset+0x42>
    *dst++ = value;
c0002379:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000237c:	8d 50 01             	lea    0x1(%eax),%edx
c000237f:	89 55 f4             	mov    %edx,-0xc(%ebp)
c0002382:	0f b6 55 e4          	movzbl -0x1c(%ebp),%edx
c0002386:	88 10                	mov    %dl,(%eax)
  while (size-- > 0) {
c0002388:	8b 45 10             	mov    0x10(%ebp),%eax
c000238b:	8d 50 ff             	lea    -0x1(%eax),%edx
c000238e:	89 55 10             	mov    %edx,0x10(%ebp)
c0002391:	85 c0                	test   %eax,%eax
c0002393:	75 e4                	jne    c0002379 <memset+0x33>
  }
}
c0002395:	90                   	nop
c0002396:	90                   	nop
c0002397:	c9                   	leave  
c0002398:	c3                   	ret    

c0002399 <memcpy>:

// 内存数据拷贝=> 终止条件：size
// 将src_起始的size个字节复制到dst_
void memcpy(void *dst_, const void *src_, uint32_t size) {
c0002399:	55                   	push   %ebp
c000239a:	89 e5                	mov    %esp,%ebp
c000239c:	83 ec 18             	sub    $0x18,%esp
  ASSERT(dst_ != NULL && src_ != NULL);
c000239f:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c00023a3:	74 06                	je     c00023ab <memcpy+0x12>
c00023a5:	83 7d 0c 00          	cmpl   $0x0,0xc(%ebp)
c00023a9:	75 19                	jne    c00023c4 <memcpy+0x2b>
c00023ab:	68 f6 53 00 c0       	push   $0xc00053f6
c00023b0:	68 40 54 00 c0       	push   $0xc0005440
c00023b5:	6a 12                	push   $0x12
c00023b7:	68 e9 53 00 c0       	push   $0xc00053e9
c00023bc:	e8 af fe ff ff       	call   c0002270 <panic_spin>
c00023c1:	83 c4 10             	add    $0x10,%esp
  uint8_t *dst = dst_;
c00023c4:	8b 45 08             	mov    0x8(%ebp),%eax
c00023c7:	89 45 f4             	mov    %eax,-0xc(%ebp)
  const uint8_t *src = src_;
c00023ca:	8b 45 0c             	mov    0xc(%ebp),%eax
c00023cd:	89 45 f0             	mov    %eax,-0x10(%ebp)
  while (size-- > 0) {
c00023d0:	eb 17                	jmp    c00023e9 <memcpy+0x50>
    *dst++ = *src++;
c00023d2:	8b 55 f0             	mov    -0x10(%ebp),%edx
c00023d5:	8d 42 01             	lea    0x1(%edx),%eax
c00023d8:	89 45 f0             	mov    %eax,-0x10(%ebp)
c00023db:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00023de:	8d 48 01             	lea    0x1(%eax),%ecx
c00023e1:	89 4d f4             	mov    %ecx,-0xc(%ebp)
c00023e4:	0f b6 12             	movzbl (%edx),%edx
c00023e7:	88 10                	mov    %dl,(%eax)
  while (size-- > 0) {
c00023e9:	8b 45 10             	mov    0x10(%ebp),%eax
c00023ec:	8d 50 ff             	lea    -0x1(%eax),%edx
c00023ef:	89 55 10             	mov    %edx,0x10(%ebp)
c00023f2:	85 c0                	test   %eax,%eax
c00023f4:	75 dc                	jne    c00023d2 <memcpy+0x39>
  }
}
c00023f6:	90                   	nop
c00023f7:	90                   	nop
c00023f8:	c9                   	leave  
c00023f9:	c3                   	ret    

c00023fa <memcmp>:

// 用于一段内存数据比较=>
// 连续比较以地址a_和b_开头的size个字节，相等返回0，a_>b_返回+1，否则返回−1
int memcmp(const void *a_, const void *b_, uint32_t size) {
c00023fa:	55                   	push   %ebp
c00023fb:	89 e5                	mov    %esp,%ebp
c00023fd:	83 ec 18             	sub    $0x18,%esp
  const char *a = a_;
c0002400:	8b 45 08             	mov    0x8(%ebp),%eax
c0002403:	89 45 f4             	mov    %eax,-0xc(%ebp)
  const char *b = b_;
c0002406:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002409:	89 45 f0             	mov    %eax,-0x10(%ebp)
  ASSERT(a != NULL && b != NULL);
c000240c:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
c0002410:	74 06                	je     c0002418 <memcmp+0x1e>
c0002412:	83 7d f0 00          	cmpl   $0x0,-0x10(%ebp)
c0002416:	75 19                	jne    c0002431 <memcmp+0x37>
c0002418:	68 13 54 00 c0       	push   $0xc0005413
c000241d:	68 48 54 00 c0       	push   $0xc0005448
c0002422:	6a 1f                	push   $0x1f
c0002424:	68 e9 53 00 c0       	push   $0xc00053e9
c0002429:	e8 42 fe ff ff       	call   c0002270 <panic_spin>
c000242e:	83 c4 10             	add    $0x10,%esp
  while (size-- > 0) {
c0002431:	eb 36                	jmp    c0002469 <memcmp+0x6f>
    if (*a != *b) {
c0002433:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002436:	0f b6 10             	movzbl (%eax),%edx
c0002439:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000243c:	0f b6 00             	movzbl (%eax),%eax
c000243f:	38 c2                	cmp    %al,%dl
c0002441:	74 1e                	je     c0002461 <memcmp+0x67>
      return *a > *b ? 1 : -1;
c0002443:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002446:	0f b6 10             	movzbl (%eax),%edx
c0002449:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000244c:	0f b6 00             	movzbl (%eax),%eax
c000244f:	38 c2                	cmp    %al,%dl
c0002451:	7e 07                	jle    c000245a <memcmp+0x60>
c0002453:	b8 01 00 00 00       	mov    $0x1,%eax
c0002458:	eb 21                	jmp    c000247b <memcmp+0x81>
c000245a:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000245f:	eb 1a                	jmp    c000247b <memcmp+0x81>
    }
    a++;
c0002461:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
    b++;
c0002465:	83 45 f0 01          	addl   $0x1,-0x10(%ebp)
  while (size-- > 0) {
c0002469:	8b 45 10             	mov    0x10(%ebp),%eax
c000246c:	8d 50 ff             	lea    -0x1(%eax),%edx
c000246f:	89 55 10             	mov    %edx,0x10(%ebp)
c0002472:	85 c0                	test   %eax,%eax
c0002474:	75 bd                	jne    c0002433 <memcmp+0x39>
  }
  return 0;
c0002476:	b8 00 00 00 00       	mov    $0x0,%eax
}
c000247b:	c9                   	leave  
c000247c:	c3                   	ret    

c000247d <strcpy>:

// 字符串拷贝=> 终止条件：src_处的字符‘0’
// 将字符串从src_复制到dst_
char *strcpy(char *dst_, const char *src_) {
c000247d:	55                   	push   %ebp
c000247e:	89 e5                	mov    %esp,%ebp
c0002480:	83 ec 18             	sub    $0x18,%esp
  ASSERT(dst_ != NULL && src_ != NULL);
c0002483:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c0002487:	74 06                	je     c000248f <strcpy+0x12>
c0002489:	83 7d 0c 00          	cmpl   $0x0,0xc(%ebp)
c000248d:	75 19                	jne    c00024a8 <strcpy+0x2b>
c000248f:	68 f6 53 00 c0       	push   $0xc00053f6
c0002494:	68 50 54 00 c0       	push   $0xc0005450
c0002499:	6a 2d                	push   $0x2d
c000249b:	68 e9 53 00 c0       	push   $0xc00053e9
c00024a0:	e8 cb fd ff ff       	call   c0002270 <panic_spin>
c00024a5:	83 c4 10             	add    $0x10,%esp
  char *r = dst_; // 用来返回目的字符串dst_起始地址
c00024a8:	8b 45 08             	mov    0x8(%ebp),%eax
c00024ab:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while ((*dst_++ = *src_++))
c00024ae:	90                   	nop
c00024af:	8b 55 0c             	mov    0xc(%ebp),%edx
c00024b2:	8d 42 01             	lea    0x1(%edx),%eax
c00024b5:	89 45 0c             	mov    %eax,0xc(%ebp)
c00024b8:	8b 45 08             	mov    0x8(%ebp),%eax
c00024bb:	8d 48 01             	lea    0x1(%eax),%ecx
c00024be:	89 4d 08             	mov    %ecx,0x8(%ebp)
c00024c1:	0f b6 12             	movzbl (%edx),%edx
c00024c4:	88 10                	mov    %dl,(%eax)
c00024c6:	0f b6 00             	movzbl (%eax),%eax
c00024c9:	84 c0                	test   %al,%al
c00024cb:	75 e2                	jne    c00024af <strcpy+0x32>
    ;
  return r;
c00024cd:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c00024d0:	c9                   	leave  
c00024d1:	c3                   	ret    

c00024d2 <strlen>:

// 返回字符串长度
uint32_t strlen(const char *str) {
c00024d2:	55                   	push   %ebp
c00024d3:	89 e5                	mov    %esp,%ebp
c00024d5:	83 ec 18             	sub    $0x18,%esp
  ASSERT(str != NULL);
c00024d8:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c00024dc:	75 19                	jne    c00024f7 <strlen+0x25>
c00024de:	68 2a 54 00 c0       	push   $0xc000542a
c00024e3:	68 58 54 00 c0       	push   $0xc0005458
c00024e8:	6a 36                	push   $0x36
c00024ea:	68 e9 53 00 c0       	push   $0xc00053e9
c00024ef:	e8 7c fd ff ff       	call   c0002270 <panic_spin>
c00024f4:	83 c4 10             	add    $0x10,%esp
  const char *p = str;
c00024f7:	8b 45 08             	mov    0x8(%ebp),%eax
c00024fa:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while (*p++)
c00024fd:	90                   	nop
c00024fe:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002501:	8d 50 01             	lea    0x1(%eax),%edx
c0002504:	89 55 f4             	mov    %edx,-0xc(%ebp)
c0002507:	0f b6 00             	movzbl (%eax),%eax
c000250a:	84 c0                	test   %al,%al
c000250c:	75 f0                	jne    c00024fe <strlen+0x2c>
    ;
  return (p - str - 1);
c000250e:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002511:	2b 45 08             	sub    0x8(%ebp),%eax
c0002514:	83 e8 01             	sub    $0x1,%eax
}
c0002517:	c9                   	leave  
c0002518:	c3                   	ret    

c0002519 <strcmp>:

// 比较两个字符串，若a_中字符大于b_返回1，相等返回0，否则返回−1
uint8_t strcmp(const char *a, const char *b) {
c0002519:	55                   	push   %ebp
c000251a:	89 e5                	mov    %esp,%ebp
c000251c:	83 ec 08             	sub    $0x8,%esp
  ASSERT(a != NULL && b != NULL);
c000251f:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c0002523:	74 06                	je     c000252b <strcmp+0x12>
c0002525:	83 7d 0c 00          	cmpl   $0x0,0xc(%ebp)
c0002529:	75 19                	jne    c0002544 <strcmp+0x2b>
c000252b:	68 13 54 00 c0       	push   $0xc0005413
c0002530:	68 60 54 00 c0       	push   $0xc0005460
c0002535:	6a 3f                	push   $0x3f
c0002537:	68 e9 53 00 c0       	push   $0xc00053e9
c000253c:	e8 2f fd ff ff       	call   c0002270 <panic_spin>
c0002541:	83 c4 10             	add    $0x10,%esp
  while (*a != 0 && *a == *b) {
c0002544:	eb 08                	jmp    c000254e <strcmp+0x35>
    a++;
c0002546:	83 45 08 01          	addl   $0x1,0x8(%ebp)
    b++;
c000254a:	83 45 0c 01          	addl   $0x1,0xc(%ebp)
  while (*a != 0 && *a == *b) {
c000254e:	8b 45 08             	mov    0x8(%ebp),%eax
c0002551:	0f b6 00             	movzbl (%eax),%eax
c0002554:	84 c0                	test   %al,%al
c0002556:	74 10                	je     c0002568 <strcmp+0x4f>
c0002558:	8b 45 08             	mov    0x8(%ebp),%eax
c000255b:	0f b6 10             	movzbl (%eax),%edx
c000255e:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002561:	0f b6 00             	movzbl (%eax),%eax
c0002564:	38 c2                	cmp    %al,%dl
c0002566:	74 de                	je     c0002546 <strcmp+0x2d>
  }
  return *a < *b ? -1 : *a > *b;
c0002568:	8b 45 08             	mov    0x8(%ebp),%eax
c000256b:	0f b6 10             	movzbl (%eax),%edx
c000256e:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002571:	0f b6 00             	movzbl (%eax),%eax
c0002574:	38 c2                	cmp    %al,%dl
c0002576:	7c 13                	jl     c000258b <strcmp+0x72>
c0002578:	8b 45 08             	mov    0x8(%ebp),%eax
c000257b:	0f b6 10             	movzbl (%eax),%edx
c000257e:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002581:	0f b6 00             	movzbl (%eax),%eax
c0002584:	38 c2                	cmp    %al,%dl
c0002586:	0f 9f c0             	setg   %al
c0002589:	eb 05                	jmp    c0002590 <strcmp+0x77>
c000258b:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
}
c0002590:	c9                   	leave  
c0002591:	c3                   	ret    

c0002592 <strchr>:

// 从左到右 查找字符串str中首次出现字符ch的地址
char *strchr(const char *str, const uint8_t ch) {
c0002592:	55                   	push   %ebp
c0002593:	89 e5                	mov    %esp,%ebp
c0002595:	83 ec 18             	sub    $0x18,%esp
c0002598:	8b 45 0c             	mov    0xc(%ebp),%eax
c000259b:	88 45 f4             	mov    %al,-0xc(%ebp)
  ASSERT(str != NULL);
c000259e:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c00025a2:	75 35                	jne    c00025d9 <strchr+0x47>
c00025a4:	68 2a 54 00 c0       	push   $0xc000542a
c00025a9:	68 68 54 00 c0       	push   $0xc0005468
c00025ae:	6a 49                	push   $0x49
c00025b0:	68 e9 53 00 c0       	push   $0xc00053e9
c00025b5:	e8 b6 fc ff ff       	call   c0002270 <panic_spin>
c00025ba:	83 c4 10             	add    $0x10,%esp
  while (*str != 0) {
c00025bd:	eb 1a                	jmp    c00025d9 <strchr+0x47>
    if (*str == ch) {
c00025bf:	8b 45 08             	mov    0x8(%ebp),%eax
c00025c2:	0f b6 00             	movzbl (%eax),%eax
c00025c5:	0f be d0             	movsbl %al,%edx
c00025c8:	0f b6 45 f4          	movzbl -0xc(%ebp),%eax
c00025cc:	39 c2                	cmp    %eax,%edx
c00025ce:	75 05                	jne    c00025d5 <strchr+0x43>
      return (char *)str;
c00025d0:	8b 45 08             	mov    0x8(%ebp),%eax
c00025d3:	eb 13                	jmp    c00025e8 <strchr+0x56>
    }
    str++;
c00025d5:	83 45 08 01          	addl   $0x1,0x8(%ebp)
  while (*str != 0) {
c00025d9:	8b 45 08             	mov    0x8(%ebp),%eax
c00025dc:	0f b6 00             	movzbl (%eax),%eax
c00025df:	84 c0                	test   %al,%al
c00025e1:	75 dc                	jne    c00025bf <strchr+0x2d>
  }
  return NULL;
c00025e3:	b8 00 00 00 00       	mov    $0x0,%eax
}
c00025e8:	c9                   	leave  
c00025e9:	c3                   	ret    

c00025ea <strrchr>:

// 从后往前 查找字符串str中最后一次出现字符ch的地址
char *strrchr(const char *str, const uint8_t ch) {
c00025ea:	55                   	push   %ebp
c00025eb:	89 e5                	mov    %esp,%ebp
c00025ed:	83 ec 28             	sub    $0x28,%esp
c00025f0:	8b 45 0c             	mov    0xc(%ebp),%eax
c00025f3:	88 45 e4             	mov    %al,-0x1c(%ebp)
  ASSERT(str != NULL);
c00025f6:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c00025fa:	75 19                	jne    c0002615 <strrchr+0x2b>
c00025fc:	68 2a 54 00 c0       	push   $0xc000542a
c0002601:	68 70 54 00 c0       	push   $0xc0005470
c0002606:	6a 55                	push   $0x55
c0002608:	68 e9 53 00 c0       	push   $0xc00053e9
c000260d:	e8 5e fc ff ff       	call   c0002270 <panic_spin>
c0002612:	83 c4 10             	add    $0x10,%esp
  const char *last_char = NULL;
c0002615:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  while (*str != 0) {
c000261c:	eb 1b                	jmp    c0002639 <strrchr+0x4f>
    if (*str == ch) {
c000261e:	8b 45 08             	mov    0x8(%ebp),%eax
c0002621:	0f b6 00             	movzbl (%eax),%eax
c0002624:	0f be d0             	movsbl %al,%edx
c0002627:	0f b6 45 e4          	movzbl -0x1c(%ebp),%eax
c000262b:	39 c2                	cmp    %eax,%edx
c000262d:	75 06                	jne    c0002635 <strrchr+0x4b>
      last_char = str;
c000262f:	8b 45 08             	mov    0x8(%ebp),%eax
c0002632:	89 45 f4             	mov    %eax,-0xc(%ebp)
    }
    str++;
c0002635:	83 45 08 01          	addl   $0x1,0x8(%ebp)
  while (*str != 0) {
c0002639:	8b 45 08             	mov    0x8(%ebp),%eax
c000263c:	0f b6 00             	movzbl (%eax),%eax
c000263f:	84 c0                	test   %al,%al
c0002641:	75 db                	jne    c000261e <strrchr+0x34>
  }
  return (char *)last_char;
c0002643:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0002646:	c9                   	leave  
c0002647:	c3                   	ret    

c0002648 <strcat>:

// 字符串拼接=>
// 将字符串src_拼接到dst_后，返回dst_地址
char *strcat(char *dst_, const char *src_) {
c0002648:	55                   	push   %ebp
c0002649:	89 e5                	mov    %esp,%ebp
c000264b:	83 ec 18             	sub    $0x18,%esp
  ASSERT(dst_ != NULL && src_ != NULL);
c000264e:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c0002652:	74 06                	je     c000265a <strcat+0x12>
c0002654:	83 7d 0c 00          	cmpl   $0x0,0xc(%ebp)
c0002658:	75 19                	jne    c0002673 <strcat+0x2b>
c000265a:	68 f6 53 00 c0       	push   $0xc00053f6
c000265f:	68 78 54 00 c0       	push   $0xc0005478
c0002664:	6a 63                	push   $0x63
c0002666:	68 e9 53 00 c0       	push   $0xc00053e9
c000266b:	e8 00 fc ff ff       	call   c0002270 <panic_spin>
c0002670:	83 c4 10             	add    $0x10,%esp
  char *str = dst_;
c0002673:	8b 45 08             	mov    0x8(%ebp),%eax
c0002676:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while (*str++)
c0002679:	90                   	nop
c000267a:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000267d:	8d 50 01             	lea    0x1(%eax),%edx
c0002680:	89 55 f4             	mov    %edx,-0xc(%ebp)
c0002683:	0f b6 00             	movzbl (%eax),%eax
c0002686:	84 c0                	test   %al,%al
c0002688:	75 f0                	jne    c000267a <strcat+0x32>
    ;
  --str;
c000268a:	83 6d f4 01          	subl   $0x1,-0xc(%ebp)
  while ((*str++ = *src_++)) // 当*str被赋值0时
c000268e:	90                   	nop
c000268f:	8b 55 0c             	mov    0xc(%ebp),%edx
c0002692:	8d 42 01             	lea    0x1(%edx),%eax
c0002695:	89 45 0c             	mov    %eax,0xc(%ebp)
c0002698:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000269b:	8d 48 01             	lea    0x1(%eax),%ecx
c000269e:	89 4d f4             	mov    %ecx,-0xc(%ebp)
c00026a1:	0f b6 12             	movzbl (%edx),%edx
c00026a4:	88 10                	mov    %dl,(%eax)
c00026a6:	0f b6 00             	movzbl (%eax),%eax
c00026a9:	84 c0                	test   %al,%al
c00026ab:	75 e2                	jne    c000268f <strcat+0x47>
    ; //也就是表达式不成立，正好添加了字符串结尾的0
  return dst_;
c00026ad:	8b 45 08             	mov    0x8(%ebp),%eax
}
c00026b0:	c9                   	leave  
c00026b1:	c3                   	ret    

c00026b2 <strchrs>:

// 在字符串str中查找字符ch出现的次数
uint32_t strchrs(const char *str, uint8_t ch) {
c00026b2:	55                   	push   %ebp
c00026b3:	89 e5                	mov    %esp,%ebp
c00026b5:	83 ec 28             	sub    $0x28,%esp
c00026b8:	8b 45 0c             	mov    0xc(%ebp),%eax
c00026bb:	88 45 e4             	mov    %al,-0x1c(%ebp)
  ASSERT(str != NULL);
c00026be:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c00026c2:	75 19                	jne    c00026dd <strchrs+0x2b>
c00026c4:	68 2a 54 00 c0       	push   $0xc000542a
c00026c9:	68 80 54 00 c0       	push   $0xc0005480
c00026ce:	6a 6f                	push   $0x6f
c00026d0:	68 e9 53 00 c0       	push   $0xc00053e9
c00026d5:	e8 96 fb ff ff       	call   c0002270 <panic_spin>
c00026da:	83 c4 10             	add    $0x10,%esp
  uint32_t ch_cnt = 0;
c00026dd:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  const char *p = str;
c00026e4:	8b 45 08             	mov    0x8(%ebp),%eax
c00026e7:	89 45 f0             	mov    %eax,-0x10(%ebp)
  while (*p != 0) {
c00026ea:	eb 19                	jmp    c0002705 <strchrs+0x53>
    if (*p == ch) {
c00026ec:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00026ef:	0f b6 00             	movzbl (%eax),%eax
c00026f2:	0f be d0             	movsbl %al,%edx
c00026f5:	0f b6 45 e4          	movzbl -0x1c(%ebp),%eax
c00026f9:	39 c2                	cmp    %eax,%edx
c00026fb:	75 04                	jne    c0002701 <strchrs+0x4f>
      ch_cnt++;
c00026fd:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
    }
    p++;
c0002701:	83 45 f0 01          	addl   $0x1,-0x10(%ebp)
  while (*p != 0) {
c0002705:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002708:	0f b6 00             	movzbl (%eax),%eax
c000270b:	84 c0                	test   %al,%al
c000270d:	75 dd                	jne    c00026ec <strchrs+0x3a>
  }
  return ch_cnt;
c000270f:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0002712:	c9                   	leave  
c0002713:	c3                   	ret    

c0002714 <bitmap_init>:
#include "print.h"
#include "stdint.h"
#include "string.h"

// 初始化位图btmp
void bitmap_init(struct bitmap *btmp) {
c0002714:	55                   	push   %ebp
c0002715:	89 e5                	mov    %esp,%ebp
c0002717:	83 ec 08             	sub    $0x8,%esp
  memset(btmp->bits, 0, btmp->btmp_bytes_len);
c000271a:	8b 45 08             	mov    0x8(%ebp),%eax
c000271d:	8b 10                	mov    (%eax),%edx
c000271f:	8b 45 08             	mov    0x8(%ebp),%eax
c0002722:	8b 40 04             	mov    0x4(%eax),%eax
c0002725:	83 ec 04             	sub    $0x4,%esp
c0002728:	52                   	push   %edx
c0002729:	6a 00                	push   $0x0
c000272b:	50                   	push   %eax
c000272c:	e8 15 fc ff ff       	call   c0002346 <memset>
c0002731:	83 c4 10             	add    $0x10,%esp
}
c0002734:	90                   	nop
c0002735:	c9                   	leave  
c0002736:	c3                   	ret    

c0002737 <bitmap_scan_test>:

// 判断bit_idx位是否为1，为1返回true，否则返回false
bool bitmap_scan_test(struct bitmap *btmp, uint32_t bit_idx) {
c0002737:	55                   	push   %ebp
c0002738:	89 e5                	mov    %esp,%ebp
c000273a:	53                   	push   %ebx
c000273b:	83 ec 10             	sub    $0x10,%esp
  uint32_t byte_idx = bit_idx / 8; // 向下取整用于索引数组下标
c000273e:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002741:	c1 e8 03             	shr    $0x3,%eax
c0002744:	89 45 f8             	mov    %eax,-0x8(%ebp)
  uint32_t bit_odd = bit_idx % 8;  //取余用于索引数组内的位
c0002747:	8b 45 0c             	mov    0xc(%ebp),%eax
c000274a:	83 e0 07             	and    $0x7,%eax
c000274d:	89 45 f4             	mov    %eax,-0xc(%ebp)
  return (btmp->bits[byte_idx] & (BITMAP_MASK << bit_odd));
c0002750:	8b 45 08             	mov    0x8(%ebp),%eax
c0002753:	8b 50 04             	mov    0x4(%eax),%edx
c0002756:	8b 45 f8             	mov    -0x8(%ebp),%eax
c0002759:	01 d0                	add    %edx,%eax
c000275b:	0f b6 00             	movzbl (%eax),%eax
c000275e:	0f b6 d0             	movzbl %al,%edx
c0002761:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002764:	bb 01 00 00 00       	mov    $0x1,%ebx
c0002769:	89 c1                	mov    %eax,%ecx
c000276b:	d3 e3                	shl    %cl,%ebx
c000276d:	89 d8                	mov    %ebx,%eax
c000276f:	21 d0                	and    %edx,%eax
}
c0002771:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c0002774:	c9                   	leave  
c0002775:	c3                   	ret    

c0002776 <bitmap_scan>:

// 在位图中申请cnt个位，成功返回其起始下标地址，失败返回-1
int bitmap_scan(struct bitmap *btmp, uint32_t cnt) {
c0002776:	55                   	push   %ebp
c0002777:	89 e5                	mov    %esp,%ebp
c0002779:	83 ec 28             	sub    $0x28,%esp
  uint32_t idx_byte = 0; //用于记录空闲位所在字节索引
c000277c:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  //逐个字节比较
  while ((0xff == btmp->bits[idx_byte]) && (idx_byte < btmp->btmp_bytes_len)) {
c0002783:	eb 04                	jmp    c0002789 <bitmap_scan+0x13>
    // 0xff表示该字节内已无空闲位，继续下一个字节
    idx_byte++;
c0002785:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
  while ((0xff == btmp->bits[idx_byte]) && (idx_byte < btmp->btmp_bytes_len)) {
c0002789:	8b 45 08             	mov    0x8(%ebp),%eax
c000278c:	8b 50 04             	mov    0x4(%eax),%edx
c000278f:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002792:	01 d0                	add    %edx,%eax
c0002794:	0f b6 00             	movzbl (%eax),%eax
c0002797:	3c ff                	cmp    $0xff,%al
c0002799:	75 0a                	jne    c00027a5 <bitmap_scan+0x2f>
c000279b:	8b 45 08             	mov    0x8(%ebp),%eax
c000279e:	8b 00                	mov    (%eax),%eax
c00027a0:	39 45 f4             	cmp    %eax,-0xc(%ebp)
c00027a3:	72 e0                	jb     c0002785 <bitmap_scan+0xf>
  }

  ASSERT(idx_byte < btmp->btmp_bytes_len);
c00027a5:	8b 45 08             	mov    0x8(%ebp),%eax
c00027a8:	8b 00                	mov    (%eax),%eax
c00027aa:	39 45 f4             	cmp    %eax,-0xc(%ebp)
c00027ad:	72 19                	jb     c00027c8 <bitmap_scan+0x52>
c00027af:	68 88 54 00 c0       	push   $0xc0005488
c00027b4:	68 dc 54 00 c0       	push   $0xc00054dc
c00027b9:	6a 1d                	push   $0x1d
c00027bb:	68 a8 54 00 c0       	push   $0xc00054a8
c00027c0:	e8 ab fa ff ff       	call   c0002270 <panic_spin>
c00027c5:	83 c4 10             	add    $0x10,%esp
  if (idx_byte == btmp->btmp_bytes_len) { //该内存池已找不到空间
c00027c8:	8b 45 08             	mov    0x8(%ebp),%eax
c00027cb:	8b 00                	mov    (%eax),%eax
c00027cd:	39 45 f4             	cmp    %eax,-0xc(%ebp)
c00027d0:	75 0a                	jne    c00027dc <bitmap_scan+0x66>
    return -1;
c00027d2:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c00027d7:	e9 c3 00 00 00       	jmp    c000289f <bitmap_scan+0x129>
  }

  //在位图数组范围内的某字节内找到了空闲位，在该字节内逐位比对，返回空闲位的索引
  int idx_bit = 0; // 字节内的索引(范围0-7)
c00027dc:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
  while ((uint8_t)(BITMAP_MASK << idx_bit) & btmp->bits[idx_byte]) {
c00027e3:	eb 04                	jmp    c00027e9 <bitmap_scan+0x73>
    idx_bit++;
c00027e5:	83 45 f0 01          	addl   $0x1,-0x10(%ebp)
  while ((uint8_t)(BITMAP_MASK << idx_bit) & btmp->bits[idx_byte]) {
c00027e9:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00027ec:	ba 01 00 00 00       	mov    $0x1,%edx
c00027f1:	89 c1                	mov    %eax,%ecx
c00027f3:	d3 e2                	shl    %cl,%edx
c00027f5:	89 d0                	mov    %edx,%eax
c00027f7:	89 c1                	mov    %eax,%ecx
c00027f9:	8b 45 08             	mov    0x8(%ebp),%eax
c00027fc:	8b 50 04             	mov    0x4(%eax),%edx
c00027ff:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002802:	01 d0                	add    %edx,%eax
c0002804:	0f b6 00             	movzbl (%eax),%eax
c0002807:	21 c8                	and    %ecx,%eax
c0002809:	84 c0                	test   %al,%al
c000280b:	75 d8                	jne    c00027e5 <bitmap_scan+0x6f>
  }

  int bit_idx_start = idx_byte * 8 + idx_bit; // 空闲位在位图内的下标
c000280d:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002810:	8d 14 c5 00 00 00 00 	lea    0x0(,%eax,8),%edx
c0002817:	8b 45 f0             	mov    -0x10(%ebp),%eax
c000281a:	01 d0                	add    %edx,%eax
c000281c:	89 45 ec             	mov    %eax,-0x14(%ebp)
  if (cnt == 1) {
c000281f:	83 7d 0c 01          	cmpl   $0x1,0xc(%ebp)
c0002823:	75 05                	jne    c000282a <bitmap_scan+0xb4>
    return bit_idx_start;
c0002825:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002828:	eb 75                	jmp    c000289f <bitmap_scan+0x129>
  }

  uint32_t bit_left = (btmp->btmp_bytes_len * 8 - bit_idx_start);
c000282a:	8b 45 08             	mov    0x8(%ebp),%eax
c000282d:	8b 00                	mov    (%eax),%eax
c000282f:	c1 e0 03             	shl    $0x3,%eax
c0002832:	8b 55 ec             	mov    -0x14(%ebp),%edx
c0002835:	29 d0                	sub    %edx,%eax
c0002837:	89 45 e8             	mov    %eax,-0x18(%ebp)
  // 记录还有多少位可以判断
  uint32_t next_bit = bit_idx_start + 1;
c000283a:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000283d:	83 c0 01             	add    $0x1,%eax
c0002840:	89 45 e4             	mov    %eax,-0x1c(%ebp)
  uint32_t count = 1; //用于记录找到的空闲位数
c0002843:	c7 45 e0 01 00 00 00 	movl   $0x1,-0x20(%ebp)

  bit_idx_start = -1; // 先将其置为-1，若找不到连续的位置就直接返回
c000284a:	c7 45 ec ff ff ff ff 	movl   $0xffffffff,-0x14(%ebp)
  while (bit_left-- > 0) {
c0002851:	eb 3c                	jmp    c000288f <bitmap_scan+0x119>
    if (!(bitmap_scan_test(btmp, next_bit))) { //如果next_bit为0
c0002853:	83 ec 08             	sub    $0x8,%esp
c0002856:	ff 75 e4             	push   -0x1c(%ebp)
c0002859:	ff 75 08             	push   0x8(%ebp)
c000285c:	e8 d6 fe ff ff       	call   c0002737 <bitmap_scan_test>
c0002861:	83 c4 10             	add    $0x10,%esp
c0002864:	85 c0                	test   %eax,%eax
c0002866:	75 06                	jne    c000286e <bitmap_scan+0xf8>
      count++;
c0002868:	83 45 e0 01          	addl   $0x1,-0x20(%ebp)
c000286c:	eb 07                	jmp    c0002875 <bitmap_scan+0xff>
    } else {
      count = 0;
c000286e:	c7 45 e0 00 00 00 00 	movl   $0x0,-0x20(%ebp)
    }
    if (count == cnt) { // 若找到连续的cnt个空位
c0002875:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0002878:	3b 45 0c             	cmp    0xc(%ebp),%eax
c000287b:	75 0e                	jne    c000288b <bitmap_scan+0x115>
      bit_idx_start = next_bit - cnt + 1;
c000287d:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0002880:	2b 45 0c             	sub    0xc(%ebp),%eax
c0002883:	83 c0 01             	add    $0x1,%eax
c0002886:	89 45 ec             	mov    %eax,-0x14(%ebp)
      break;
c0002889:	eb 11                	jmp    c000289c <bitmap_scan+0x126>
    }
    next_bit++;
c000288b:	83 45 e4 01          	addl   $0x1,-0x1c(%ebp)
  while (bit_left-- > 0) {
c000288f:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002892:	8d 50 ff             	lea    -0x1(%eax),%edx
c0002895:	89 55 e8             	mov    %edx,-0x18(%ebp)
c0002898:	85 c0                	test   %eax,%eax
c000289a:	75 b7                	jne    c0002853 <bitmap_scan+0xdd>
  }
  return bit_idx_start;
c000289c:	8b 45 ec             	mov    -0x14(%ebp),%eax
}
c000289f:	c9                   	leave  
c00028a0:	c3                   	ret    

c00028a1 <bitmap_set>:

// 将位图的btmp的bit_idx位设置为value
void bitmap_set(struct bitmap *btmp, uint32_t bit_idx, int8_t value) {
c00028a1:	55                   	push   %ebp
c00028a2:	89 e5                	mov    %esp,%ebp
c00028a4:	53                   	push   %ebx
c00028a5:	83 ec 24             	sub    $0x24,%esp
c00028a8:	8b 45 10             	mov    0x10(%ebp),%eax
c00028ab:	88 45 e4             	mov    %al,-0x1c(%ebp)
  ASSERT((value == 0) || (value == 1));
c00028ae:	80 7d e4 00          	cmpb   $0x0,-0x1c(%ebp)
c00028b2:	74 1f                	je     c00028d3 <bitmap_set+0x32>
c00028b4:	80 7d e4 01          	cmpb   $0x1,-0x1c(%ebp)
c00028b8:	74 19                	je     c00028d3 <bitmap_set+0x32>
c00028ba:	68 bc 54 00 c0       	push   $0xc00054bc
c00028bf:	68 e8 54 00 c0       	push   $0xc00054e8
c00028c4:	6a 44                	push   $0x44
c00028c6:	68 a8 54 00 c0       	push   $0xc00054a8
c00028cb:	e8 a0 f9 ff ff       	call   c0002270 <panic_spin>
c00028d0:	83 c4 10             	add    $0x10,%esp
  uint32_t byte_idx = bit_idx / 8; //向下取整用于索引数组下标
c00028d3:	8b 45 0c             	mov    0xc(%ebp),%eax
c00028d6:	c1 e8 03             	shr    $0x3,%eax
c00028d9:	89 45 f4             	mov    %eax,-0xc(%ebp)
  uint32_t bit_odd = bit_idx % 8;  // 取余用于索引数组内的位
c00028dc:	8b 45 0c             	mov    0xc(%ebp),%eax
c00028df:	83 e0 07             	and    $0x7,%eax
c00028e2:	89 45 f0             	mov    %eax,-0x10(%ebp)

  // 一般用0x1这样的数对字节中的位操作，将1任意移动后再取反，或者先取反再移位，可用来对位置0操作
  if (value) { // value==1
c00028e5:	80 7d e4 00          	cmpb   $0x0,-0x1c(%ebp)
c00028e9:	74 33                	je     c000291e <bitmap_set+0x7d>
    btmp->bits[byte_idx] |= (BITMAP_MASK << bit_odd);
c00028eb:	8b 45 08             	mov    0x8(%ebp),%eax
c00028ee:	8b 50 04             	mov    0x4(%eax),%edx
c00028f1:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00028f4:	01 d0                	add    %edx,%eax
c00028f6:	0f b6 00             	movzbl (%eax),%eax
c00028f9:	89 c3                	mov    %eax,%ebx
c00028fb:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00028fe:	ba 01 00 00 00       	mov    $0x1,%edx
c0002903:	89 c1                	mov    %eax,%ecx
c0002905:	d3 e2                	shl    %cl,%edx
c0002907:	89 d0                	mov    %edx,%eax
c0002909:	09 c3                	or     %eax,%ebx
c000290b:	89 d9                	mov    %ebx,%ecx
c000290d:	8b 45 08             	mov    0x8(%ebp),%eax
c0002910:	8b 50 04             	mov    0x4(%eax),%edx
c0002913:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002916:	01 d0                	add    %edx,%eax
c0002918:	89 ca                	mov    %ecx,%edx
c000291a:	88 10                	mov    %dl,(%eax)
  } else {
    btmp->bits[byte_idx] &= ~(BITMAP_MASK << bit_odd);
  }
c000291c:	eb 33                	jmp    c0002951 <bitmap_set+0xb0>
    btmp->bits[byte_idx] &= ~(BITMAP_MASK << bit_odd);
c000291e:	8b 45 08             	mov    0x8(%ebp),%eax
c0002921:	8b 50 04             	mov    0x4(%eax),%edx
c0002924:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002927:	01 d0                	add    %edx,%eax
c0002929:	0f b6 00             	movzbl (%eax),%eax
c000292c:	89 c3                	mov    %eax,%ebx
c000292e:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002931:	ba 01 00 00 00       	mov    $0x1,%edx
c0002936:	89 c1                	mov    %eax,%ecx
c0002938:	d3 e2                	shl    %cl,%edx
c000293a:	89 d0                	mov    %edx,%eax
c000293c:	f7 d0                	not    %eax
c000293e:	21 c3                	and    %eax,%ebx
c0002940:	89 d9                	mov    %ebx,%ecx
c0002942:	8b 45 08             	mov    0x8(%ebp),%eax
c0002945:	8b 50 04             	mov    0x4(%eax),%edx
c0002948:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000294b:	01 d0                	add    %edx,%eax
c000294d:	89 ca                	mov    %ecx,%edx
c000294f:	88 10                	mov    %dl,(%eax)
c0002951:	90                   	nop
c0002952:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c0002955:	c9                   	leave  
c0002956:	c3                   	ret    

c0002957 <vaddr_get>:
};
struct pool kernel_pool, user_pool;
struct virtual_addr kernel_vaddr; // 用来给内核分配虚拟地址

// 在虚拟内存池（pf指定类型）中申请pg_cnt个虚拟页
static void *vaddr_get(enum pool_flags pf, uint32_t pg_cnt) {
c0002957:	55                   	push   %ebp
c0002958:	89 e5                	mov    %esp,%ebp
c000295a:	83 ec 18             	sub    $0x18,%esp
  int vaddr_start = 0, bit_idx_start = -1;
c000295d:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
c0002964:	c7 45 ec ff ff ff ff 	movl   $0xffffffff,-0x14(%ebp)
  uint32_t cnt = 0;
c000296b:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)

  if (pf == PF_KERNEL) {
c0002972:	83 7d 08 01          	cmpl   $0x1,0x8(%ebp)
c0002976:	75 65                	jne    c00029dd <vaddr_get+0x86>
    bit_idx_start = bitmap_scan(&kernel_vaddr.vaddr_bitmap, pg_cnt);
c0002978:	83 ec 08             	sub    $0x8,%esp
c000297b:	ff 75 0c             	push   0xc(%ebp)
c000297e:	68 0c 85 00 c0       	push   $0xc000850c
c0002983:	e8 ee fd ff ff       	call   c0002776 <bitmap_scan>
c0002988:	83 c4 10             	add    $0x10,%esp
c000298b:	89 45 ec             	mov    %eax,-0x14(%ebp)
    if (bit_idx_start == -1) {
c000298e:	83 7d ec ff          	cmpl   $0xffffffff,-0x14(%ebp)
c0002992:	75 2b                	jne    c00029bf <vaddr_get+0x68>
      return NULL; // 失败
c0002994:	b8 00 00 00 00       	mov    $0x0,%eax
c0002999:	e9 ce 00 00 00       	jmp    c0002a6c <vaddr_get+0x115>
    }
    while (cnt < pg_cnt) {
      bitmap_set(&kernel_vaddr.vaddr_bitmap, bit_idx_start + cnt++, 1);
c000299e:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00029a1:	8d 50 01             	lea    0x1(%eax),%edx
c00029a4:	89 55 f0             	mov    %edx,-0x10(%ebp)
c00029a7:	8b 55 ec             	mov    -0x14(%ebp),%edx
c00029aa:	01 d0                	add    %edx,%eax
c00029ac:	83 ec 04             	sub    $0x4,%esp
c00029af:	6a 01                	push   $0x1
c00029b1:	50                   	push   %eax
c00029b2:	68 0c 85 00 c0       	push   $0xc000850c
c00029b7:	e8 e5 fe ff ff       	call   c00028a1 <bitmap_set>
c00029bc:	83 c4 10             	add    $0x10,%esp
    while (cnt < pg_cnt) {
c00029bf:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00029c2:	3b 45 0c             	cmp    0xc(%ebp),%eax
c00029c5:	72 d7                	jb     c000299e <vaddr_get+0x47>
    }
    // 将bit_idx_start转为虚拟地址
    vaddr_start = kernel_vaddr.vaddr_start + bit_idx_start * PG_SIZE;
c00029c7:	8b 15 14 85 00 c0    	mov    0xc0008514,%edx
c00029cd:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00029d0:	c1 e0 0c             	shl    $0xc,%eax
c00029d3:	01 d0                	add    %edx,%eax
c00029d5:	89 45 f4             	mov    %eax,-0xc(%ebp)
c00029d8:	e9 8c 00 00 00       	jmp    c0002a69 <vaddr_get+0x112>
  } else {
    struct task_struct *cur = running_thread();
c00029dd:	e8 60 07 00 00       	call   c0003142 <running_thread>
c00029e2:	89 45 e8             	mov    %eax,-0x18(%ebp)
    bit_idx_start = bitmap_scan(&cur->userprog_vaddr.vaddr_bitmap, pg_cnt);
c00029e5:	8b 45 e8             	mov    -0x18(%ebp),%eax
c00029e8:	83 c0 34             	add    $0x34,%eax
c00029eb:	83 ec 08             	sub    $0x8,%esp
c00029ee:	ff 75 0c             	push   0xc(%ebp)
c00029f1:	50                   	push   %eax
c00029f2:	e8 7f fd ff ff       	call   c0002776 <bitmap_scan>
c00029f7:	83 c4 10             	add    $0x10,%esp
c00029fa:	89 45 ec             	mov    %eax,-0x14(%ebp)
    if (bit_idx_start == -1) {
c00029fd:	83 7d ec ff          	cmpl   $0xffffffff,-0x14(%ebp)
c0002a01:	75 2a                	jne    c0002a2d <vaddr_get+0xd6>
      return NULL;
c0002a03:	b8 00 00 00 00       	mov    $0x0,%eax
c0002a08:	eb 62                	jmp    c0002a6c <vaddr_get+0x115>
    }

    while (cnt < pg_cnt) {
      bitmap_set(&cur->userprog_vaddr.vaddr_bitmap, bit_idx_start + cnt++, 1);
c0002a0a:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002a0d:	8d 50 01             	lea    0x1(%eax),%edx
c0002a10:	89 55 f0             	mov    %edx,-0x10(%ebp)
c0002a13:	8b 55 ec             	mov    -0x14(%ebp),%edx
c0002a16:	01 c2                	add    %eax,%edx
c0002a18:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002a1b:	83 c0 34             	add    $0x34,%eax
c0002a1e:	83 ec 04             	sub    $0x4,%esp
c0002a21:	6a 01                	push   $0x1
c0002a23:	52                   	push   %edx
c0002a24:	50                   	push   %eax
c0002a25:	e8 77 fe ff ff       	call   c00028a1 <bitmap_set>
c0002a2a:	83 c4 10             	add    $0x10,%esp
    while (cnt < pg_cnt) {
c0002a2d:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002a30:	3b 45 0c             	cmp    0xc(%ebp),%eax
c0002a33:	72 d5                	jb     c0002a0a <vaddr_get+0xb3>
    }
    vaddr_start = cur->userprog_vaddr.vaddr_start + bit_idx_start * PG_SIZE;
c0002a35:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002a38:	8b 50 3c             	mov    0x3c(%eax),%edx
c0002a3b:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002a3e:	c1 e0 0c             	shl    $0xc,%eax
c0002a41:	01 d0                	add    %edx,%eax
c0002a43:	89 45 f4             	mov    %eax,-0xc(%ebp)

    // (0xc0000000-PG_SIZE)-> 用户3级栈
    ASSERT((uint32_t)vaddr_start < (0xc0000000 - PG_SIZE));
c0002a46:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002a49:	3d ff ef ff bf       	cmp    $0xbfffefff,%eax
c0002a4e:	76 19                	jbe    c0002a69 <vaddr_get+0x112>
c0002a50:	68 f4 54 00 c0       	push   $0xc00054f4
c0002a55:	68 9c 56 00 c0       	push   $0xc000569c
c0002a5a:	6a 3c                	push   $0x3c
c0002a5c:	68 23 55 00 c0       	push   $0xc0005523
c0002a61:	e8 0a f8 ff ff       	call   c0002270 <panic_spin>
c0002a66:	83 c4 10             	add    $0x10,%esp
  }
  return (void *)vaddr_start;
c0002a69:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0002a6c:	c9                   	leave  
c0002a6d:	c3                   	ret    

c0002a6e <pte_ptr>:

// 得到虚拟地址对应的pte指针
uint32_t *pte_ptr(uint32_t vaddr) {
c0002a6e:	55                   	push   %ebp
c0002a6f:	89 e5                	mov    %esp,%ebp
c0002a71:	83 ec 10             	sub    $0x10,%esp
  /* 先访问到页表自己
   * 再用页目录项 pde（页目录内页表的索引）作为 pte 的索引访问到页表
   * 再用 pte 的索引作为页内偏移
   */
  uint32_t *pte = (uint32_t *)(0xffc00000 + ((vaddr & 0xffc00000) >> 10) +
c0002a74:	8b 45 08             	mov    0x8(%ebp),%eax
c0002a77:	c1 e8 0a             	shr    $0xa,%eax
c0002a7a:	25 00 f0 3f 00       	and    $0x3ff000,%eax
c0002a7f:	89 c2                	mov    %eax,%edx
                               PTE_IDX(vaddr) * 4);
c0002a81:	8b 45 08             	mov    0x8(%ebp),%eax
c0002a84:	c1 e8 0c             	shr    $0xc,%eax
c0002a87:	25 ff 03 00 00       	and    $0x3ff,%eax
c0002a8c:	c1 e0 02             	shl    $0x2,%eax
  uint32_t *pte = (uint32_t *)(0xffc00000 + ((vaddr & 0xffc00000) >> 10) +
c0002a8f:	01 d0                	add    %edx,%eax
c0002a91:	2d 00 00 40 00       	sub    $0x400000,%eax
c0002a96:	89 45 fc             	mov    %eax,-0x4(%ebp)
  return pte;
c0002a99:	8b 45 fc             	mov    -0x4(%ebp),%eax
}
c0002a9c:	c9                   	leave  
c0002a9d:	c3                   	ret    

c0002a9e <pde_ptr>:

// 得到虚拟地址对应的pde指针
uint32_t *pde_ptr(uint32_t vaddr) {
c0002a9e:	55                   	push   %ebp
c0002a9f:	89 e5                	mov    %esp,%ebp
c0002aa1:	83 ec 10             	sub    $0x10,%esp
  // 0xfffff用来访问到页表本身所在的地址
  uint32_t *pde = (uint32_t *)((0xfffff000) + PDE_IDX(vaddr) * 4);
c0002aa4:	8b 45 08             	mov    0x8(%ebp),%eax
c0002aa7:	c1 e8 16             	shr    $0x16,%eax
c0002aaa:	05 00 fc ff 3f       	add    $0x3ffffc00,%eax
c0002aaf:	c1 e0 02             	shl    $0x2,%eax
c0002ab2:	89 45 fc             	mov    %eax,-0x4(%ebp)
  return pde;
c0002ab5:	8b 45 fc             	mov    -0x4(%ebp),%eax
}
c0002ab8:	c9                   	leave  
c0002ab9:	c3                   	ret    

c0002aba <palloc>:

// 在m_pool指向的物理内存池中分配1个物理页
static void *palloc(struct pool *m_pool) {
c0002aba:	55                   	push   %ebp
c0002abb:	89 e5                	mov    %esp,%ebp
c0002abd:	83 ec 18             	sub    $0x18,%esp
  /* 扫描或设置位图要保证原子操作 */
  int bit_idx = bitmap_scan(&m_pool->pool_bitmap, 1); // 找一个物理页面
c0002ac0:	8b 45 08             	mov    0x8(%ebp),%eax
c0002ac3:	83 ec 08             	sub    $0x8,%esp
c0002ac6:	6a 01                	push   $0x1
c0002ac8:	50                   	push   %eax
c0002ac9:	e8 a8 fc ff ff       	call   c0002776 <bitmap_scan>
c0002ace:	83 c4 10             	add    $0x10,%esp
c0002ad1:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (bit_idx == -1) {
c0002ad4:	83 7d f4 ff          	cmpl   $0xffffffff,-0xc(%ebp)
c0002ad8:	75 07                	jne    c0002ae1 <palloc+0x27>
    return NULL; // 失败
c0002ada:	b8 00 00 00 00       	mov    $0x0,%eax
c0002adf:	eb 2b                	jmp    c0002b0c <palloc+0x52>
  }
  bitmap_set(&m_pool->pool_bitmap, bit_idx, 1);
c0002ae1:	8b 55 f4             	mov    -0xc(%ebp),%edx
c0002ae4:	8b 45 08             	mov    0x8(%ebp),%eax
c0002ae7:	83 ec 04             	sub    $0x4,%esp
c0002aea:	6a 01                	push   $0x1
c0002aec:	52                   	push   %edx
c0002aed:	50                   	push   %eax
c0002aee:	e8 ae fd ff ff       	call   c00028a1 <bitmap_set>
c0002af3:	83 c4 10             	add    $0x10,%esp
  uint32_t page_phyaddr = // 分配的物理页地址
      ((bit_idx * PG_SIZE) + m_pool->phy_addr_start);
c0002af6:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002af9:	c1 e0 0c             	shl    $0xc,%eax
c0002afc:	89 c2                	mov    %eax,%edx
c0002afe:	8b 45 08             	mov    0x8(%ebp),%eax
c0002b01:	8b 40 08             	mov    0x8(%eax),%eax
  uint32_t page_phyaddr = // 分配的物理页地址
c0002b04:	01 d0                	add    %edx,%eax
c0002b06:	89 45 f0             	mov    %eax,-0x10(%ebp)
  return (void *)page_phyaddr;
c0002b09:	8b 45 f0             	mov    -0x10(%ebp),%eax
}
c0002b0c:	c9                   	leave  
c0002b0d:	c3                   	ret    

c0002b0e <page_table_add>:

// 页表中添加虚拟地址与物理地址的映射
static void page_table_add(void *_vaddr, void *_page_phyaddr) {
c0002b0e:	55                   	push   %ebp
c0002b0f:	89 e5                	mov    %esp,%ebp
c0002b11:	83 ec 28             	sub    $0x28,%esp
  uint32_t vaddr = (uint32_t)_vaddr, page_phyaddr = (uint32_t)_page_phyaddr;
c0002b14:	8b 45 08             	mov    0x8(%ebp),%eax
c0002b17:	89 45 f4             	mov    %eax,-0xc(%ebp)
c0002b1a:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002b1d:	89 45 f0             	mov    %eax,-0x10(%ebp)
  uint32_t *pde = pde_ptr(vaddr);
c0002b20:	ff 75 f4             	push   -0xc(%ebp)
c0002b23:	e8 76 ff ff ff       	call   c0002a9e <pde_ptr>
c0002b28:	83 c4 04             	add    $0x4,%esp
c0002b2b:	89 45 ec             	mov    %eax,-0x14(%ebp)
  uint32_t *pte = pte_ptr(vaddr);
c0002b2e:	ff 75 f4             	push   -0xc(%ebp)
c0002b31:	e8 38 ff ff ff       	call   c0002a6e <pte_ptr>
c0002b36:	83 c4 04             	add    $0x4,%esp
c0002b39:	89 45 e8             	mov    %eax,-0x18(%ebp)

  // 在页目录表内判断目录项的P位，为1表示该表已存在
  if (*pde & 0x00000001) {
c0002b3c:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002b3f:	8b 00                	mov    (%eax),%eax
c0002b41:	83 e0 01             	and    $0x1,%eax
c0002b44:	85 c0                	test   %eax,%eax
c0002b46:	74 6b                	je     c0002bb3 <page_table_add+0xa5>
    ASSERT(!(*pte & 0x00000001));
c0002b48:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002b4b:	8b 00                	mov    (%eax),%eax
c0002b4d:	83 e0 01             	and    $0x1,%eax
c0002b50:	85 c0                	test   %eax,%eax
c0002b52:	74 19                	je     c0002b6d <page_table_add+0x5f>
c0002b54:	68 33 55 00 c0       	push   $0xc0005533
c0002b59:	68 a8 56 00 c0       	push   $0xc00056a8
c0002b5e:	6a 68                	push   $0x68
c0002b60:	68 23 55 00 c0       	push   $0xc0005523
c0002b65:	e8 06 f7 ff ff       	call   c0002270 <panic_spin>
c0002b6a:	83 c4 10             	add    $0x10,%esp
    if (!(*pte & 0x00000001)) {
c0002b6d:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002b70:	8b 00                	mov    (%eax),%eax
c0002b72:	83 e0 01             	and    $0x1,%eax
c0002b75:	85 c0                	test   %eax,%eax
c0002b77:	75 12                	jne    c0002b8b <page_table_add+0x7d>
      *pte = (page_phyaddr | PG_US_U | PG_RW_W | PG_P_1); // US=1,RW=1,P=1
c0002b79:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002b7c:	83 c8 07             	or     $0x7,%eax
c0002b7f:	89 c2                	mov    %eax,%edx
c0002b81:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002b84:	89 10                	mov    %edx,(%eax)
    // 取高20位，低12位置0
    memset((void *)((int)pte & 0xfffff000), 0, PG_SIZE);
    ASSERT(!(*pte & 0x00000001));
    *pte = (page_phyaddr | PG_US_U | PG_RW_W | PG_P_1); // US=1,RW=1,P=1
  }
}
c0002b86:	e9 95 00 00 00       	jmp    c0002c20 <page_table_add+0x112>
      PANIC("pte repeat");
c0002b8b:	68 48 55 00 c0       	push   $0xc0005548
c0002b90:	68 a8 56 00 c0       	push   $0xc00056a8
c0002b95:	6a 6d                	push   $0x6d
c0002b97:	68 23 55 00 c0       	push   $0xc0005523
c0002b9c:	e8 cf f6 ff ff       	call   c0002270 <panic_spin>
c0002ba1:	83 c4 10             	add    $0x10,%esp
      *pte = (page_phyaddr | PG_US_U | PG_RW_W | PG_P_1); // US=1,RW=1,P=1
c0002ba4:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002ba7:	83 c8 07             	or     $0x7,%eax
c0002baa:	89 c2                	mov    %eax,%edx
c0002bac:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002baf:	89 10                	mov    %edx,(%eax)
}
c0002bb1:	eb 6d                	jmp    c0002c20 <page_table_add+0x112>
    uint32_t pde_pyhaddr = (uint32_t)palloc(&kernel_pool);
c0002bb3:	83 ec 0c             	sub    $0xc,%esp
c0002bb6:	68 a0 84 00 c0       	push   $0xc00084a0
c0002bbb:	e8 fa fe ff ff       	call   c0002aba <palloc>
c0002bc0:	83 c4 10             	add    $0x10,%esp
c0002bc3:	89 45 e4             	mov    %eax,-0x1c(%ebp)
    *pde = (pde_pyhaddr | PG_US_U | PG_RW_W | PG_P_1);
c0002bc6:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0002bc9:	83 c8 07             	or     $0x7,%eax
c0002bcc:	89 c2                	mov    %eax,%edx
c0002bce:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002bd1:	89 10                	mov    %edx,(%eax)
    memset((void *)((int)pte & 0xfffff000), 0, PG_SIZE);
c0002bd3:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002bd6:	25 00 f0 ff ff       	and    $0xfffff000,%eax
c0002bdb:	83 ec 04             	sub    $0x4,%esp
c0002bde:	68 00 10 00 00       	push   $0x1000
c0002be3:	6a 00                	push   $0x0
c0002be5:	50                   	push   %eax
c0002be6:	e8 5b f7 ff ff       	call   c0002346 <memset>
c0002beb:	83 c4 10             	add    $0x10,%esp
    ASSERT(!(*pte & 0x00000001));
c0002bee:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002bf1:	8b 00                	mov    (%eax),%eax
c0002bf3:	83 e0 01             	and    $0x1,%eax
c0002bf6:	85 c0                	test   %eax,%eax
c0002bf8:	74 19                	je     c0002c13 <page_table_add+0x105>
c0002bfa:	68 33 55 00 c0       	push   $0xc0005533
c0002bff:	68 a8 56 00 c0       	push   $0xc00056a8
c0002c04:	6a 77                	push   $0x77
c0002c06:	68 23 55 00 c0       	push   $0xc0005523
c0002c0b:	e8 60 f6 ff ff       	call   c0002270 <panic_spin>
c0002c10:	83 c4 10             	add    $0x10,%esp
    *pte = (page_phyaddr | PG_US_U | PG_RW_W | PG_P_1); // US=1,RW=1,P=1
c0002c13:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002c16:	83 c8 07             	or     $0x7,%eax
c0002c19:	89 c2                	mov    %eax,%edx
c0002c1b:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002c1e:	89 10                	mov    %edx,(%eax)
}
c0002c20:	90                   	nop
c0002c21:	c9                   	leave  
c0002c22:	c3                   	ret    

c0002c23 <malloc_page>:
/***** malloc_page：分配pg_cnt个页，成功返回起始虚拟地址 *******
1、在虚拟内存池中申请虚拟地址（vaddr_get）
2、在物理内存池中申请物理页（palloc）
3、将以上得到的虚拟地址和物理地址在页表中完成映射（page_table_add）
**********************************************************/
void *malloc_page(enum pool_flags pf, uint32_t pg_cnt) {
c0002c23:	55                   	push   %ebp
c0002c24:	89 e5                	mov    %esp,%ebp
c0002c26:	83 ec 28             	sub    $0x28,%esp
  ASSERT(pg_cnt > 0 && pg_cnt < 3840);
c0002c29:	83 7d 0c 00          	cmpl   $0x0,0xc(%ebp)
c0002c2d:	74 09                	je     c0002c38 <malloc_page+0x15>
c0002c2f:	81 7d 0c ff 0e 00 00 	cmpl   $0xeff,0xc(%ebp)
c0002c36:	76 1c                	jbe    c0002c54 <malloc_page+0x31>
c0002c38:	68 53 55 00 c0       	push   $0xc0005553
c0002c3d:	68 b8 56 00 c0       	push   $0xc00056b8
c0002c42:	68 82 00 00 00       	push   $0x82
c0002c47:	68 23 55 00 c0       	push   $0xc0005523
c0002c4c:	e8 1f f6 ff ff       	call   c0002270 <panic_spin>
c0002c51:	83 c4 10             	add    $0x10,%esp
  void *vaddr_start = vaddr_get(pf, pg_cnt);
c0002c54:	83 ec 08             	sub    $0x8,%esp
c0002c57:	ff 75 0c             	push   0xc(%ebp)
c0002c5a:	ff 75 08             	push   0x8(%ebp)
c0002c5d:	e8 f5 fc ff ff       	call   c0002957 <vaddr_get>
c0002c62:	83 c4 10             	add    $0x10,%esp
c0002c65:	89 45 ec             	mov    %eax,-0x14(%ebp)
  if (vaddr_start == NULL) {
c0002c68:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c0002c6c:	75 07                	jne    c0002c75 <malloc_page+0x52>
    return NULL; // 失败
c0002c6e:	b8 00 00 00 00       	mov    $0x0,%eax
c0002c73:	eb 6e                	jmp    c0002ce3 <malloc_page+0xc0>
  }

  uint32_t vaddr = (uint32_t)vaddr_start, cnt = pg_cnt;
c0002c75:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002c78:	89 45 f4             	mov    %eax,-0xc(%ebp)
c0002c7b:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002c7e:	89 45 f0             	mov    %eax,-0x10(%ebp)
  struct pool *mem_pool = pf & PF_KERNEL ? &kernel_pool : &user_pool;
c0002c81:	8b 45 08             	mov    0x8(%ebp),%eax
c0002c84:	83 e0 01             	and    $0x1,%eax
c0002c87:	85 c0                	test   %eax,%eax
c0002c89:	74 07                	je     c0002c92 <malloc_page+0x6f>
c0002c8b:	b8 a0 84 00 c0       	mov    $0xc00084a0,%eax
c0002c90:	eb 05                	jmp    c0002c97 <malloc_page+0x74>
c0002c92:	b8 e0 84 00 c0       	mov    $0xc00084e0,%eax
c0002c97:	89 45 e8             	mov    %eax,-0x18(%ebp)

  // 虚拟地址连续但物理地址可以不连续，所以逐个做映射
  while (cnt-- > 0) {
c0002c9a:	eb 37                	jmp    c0002cd3 <malloc_page+0xb0>
    void *page_phyaddr = palloc(mem_pool);
c0002c9c:	83 ec 0c             	sub    $0xc,%esp
c0002c9f:	ff 75 e8             	push   -0x18(%ebp)
c0002ca2:	e8 13 fe ff ff       	call   c0002aba <palloc>
c0002ca7:	83 c4 10             	add    $0x10,%esp
c0002caa:	89 45 e4             	mov    %eax,-0x1c(%ebp)
    if (page_phyaddr == NULL) {
c0002cad:	83 7d e4 00          	cmpl   $0x0,-0x1c(%ebp)
c0002cb1:	75 07                	jne    c0002cba <malloc_page+0x97>
      // TODO：失败时要将曾经已申请的虚拟地址和物理页全部回滚，完成内存回收时再补充
      return NULL;
c0002cb3:	b8 00 00 00 00       	mov    $0x0,%eax
c0002cb8:	eb 29                	jmp    c0002ce3 <malloc_page+0xc0>
    }
    page_table_add((void *)vaddr, page_phyaddr); // 在页表中作映射
c0002cba:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002cbd:	83 ec 08             	sub    $0x8,%esp
c0002cc0:	ff 75 e4             	push   -0x1c(%ebp)
c0002cc3:	50                   	push   %eax
c0002cc4:	e8 45 fe ff ff       	call   c0002b0e <page_table_add>
c0002cc9:	83 c4 10             	add    $0x10,%esp
    vaddr += PG_SIZE;                            // 下个虚拟页
c0002ccc:	81 45 f4 00 10 00 00 	addl   $0x1000,-0xc(%ebp)
  while (cnt-- > 0) {
c0002cd3:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002cd6:	8d 50 ff             	lea    -0x1(%eax),%edx
c0002cd9:	89 55 f0             	mov    %edx,-0x10(%ebp)
c0002cdc:	85 c0                	test   %eax,%eax
c0002cde:	75 bc                	jne    c0002c9c <malloc_page+0x79>
  }
  return vaddr_start;
c0002ce0:	8b 45 ec             	mov    -0x14(%ebp),%eax
}
c0002ce3:	c9                   	leave  
c0002ce4:	c3                   	ret    

c0002ce5 <get_kernel_pages>:

// 从内核物理内存池中申请1页内存，成功则返回其虚拟地址
void *get_kernel_pages(uint32_t pg_cnt) {
c0002ce5:	55                   	push   %ebp
c0002ce6:	89 e5                	mov    %esp,%ebp
c0002ce8:	83 ec 18             	sub    $0x18,%esp
  void *vaddr = malloc_page(PF_KERNEL, pg_cnt);
c0002ceb:	83 ec 08             	sub    $0x8,%esp
c0002cee:	ff 75 08             	push   0x8(%ebp)
c0002cf1:	6a 01                	push   $0x1
c0002cf3:	e8 2b ff ff ff       	call   c0002c23 <malloc_page>
c0002cf8:	83 c4 10             	add    $0x10,%esp
c0002cfb:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (vaddr != NULL) { // 若分配的地址不为空，将页框清0后返回
c0002cfe:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
c0002d02:	74 17                	je     c0002d1b <get_kernel_pages+0x36>
    memset(vaddr, 0, pg_cnt * PG_SIZE);
c0002d04:	8b 45 08             	mov    0x8(%ebp),%eax
c0002d07:	c1 e0 0c             	shl    $0xc,%eax
c0002d0a:	83 ec 04             	sub    $0x4,%esp
c0002d0d:	50                   	push   %eax
c0002d0e:	6a 00                	push   $0x0
c0002d10:	ff 75 f4             	push   -0xc(%ebp)
c0002d13:	e8 2e f6 ff ff       	call   c0002346 <memset>
c0002d18:	83 c4 10             	add    $0x10,%esp
  }
  return vaddr;
c0002d1b:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0002d1e:	c9                   	leave  
c0002d1f:	c3                   	ret    

c0002d20 <get_user_pages>:

// 在用户空间中申请4k内存，并返回其虚拟地址
void *get_user_pages(uint32_t pg_cnt) {
c0002d20:	55                   	push   %ebp
c0002d21:	89 e5                	mov    %esp,%ebp
c0002d23:	83 ec 18             	sub    $0x18,%esp
  lock_acquire(&user_pool.lock);
c0002d26:	83 ec 0c             	sub    $0xc,%esp
c0002d29:	68 f0 84 00 c0       	push   $0xc00084f0
c0002d2e:	e8 76 0d 00 00       	call   c0003aa9 <lock_acquire>
c0002d33:	83 c4 10             	add    $0x10,%esp
  void *vaddr = malloc_page(PF_USER, pg_cnt);
c0002d36:	83 ec 08             	sub    $0x8,%esp
c0002d39:	ff 75 08             	push   0x8(%ebp)
c0002d3c:	6a 02                	push   $0x2
c0002d3e:	e8 e0 fe ff ff       	call   c0002c23 <malloc_page>
c0002d43:	83 c4 10             	add    $0x10,%esp
c0002d46:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (vaddr != NULL) {
c0002d49:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
c0002d4d:	74 17                	je     c0002d66 <get_user_pages+0x46>
    memset(vaddr, 0, pg_cnt * PG_SIZE);
c0002d4f:	8b 45 08             	mov    0x8(%ebp),%eax
c0002d52:	c1 e0 0c             	shl    $0xc,%eax
c0002d55:	83 ec 04             	sub    $0x4,%esp
c0002d58:	50                   	push   %eax
c0002d59:	6a 00                	push   $0x0
c0002d5b:	ff 75 f4             	push   -0xc(%ebp)
c0002d5e:	e8 e3 f5 ff ff       	call   c0002346 <memset>
c0002d63:	83 c4 10             	add    $0x10,%esp
  }
  lock_release(&user_pool.lock);
c0002d66:	83 ec 0c             	sub    $0xc,%esp
c0002d69:	68 f0 84 00 c0       	push   $0xc00084f0
c0002d6e:	e8 ab 0d 00 00       	call   c0003b1e <lock_release>
c0002d73:	83 c4 10             	add    $0x10,%esp
  return vaddr;
c0002d76:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0002d79:	c9                   	leave  
c0002d7a:	c3                   	ret    

c0002d7b <get_a_page>:

// 申请一页内存，并将vaddr映射到该页（即可指定虚拟地址
void *get_a_page(enum pool_flags pf, uint32_t vaddr) {
c0002d7b:	55                   	push   %ebp
c0002d7c:	89 e5                	mov    %esp,%ebp
c0002d7e:	83 ec 18             	sub    $0x18,%esp
  struct pool *mem_pool = pf & PF_KERNEL ? &kernel_pool : &user_pool;
c0002d81:	8b 45 08             	mov    0x8(%ebp),%eax
c0002d84:	83 e0 01             	and    $0x1,%eax
c0002d87:	85 c0                	test   %eax,%eax
c0002d89:	74 07                	je     c0002d92 <get_a_page+0x17>
c0002d8b:	b8 a0 84 00 c0       	mov    $0xc00084a0,%eax
c0002d90:	eb 05                	jmp    c0002d97 <get_a_page+0x1c>
c0002d92:	b8 e0 84 00 c0       	mov    $0xc00084e0,%eax
c0002d97:	89 45 f4             	mov    %eax,-0xc(%ebp)
  lock_acquire(&mem_pool->lock);
c0002d9a:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002d9d:	83 c0 10             	add    $0x10,%eax
c0002da0:	83 ec 0c             	sub    $0xc,%esp
c0002da3:	50                   	push   %eax
c0002da4:	e8 00 0d 00 00       	call   c0003aa9 <lock_acquire>
c0002da9:	83 c4 10             	add    $0x10,%esp
  struct task_struct *cur = running_thread();
c0002dac:	e8 91 03 00 00       	call   c0003142 <running_thread>
c0002db1:	89 45 f0             	mov    %eax,-0x10(%ebp)
  int32_t bit_idx = -1;
c0002db4:	c7 45 ec ff ff ff ff 	movl   $0xffffffff,-0x14(%ebp)

  // 位图置1操作
  if (cur->pgdir != NULL && pf == PF_USER) {
c0002dbb:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002dbe:	8b 40 30             	mov    0x30(%eax),%eax
c0002dc1:	85 c0                	test   %eax,%eax
c0002dc3:	74 53                	je     c0002e18 <get_a_page+0x9d>
c0002dc5:	83 7d 08 02          	cmpl   $0x2,0x8(%ebp)
c0002dc9:	75 4d                	jne    c0002e18 <get_a_page+0x9d>
    bit_idx = (vaddr - cur->userprog_vaddr.vaddr_start) / PG_SIZE;
c0002dcb:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002dce:	8b 50 3c             	mov    0x3c(%eax),%edx
c0002dd1:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002dd4:	29 d0                	sub    %edx,%eax
c0002dd6:	c1 e8 0c             	shr    $0xc,%eax
c0002dd9:	89 45 ec             	mov    %eax,-0x14(%ebp)
    ASSERT(bit_idx > 0);
c0002ddc:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c0002de0:	7f 1c                	jg     c0002dfe <get_a_page+0x83>
c0002de2:	68 6f 55 00 c0       	push   $0xc000556f
c0002de7:	68 c4 56 00 c0       	push   $0xc00056c4
c0002dec:	68 b6 00 00 00       	push   $0xb6
c0002df1:	68 23 55 00 c0       	push   $0xc0005523
c0002df6:	e8 75 f4 ff ff       	call   c0002270 <panic_spin>
c0002dfb:	83 c4 10             	add    $0x10,%esp
    bitmap_set(&cur->userprog_vaddr.vaddr_bitmap, bit_idx, 1);
c0002dfe:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002e01:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0002e04:	83 c2 34             	add    $0x34,%edx
c0002e07:	83 ec 04             	sub    $0x4,%esp
c0002e0a:	6a 01                	push   $0x1
c0002e0c:	50                   	push   %eax
c0002e0d:	52                   	push   %edx
c0002e0e:	e8 8e fa ff ff       	call   c00028a1 <bitmap_set>
c0002e13:	83 c4 10             	add    $0x10,%esp
c0002e16:	eb 77                	jmp    c0002e8f <get_a_page+0x114>
  } else if (cur->pgdir == NULL && pf == PF_KERNEL) {
c0002e18:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002e1b:	8b 40 30             	mov    0x30(%eax),%eax
c0002e1e:	85 c0                	test   %eax,%eax
c0002e20:	75 51                	jne    c0002e73 <get_a_page+0xf8>
c0002e22:	83 7d 08 01          	cmpl   $0x1,0x8(%ebp)
c0002e26:	75 4b                	jne    c0002e73 <get_a_page+0xf8>
    bit_idx = (vaddr - kernel_vaddr.vaddr_start) / PG_SIZE;
c0002e28:	8b 15 14 85 00 c0    	mov    0xc0008514,%edx
c0002e2e:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002e31:	29 d0                	sub    %edx,%eax
c0002e33:	c1 e8 0c             	shr    $0xc,%eax
c0002e36:	89 45 ec             	mov    %eax,-0x14(%ebp)
    ASSERT(bit_idx > 0);
c0002e39:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c0002e3d:	7f 1c                	jg     c0002e5b <get_a_page+0xe0>
c0002e3f:	68 6f 55 00 c0       	push   $0xc000556f
c0002e44:	68 c4 56 00 c0       	push   $0xc00056c4
c0002e49:	68 ba 00 00 00       	push   $0xba
c0002e4e:	68 23 55 00 c0       	push   $0xc0005523
c0002e53:	e8 18 f4 ff ff       	call   c0002270 <panic_spin>
c0002e58:	83 c4 10             	add    $0x10,%esp
    bitmap_set(&kernel_vaddr.vaddr_bitmap, bit_idx, 1);
c0002e5b:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002e5e:	83 ec 04             	sub    $0x4,%esp
c0002e61:	6a 01                	push   $0x1
c0002e63:	50                   	push   %eax
c0002e64:	68 0c 85 00 c0       	push   $0xc000850c
c0002e69:	e8 33 fa ff ff       	call   c00028a1 <bitmap_set>
c0002e6e:	83 c4 10             	add    $0x10,%esp
c0002e71:	eb 1c                	jmp    c0002e8f <get_a_page+0x114>
  } else {
    PANIC("get_a_pages: not allow kernel alloc userspace or user alloc "
c0002e73:	68 7c 55 00 c0       	push   $0xc000557c
c0002e78:	68 c4 56 00 c0       	push   $0xc00056c4
c0002e7d:	68 bd 00 00 00       	push   $0xbd
c0002e82:	68 23 55 00 c0       	push   $0xc0005523
c0002e87:	e8 e4 f3 ff ff       	call   c0002270 <panic_spin>
c0002e8c:	83 c4 10             	add    $0x10,%esp
          "kernelspace by get_a_page");
  }

  void *page_phyaddr = palloc(mem_pool);
c0002e8f:	83 ec 0c             	sub    $0xc,%esp
c0002e92:	ff 75 f4             	push   -0xc(%ebp)
c0002e95:	e8 20 fc ff ff       	call   c0002aba <palloc>
c0002e9a:	83 c4 10             	add    $0x10,%esp
c0002e9d:	89 45 e8             	mov    %eax,-0x18(%ebp)
  if (page_phyaddr == NULL) {
c0002ea0:	83 7d e8 00          	cmpl   $0x0,-0x18(%ebp)
c0002ea4:	75 07                	jne    c0002ead <get_a_page+0x132>
    return NULL;
c0002ea6:	b8 00 00 00 00       	mov    $0x0,%eax
c0002eab:	eb 27                	jmp    c0002ed4 <get_a_page+0x159>
  }
  page_table_add((void *)vaddr, page_phyaddr);
c0002ead:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002eb0:	83 ec 08             	sub    $0x8,%esp
c0002eb3:	ff 75 e8             	push   -0x18(%ebp)
c0002eb6:	50                   	push   %eax
c0002eb7:	e8 52 fc ff ff       	call   c0002b0e <page_table_add>
c0002ebc:	83 c4 10             	add    $0x10,%esp
  lock_release(&mem_pool->lock);
c0002ebf:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002ec2:	83 c0 10             	add    $0x10,%eax
c0002ec5:	83 ec 0c             	sub    $0xc,%esp
c0002ec8:	50                   	push   %eax
c0002ec9:	e8 50 0c 00 00       	call   c0003b1e <lock_release>
c0002ece:	83 c4 10             	add    $0x10,%esp
  return (void *)vaddr;
c0002ed1:	8b 45 0c             	mov    0xc(%ebp),%eax
}
c0002ed4:	c9                   	leave  
c0002ed5:	c3                   	ret    

c0002ed6 <addr_v2p>:

// 得到vaddr映射的物理地址
uint32_t addr_v2p(uint32_t vaddr) {
c0002ed6:	55                   	push   %ebp
c0002ed7:	89 e5                	mov    %esp,%ebp
c0002ed9:	83 ec 10             	sub    $0x10,%esp
  uint32_t *pte = pte_ptr(vaddr);
c0002edc:	ff 75 08             	push   0x8(%ebp)
c0002edf:	e8 8a fb ff ff       	call   c0002a6e <pte_ptr>
c0002ee4:	83 c4 04             	add    $0x4,%esp
c0002ee7:	89 45 fc             	mov    %eax,-0x4(%ebp)
  return ((*pte & 0xfffff000) +
c0002eea:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0002eed:	8b 00                	mov    (%eax),%eax
c0002eef:	25 00 f0 ff ff       	and    $0xfffff000,%eax
c0002ef4:	89 c2                	mov    %eax,%edx
          (vaddr & 0x00000fff)); // 去掉页表物理地址低12位属性 + vaddr低12位
c0002ef6:	8b 45 08             	mov    0x8(%ebp),%eax
c0002ef9:	25 ff 0f 00 00       	and    $0xfff,%eax
  return ((*pte & 0xfffff000) +
c0002efe:	09 d0                	or     %edx,%eax
}
c0002f00:	c9                   	leave  
c0002f01:	c3                   	ret    

c0002f02 <mem_pool_init>:

// 初始化内存池
static void mem_pool_init(uint32_t all_mem) {
c0002f02:	55                   	push   %ebp
c0002f03:	89 e5                	mov    %esp,%ebp
c0002f05:	83 ec 38             	sub    $0x38,%esp
  put_str("   mem_pool_init start\n");
c0002f08:	83 ec 0c             	sub    $0xc,%esp
c0002f0b:	68 d2 55 00 c0       	push   $0xc00055d2
c0002f10:	e8 5b eb ff ff       	call   c0001a70 <put_str>
c0002f15:	83 c4 10             	add    $0x10,%esp
  uint32_t page_table_size = PG_SIZE * 256; // 页表+页目录表
c0002f18:	c7 45 f4 00 00 10 00 	movl   $0x100000,-0xc(%ebp)
  uint32_t used_mem = page_table_size + 0x100000; // 已用：页表占大小+低端1MB
c0002f1f:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002f22:	05 00 00 10 00       	add    $0x100000,%eax
c0002f27:	89 45 f0             	mov    %eax,-0x10(%ebp)
  uint32_t free_mem = all_mem - used_mem;
c0002f2a:	8b 45 08             	mov    0x8(%ebp),%eax
c0002f2d:	2b 45 f0             	sub    -0x10(%ebp),%eax
c0002f30:	89 45 ec             	mov    %eax,-0x14(%ebp)
  uint16_t all_free_pages = free_mem / PG_SIZE; // free_mem转为的物理内存页数
c0002f33:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002f36:	c1 e8 0c             	shr    $0xc,%eax
c0002f39:	66 89 45 ea          	mov    %ax,-0x16(%ebp)
  uint16_t kernel_free_pages = all_free_pages / 2;
c0002f3d:	0f b7 45 ea          	movzwl -0x16(%ebp),%eax
c0002f41:	66 d1 e8             	shr    %ax
c0002f44:	66 89 45 e8          	mov    %ax,-0x18(%ebp)
  uint16_t user_free_pages = all_free_pages - kernel_free_pages;
c0002f48:	0f b7 45 ea          	movzwl -0x16(%ebp),%eax
c0002f4c:	66 2b 45 e8          	sub    -0x18(%ebp),%ax
c0002f50:	66 89 45 e6          	mov    %ax,-0x1a(%ebp)

  uint32_t kbm_len = kernel_free_pages / 8;
c0002f54:	0f b7 45 e8          	movzwl -0x18(%ebp),%eax
c0002f58:	66 c1 e8 03          	shr    $0x3,%ax
c0002f5c:	0f b7 c0             	movzwl %ax,%eax
c0002f5f:	89 45 e0             	mov    %eax,-0x20(%ebp)
  uint32_t ubm_len = user_free_pages / 8;
c0002f62:	0f b7 45 e6          	movzwl -0x1a(%ebp),%eax
c0002f66:	66 c1 e8 03          	shr    $0x3,%ax
c0002f6a:	0f b7 c0             	movzwl %ax,%eax
c0002f6d:	89 45 dc             	mov    %eax,-0x24(%ebp)

  // 内核内存池起始地址
  uint32_t kp_start = used_mem;
c0002f70:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002f73:	89 45 d8             	mov    %eax,-0x28(%ebp)
  // 用户内存池起始地址
  uint32_t up_start = kp_start + kernel_free_pages * PG_SIZE;
c0002f76:	0f b7 45 e8          	movzwl -0x18(%ebp),%eax
c0002f7a:	c1 e0 0c             	shl    $0xc,%eax
c0002f7d:	89 c2                	mov    %eax,%edx
c0002f7f:	8b 45 d8             	mov    -0x28(%ebp),%eax
c0002f82:	01 d0                	add    %edx,%eax
c0002f84:	89 45 d4             	mov    %eax,-0x2c(%ebp)

  kernel_pool.phy_addr_start = kp_start;
c0002f87:	8b 45 d8             	mov    -0x28(%ebp),%eax
c0002f8a:	a3 a8 84 00 c0       	mov    %eax,0xc00084a8
  user_pool.phy_addr_start = up_start;
c0002f8f:	8b 45 d4             	mov    -0x2c(%ebp),%eax
c0002f92:	a3 e8 84 00 c0       	mov    %eax,0xc00084e8

  kernel_pool.pool_size = kernel_free_pages * PG_SIZE;
c0002f97:	0f b7 45 e8          	movzwl -0x18(%ebp),%eax
c0002f9b:	c1 e0 0c             	shl    $0xc,%eax
c0002f9e:	a3 ac 84 00 c0       	mov    %eax,0xc00084ac
  user_pool.pool_size = user_free_pages * PG_SIZE;
c0002fa3:	0f b7 45 e6          	movzwl -0x1a(%ebp),%eax
c0002fa7:	c1 e0 0c             	shl    $0xc,%eax
c0002faa:	a3 ec 84 00 c0       	mov    %eax,0xc00084ec

  kernel_pool.pool_bitmap.btmp_bytes_len = kbm_len;
c0002faf:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0002fb2:	a3 a0 84 00 c0       	mov    %eax,0xc00084a0
  user_pool.pool_bitmap.btmp_bytes_len = ubm_len;
c0002fb7:	8b 45 dc             	mov    -0x24(%ebp),%eax
c0002fba:	a3 e0 84 00 c0       	mov    %eax,0xc00084e0

  kernel_pool.pool_bitmap.bits = (void *)MEM_BITMAP_BASE;
c0002fbf:	c7 05 a4 84 00 c0 00 	movl   $0xc009a000,0xc00084a4
c0002fc6:	a0 09 c0 
  user_pool.pool_bitmap.bits = (void *)(MEM_BITMAP_BASE + kbm_len);
c0002fc9:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0002fcc:	2d 00 60 f6 3f       	sub    $0x3ff66000,%eax
c0002fd1:	a3 e4 84 00 c0       	mov    %eax,0xc00084e4

  /* -----------------------输出内存池信息 -----------------------*/
  put_str("     kernel_pool_bitmap start: ");
c0002fd6:	83 ec 0c             	sub    $0xc,%esp
c0002fd9:	68 ec 55 00 c0       	push   $0xc00055ec
c0002fde:	e8 8d ea ff ff       	call   c0001a70 <put_str>
c0002fe3:	83 c4 10             	add    $0x10,%esp
  put_int((int)kernel_pool.pool_bitmap.bits);
c0002fe6:	a1 a4 84 00 c0       	mov    0xc00084a4,%eax
c0002feb:	83 ec 0c             	sub    $0xc,%esp
c0002fee:	50                   	push   %eax
c0002fef:	e8 68 eb ff ff       	call   c0001b5c <put_int>
c0002ff4:	83 c4 10             	add    $0x10,%esp
  put_str(" kernel_pool_phy_addr start: ");
c0002ff7:	83 ec 0c             	sub    $0xc,%esp
c0002ffa:	68 0c 56 00 c0       	push   $0xc000560c
c0002fff:	e8 6c ea ff ff       	call   c0001a70 <put_str>
c0003004:	83 c4 10             	add    $0x10,%esp
  put_int(kernel_pool.phy_addr_start);
c0003007:	a1 a8 84 00 c0       	mov    0xc00084a8,%eax
c000300c:	83 ec 0c             	sub    $0xc,%esp
c000300f:	50                   	push   %eax
c0003010:	e8 47 eb ff ff       	call   c0001b5c <put_int>
c0003015:	83 c4 10             	add    $0x10,%esp
  put_str("\n");
c0003018:	83 ec 0c             	sub    $0xc,%esp
c000301b:	68 2a 56 00 c0       	push   $0xc000562a
c0003020:	e8 4b ea ff ff       	call   c0001a70 <put_str>
c0003025:	83 c4 10             	add    $0x10,%esp
  put_str("     user_pool_bitmap start: ");
c0003028:	83 ec 0c             	sub    $0xc,%esp
c000302b:	68 2c 56 00 c0       	push   $0xc000562c
c0003030:	e8 3b ea ff ff       	call   c0001a70 <put_str>
c0003035:	83 c4 10             	add    $0x10,%esp
  put_int((int)user_pool.pool_bitmap.bits);
c0003038:	a1 e4 84 00 c0       	mov    0xc00084e4,%eax
c000303d:	83 ec 0c             	sub    $0xc,%esp
c0003040:	50                   	push   %eax
c0003041:	e8 16 eb ff ff       	call   c0001b5c <put_int>
c0003046:	83 c4 10             	add    $0x10,%esp
  put_str(" user_pool_phy_addr start: ");
c0003049:	83 ec 0c             	sub    $0xc,%esp
c000304c:	68 4a 56 00 c0       	push   $0xc000564a
c0003051:	e8 1a ea ff ff       	call   c0001a70 <put_str>
c0003056:	83 c4 10             	add    $0x10,%esp
  put_int(user_pool.phy_addr_start);
c0003059:	a1 e8 84 00 c0       	mov    0xc00084e8,%eax
c000305e:	83 ec 0c             	sub    $0xc,%esp
c0003061:	50                   	push   %eax
c0003062:	e8 f5 ea ff ff       	call   c0001b5c <put_int>
c0003067:	83 c4 10             	add    $0x10,%esp
  put_str("\n");
c000306a:	83 ec 0c             	sub    $0xc,%esp
c000306d:	68 2a 56 00 c0       	push   $0xc000562a
c0003072:	e8 f9 e9 ff ff       	call   c0001a70 <put_str>
c0003077:	83 c4 10             	add    $0x10,%esp
  bitmap_init(&kernel_pool.pool_bitmap); // 将位图置0-> 表示位对应的页未分配
c000307a:	83 ec 0c             	sub    $0xc,%esp
c000307d:	68 a0 84 00 c0       	push   $0xc00084a0
c0003082:	e8 8d f6 ff ff       	call   c0002714 <bitmap_init>
c0003087:	83 c4 10             	add    $0x10,%esp
  bitmap_init(&user_pool.pool_bitmap);
c000308a:	83 ec 0c             	sub    $0xc,%esp
c000308d:	68 e0 84 00 c0       	push   $0xc00084e0
c0003092:	e8 7d f6 ff ff       	call   c0002714 <bitmap_init>
c0003097:	83 c4 10             	add    $0x10,%esp
  lock_init(&kernel_pool.lock);
c000309a:	83 ec 0c             	sub    $0xc,%esp
c000309d:	68 b0 84 00 c0       	push   $0xc00084b0
c00030a2:	e8 28 08 00 00       	call   c00038cf <lock_init>
c00030a7:	83 c4 10             	add    $0x10,%esp
  lock_init(&user_pool.lock);
c00030aa:	83 ec 0c             	sub    $0xc,%esp
c00030ad:	68 f0 84 00 c0       	push   $0xc00084f0
c00030b2:	e8 18 08 00 00       	call   c00038cf <lock_init>
c00030b7:	83 c4 10             	add    $0x10,%esp

  // 初始化内核虚拟地址池
  kernel_vaddr.vaddr_bitmap.btmp_bytes_len = kbm_len;
c00030ba:	8b 45 e0             	mov    -0x20(%ebp),%eax
c00030bd:	a3 0c 85 00 c0       	mov    %eax,0xc000850c
  kernel_vaddr.vaddr_bitmap.bits =
      (void *)(MEM_BITMAP_BASE + kbm_len + ubm_len);
c00030c2:	8b 55 e0             	mov    -0x20(%ebp),%edx
c00030c5:	8b 45 dc             	mov    -0x24(%ebp),%eax
c00030c8:	01 d0                	add    %edx,%eax
c00030ca:	2d 00 60 f6 3f       	sub    $0x3ff66000,%eax
  kernel_vaddr.vaddr_bitmap.bits =
c00030cf:	a3 10 85 00 c0       	mov    %eax,0xc0008510
  kernel_vaddr.vaddr_start = K_HEAP_START;
c00030d4:	c7 05 14 85 00 c0 00 	movl   $0xc0100000,0xc0008514
c00030db:	00 10 c0 
  bitmap_init(&kernel_vaddr.vaddr_bitmap);
c00030de:	83 ec 0c             	sub    $0xc,%esp
c00030e1:	68 0c 85 00 c0       	push   $0xc000850c
c00030e6:	e8 29 f6 ff ff       	call   c0002714 <bitmap_init>
c00030eb:	83 c4 10             	add    $0x10,%esp
  put_str("   mem_pool_init done\n");
c00030ee:	83 ec 0c             	sub    $0xc,%esp
c00030f1:	68 66 56 00 c0       	push   $0xc0005666
c00030f6:	e8 75 e9 ff ff       	call   c0001a70 <put_str>
c00030fb:	83 c4 10             	add    $0x10,%esp
}
c00030fe:	90                   	nop
c00030ff:	c9                   	leave  
c0003100:	c3                   	ret    

c0003101 <mem_init>:

// 内存管理部分初始化入口
void mem_init() {
c0003101:	55                   	push   %ebp
c0003102:	89 e5                	mov    %esp,%ebp
c0003104:	83 ec 18             	sub    $0x18,%esp
  put_str("mem_init start\n");
c0003107:	83 ec 0c             	sub    $0xc,%esp
c000310a:	68 7d 56 00 c0       	push   $0xc000567d
c000310f:	e8 5c e9 ff ff       	call   c0001a70 <put_str>
c0003114:	83 c4 10             	add    $0x10,%esp
  uint32_t mem_bytes_total = (*(uint32_t *)(0xb00));
c0003117:	b8 00 0b 00 00       	mov    $0xb00,%eax
c000311c:	8b 00                	mov    (%eax),%eax
c000311e:	89 45 f4             	mov    %eax,-0xc(%ebp)
  mem_pool_init(mem_bytes_total); // 初始化内存池
c0003121:	83 ec 0c             	sub    $0xc,%esp
c0003124:	ff 75 f4             	push   -0xc(%ebp)
c0003127:	e8 d6 fd ff ff       	call   c0002f02 <mem_pool_init>
c000312c:	83 c4 10             	add    $0x10,%esp
  put_str("mem_init done\n");
c000312f:	83 ec 0c             	sub    $0xc,%esp
c0003132:	68 8d 56 00 c0       	push   $0xc000568d
c0003137:	e8 34 e9 ff ff       	call   c0001a70 <put_str>
c000313c:	83 c4 10             	add    $0x10,%esp
c000313f:	90                   	nop
c0003140:	c9                   	leave  
c0003141:	c3                   	ret    

c0003142 <running_thread>:

// 保存cur线程的寄存器映像，将下个线程next的寄存器映像装载到处理器
extern void switch_to(struct task_struct *cur, struct task_struct *next);

// 获取当前线程的pcb指针
struct task_struct *running_thread() {
c0003142:	55                   	push   %ebp
c0003143:	89 e5                	mov    %esp,%ebp
c0003145:	83 ec 10             	sub    $0x10,%esp
  uint32_t esp;
  asm("mov %%esp, %0" : "=g"(esp));
c0003148:	89 e0                	mov    %esp,%eax
c000314a:	89 45 fc             	mov    %eax,-0x4(%ebp)
  return (struct task_struct *)(esp &
c000314d:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0003150:	25 00 f0 ff ff       	and    $0xfffff000,%eax
                                0xfffff000); // 取esp整数部分，即pcb起始地址
}
c0003155:	c9                   	leave  
c0003156:	c3                   	ret    

c0003157 <kernel_thread>:

// 由kernel_thread去执行func(func_arg)
static void kernel_thread(thread_func *func, void *func_arg) {
c0003157:	55                   	push   %ebp
c0003158:	89 e5                	mov    %esp,%ebp
c000315a:	83 ec 08             	sub    $0x8,%esp
  intr_enable(); // 开中断避免func独享处理器
c000315d:	e8 02 e8 ff ff       	call   c0001964 <intr_enable>
  func(func_arg);
c0003162:	83 ec 0c             	sub    $0xc,%esp
c0003165:	ff 75 0c             	push   0xc(%ebp)
c0003168:	8b 45 08             	mov    0x8(%ebp),%eax
c000316b:	ff d0                	call   *%eax
c000316d:	83 c4 10             	add    $0x10,%esp
}
c0003170:	90                   	nop
c0003171:	c9                   	leave  
c0003172:	c3                   	ret    

c0003173 <thread_create>:

// 初始化线程栈，将待执行func和func_arg放到栈中相应位置
void thread_create(struct task_struct *pthread, thread_func func,
                   void *func_arg) {
c0003173:	55                   	push   %ebp
c0003174:	89 e5                	mov    %esp,%ebp
c0003176:	83 ec 10             	sub    $0x10,%esp
  pthread->self_kstack -= sizeof(struct intr_stack); // 预留中断使用栈的空间
c0003179:	8b 45 08             	mov    0x8(%ebp),%eax
c000317c:	8b 00                	mov    (%eax),%eax
c000317e:	8d 90 d0 fe ff ff    	lea    -0x130(%eax),%edx
c0003184:	8b 45 08             	mov    0x8(%ebp),%eax
c0003187:	89 10                	mov    %edx,(%eax)
  pthread->self_kstack -= sizeof(struct thread_stack); // 预留线程栈空间
c0003189:	8b 45 08             	mov    0x8(%ebp),%eax
c000318c:	8b 00                	mov    (%eax),%eax
c000318e:	8d 50 80             	lea    -0x80(%eax),%edx
c0003191:	8b 45 08             	mov    0x8(%ebp),%eax
c0003194:	89 10                	mov    %edx,(%eax)

  struct thread_stack *kthread_stack =
c0003196:	8b 45 08             	mov    0x8(%ebp),%eax
c0003199:	8b 00                	mov    (%eax),%eax
c000319b:	89 45 fc             	mov    %eax,-0x4(%ebp)
      (struct thread_stack *)pthread->self_kstack;

  // kernel_thread使用ret方式调用
  kthread_stack->eip = kernel_thread;
c000319e:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00031a1:	c7 40 10 57 31 00 c0 	movl   $0xc0003157,0x10(%eax)
  kthread_stack->function = func;
c00031a8:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00031ab:	8b 55 0c             	mov    0xc(%ebp),%edx
c00031ae:	89 50 18             	mov    %edx,0x18(%eax)
  kthread_stack->func_arg = func_arg;
c00031b1:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00031b4:	8b 55 10             	mov    0x10(%ebp),%edx
c00031b7:	89 50 1c             	mov    %edx,0x1c(%eax)

  kthread_stack->ebp = kthread_stack->ebx = kthread_stack->esi =
      kthread_stack->edi = 0;
c00031ba:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00031bd:	c7 40 08 00 00 00 00 	movl   $0x0,0x8(%eax)
c00031c4:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00031c7:	8b 50 08             	mov    0x8(%eax),%edx
  kthread_stack->ebp = kthread_stack->ebx = kthread_stack->esi =
c00031ca:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00031cd:	89 50 0c             	mov    %edx,0xc(%eax)
c00031d0:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00031d3:	8b 50 0c             	mov    0xc(%eax),%edx
c00031d6:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00031d9:	89 50 04             	mov    %edx,0x4(%eax)
c00031dc:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00031df:	8b 50 04             	mov    0x4(%eax),%edx
c00031e2:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00031e5:	89 10                	mov    %edx,(%eax)
}
c00031e7:	90                   	nop
c00031e8:	c9                   	leave  
c00031e9:	c3                   	ret    

c00031ea <init_thread>:

// 初始化线程基本信息
void init_thread(struct task_struct *pthread, char *name, int prio) {
c00031ea:	55                   	push   %ebp
c00031eb:	89 e5                	mov    %esp,%ebp
c00031ed:	83 ec 08             	sub    $0x8,%esp
  memset(pthread, 0, sizeof(*pthread)); // PCB一页清0
c00031f0:	83 ec 04             	sub    $0x4,%esp
c00031f3:	6a 44                	push   $0x44
c00031f5:	6a 00                	push   $0x0
c00031f7:	ff 75 08             	push   0x8(%ebp)
c00031fa:	e8 47 f1 ff ff       	call   c0002346 <memset>
c00031ff:	83 c4 10             	add    $0x10,%esp
  strcpy(pthread->name, name);
c0003202:	8b 45 08             	mov    0x8(%ebp),%eax
c0003205:	83 c0 08             	add    $0x8,%eax
c0003208:	83 ec 08             	sub    $0x8,%esp
c000320b:	ff 75 0c             	push   0xc(%ebp)
c000320e:	50                   	push   %eax
c000320f:	e8 69 f2 ff ff       	call   c000247d <strcpy>
c0003214:	83 c4 10             	add    $0x10,%esp

  if (pthread == main_thread) {
c0003217:	a1 18 85 00 c0       	mov    0xc0008518,%eax
c000321c:	39 45 08             	cmp    %eax,0x8(%ebp)
c000321f:	75 0c                	jne    c000322d <init_thread+0x43>
    pthread->status = TASK_RUNNING;
c0003221:	8b 45 08             	mov    0x8(%ebp),%eax
c0003224:	c7 40 04 00 00 00 00 	movl   $0x0,0x4(%eax)
c000322b:	eb 0a                	jmp    c0003237 <init_thread+0x4d>
  } else {
    pthread->status = TASK_READY;
c000322d:	8b 45 08             	mov    0x8(%ebp),%eax
c0003230:	c7 40 04 01 00 00 00 	movl   $0x1,0x4(%eax)
  }

  pthread->self_kstack =
      (uint32_t *)((uint32_t)pthread + PG_SIZE); // 线程的内核栈顶地址
c0003237:	8b 45 08             	mov    0x8(%ebp),%eax
c000323a:	05 00 10 00 00       	add    $0x1000,%eax
c000323f:	89 c2                	mov    %eax,%edx
  pthread->self_kstack =
c0003241:	8b 45 08             	mov    0x8(%ebp),%eax
c0003244:	89 10                	mov    %edx,(%eax)
  pthread->priority = prio;
c0003246:	8b 45 10             	mov    0x10(%ebp),%eax
c0003249:	89 c2                	mov    %eax,%edx
c000324b:	8b 45 08             	mov    0x8(%ebp),%eax
c000324e:	88 50 18             	mov    %dl,0x18(%eax)
  pthread->ticks = prio;
c0003251:	8b 45 10             	mov    0x10(%ebp),%eax
c0003254:	89 c2                	mov    %eax,%edx
c0003256:	8b 45 08             	mov    0x8(%ebp),%eax
c0003259:	88 50 19             	mov    %dl,0x19(%eax)
  pthread->elapsed_ticks = 0;
c000325c:	8b 45 08             	mov    0x8(%ebp),%eax
c000325f:	c7 40 1c 00 00 00 00 	movl   $0x0,0x1c(%eax)
  pthread->pgdir = NULL;
c0003266:	8b 45 08             	mov    0x8(%ebp),%eax
c0003269:	c7 40 30 00 00 00 00 	movl   $0x0,0x30(%eax)
  pthread->stack_magic = 0x20021112; // 自定义魔数
c0003270:	8b 45 08             	mov    0x8(%ebp),%eax
c0003273:	c7 40 40 12 11 02 20 	movl   $0x20021112,0x40(%eax)
}
c000327a:	90                   	nop
c000327b:	c9                   	leave  
c000327c:	c3                   	ret    

c000327d <thread_start>:

// 创建线程，线程执行函数是function(func_arg)
struct task_struct *thread_start(char *name, int prio, thread_func func,
                                 void *func_arg) {
c000327d:	55                   	push   %ebp
c000327e:	89 e5                	mov    %esp,%ebp
c0003280:	83 ec 18             	sub    $0x18,%esp
  struct task_struct *thread = get_kernel_pages(1); // PCB指针->最低地址
c0003283:	83 ec 0c             	sub    $0xc,%esp
c0003286:	6a 01                	push   $0x1
c0003288:	e8 58 fa ff ff       	call   c0002ce5 <get_kernel_pages>
c000328d:	83 c4 10             	add    $0x10,%esp
c0003290:	89 45 f4             	mov    %eax,-0xc(%ebp)
  init_thread(thread, name, prio);
c0003293:	83 ec 04             	sub    $0x4,%esp
c0003296:	ff 75 0c             	push   0xc(%ebp)
c0003299:	ff 75 08             	push   0x8(%ebp)
c000329c:	ff 75 f4             	push   -0xc(%ebp)
c000329f:	e8 46 ff ff ff       	call   c00031ea <init_thread>
c00032a4:	83 c4 10             	add    $0x10,%esp
  thread_create(thread, func, func_arg);
c00032a7:	83 ec 04             	sub    $0x4,%esp
c00032aa:	ff 75 14             	push   0x14(%ebp)
c00032ad:	ff 75 10             	push   0x10(%ebp)
c00032b0:	ff 75 f4             	push   -0xc(%ebp)
c00032b3:	e8 bb fe ff ff       	call   c0003173 <thread_create>
c00032b8:	83 c4 10             	add    $0x10,%esp

  ASSERT(!elem_find(&thread_ready_list, &thread->general_tag));
c00032bb:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00032be:	83 c0 20             	add    $0x20,%eax
c00032c1:	83 ec 08             	sub    $0x8,%esp
c00032c4:	50                   	push   %eax
c00032c5:	68 1c 85 00 c0       	push   $0xc000851c
c00032ca:	e8 d6 04 00 00       	call   c00037a5 <elem_find>
c00032cf:	83 c4 10             	add    $0x10,%esp
c00032d2:	85 c0                	test   %eax,%eax
c00032d4:	74 19                	je     c00032ef <thread_start+0x72>
c00032d6:	68 d0 56 00 c0       	push   $0xc00056d0
c00032db:	68 50 59 00 c0       	push   $0xc0005950
c00032e0:	6a 52                	push   $0x52
c00032e2:	68 05 57 00 c0       	push   $0xc0005705
c00032e7:	e8 84 ef ff ff       	call   c0002270 <panic_spin>
c00032ec:	83 c4 10             	add    $0x10,%esp
  list_append(&thread_ready_list, &thread->general_tag); // 加入就绪线程队列
c00032ef:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00032f2:	83 c0 20             	add    $0x20,%eax
c00032f5:	83 ec 08             	sub    $0x8,%esp
c00032f8:	50                   	push   %eax
c00032f9:	68 1c 85 00 c0       	push   $0xc000851c
c00032fe:	e8 28 04 00 00       	call   c000372b <list_append>
c0003303:	83 c4 10             	add    $0x10,%esp
  ASSERT(!elem_find(&thread_all_list, &thread->all_list_tag));
c0003306:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003309:	83 c0 28             	add    $0x28,%eax
c000330c:	83 ec 08             	sub    $0x8,%esp
c000330f:	50                   	push   %eax
c0003310:	68 2c 85 00 c0       	push   $0xc000852c
c0003315:	e8 8b 04 00 00       	call   c00037a5 <elem_find>
c000331a:	83 c4 10             	add    $0x10,%esp
c000331d:	85 c0                	test   %eax,%eax
c000331f:	74 19                	je     c000333a <thread_start+0xbd>
c0003321:	68 18 57 00 c0       	push   $0xc0005718
c0003326:	68 50 59 00 c0       	push   $0xc0005950
c000332b:	6a 54                	push   $0x54
c000332d:	68 05 57 00 c0       	push   $0xc0005705
c0003332:	e8 39 ef ff ff       	call   c0002270 <panic_spin>
c0003337:	83 c4 10             	add    $0x10,%esp
  list_append(&thread_all_list, &thread->all_list_tag); // 加入全部线程队列
c000333a:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000333d:	83 c0 28             	add    $0x28,%eax
c0003340:	83 ec 08             	sub    $0x8,%esp
c0003343:	50                   	push   %eax
c0003344:	68 2c 85 00 c0       	push   $0xc000852c
c0003349:	e8 dd 03 00 00       	call   c000372b <list_append>
c000334e:	83 c4 10             	add    $0x10,%esp

  return thread;
c0003351:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0003354:	c9                   	leave  
c0003355:	c3                   	ret    

c0003356 <make_main_thread>:

// 将kernel中的main函数完善为主线程
static void make_main_thread(void) {
c0003356:	55                   	push   %ebp
c0003357:	89 e5                	mov    %esp,%ebp
c0003359:	83 ec 08             	sub    $0x8,%esp
  main_thread = running_thread();
c000335c:	e8 e1 fd ff ff       	call   c0003142 <running_thread>
c0003361:	a3 18 85 00 c0       	mov    %eax,0xc0008518
  init_thread(main_thread, "main", 31);
c0003366:	a1 18 85 00 c0       	mov    0xc0008518,%eax
c000336b:	83 ec 04             	sub    $0x4,%esp
c000336e:	6a 1f                	push   $0x1f
c0003370:	68 4c 57 00 c0       	push   $0xc000574c
c0003375:	50                   	push   %eax
c0003376:	e8 6f fe ff ff       	call   c00031ea <init_thread>
c000337b:	83 c4 10             	add    $0x10,%esp

  ASSERT(!elem_find(&thread_all_list, &main_thread->all_list_tag));
c000337e:	a1 18 85 00 c0       	mov    0xc0008518,%eax
c0003383:	83 c0 28             	add    $0x28,%eax
c0003386:	83 ec 08             	sub    $0x8,%esp
c0003389:	50                   	push   %eax
c000338a:	68 2c 85 00 c0       	push   $0xc000852c
c000338f:	e8 11 04 00 00       	call   c00037a5 <elem_find>
c0003394:	83 c4 10             	add    $0x10,%esp
c0003397:	85 c0                	test   %eax,%eax
c0003399:	74 19                	je     c00033b4 <make_main_thread+0x5e>
c000339b:	68 54 57 00 c0       	push   $0xc0005754
c00033a0:	68 60 59 00 c0       	push   $0xc0005960
c00033a5:	6a 5f                	push   $0x5f
c00033a7:	68 05 57 00 c0       	push   $0xc0005705
c00033ac:	e8 bf ee ff ff       	call   c0002270 <panic_spin>
c00033b1:	83 c4 10             	add    $0x10,%esp
  list_append(&thread_all_list, &main_thread->all_list_tag);
c00033b4:	a1 18 85 00 c0       	mov    0xc0008518,%eax
c00033b9:	83 c0 28             	add    $0x28,%eax
c00033bc:	83 ec 08             	sub    $0x8,%esp
c00033bf:	50                   	push   %eax
c00033c0:	68 2c 85 00 c0       	push   $0xc000852c
c00033c5:	e8 61 03 00 00       	call   c000372b <list_append>
c00033ca:	83 c4 10             	add    $0x10,%esp
}
c00033cd:	90                   	nop
c00033ce:	c9                   	leave  
c00033cf:	c3                   	ret    

c00033d0 <schedule>:

// 调度函数
void schedule() {
c00033d0:	55                   	push   %ebp
c00033d1:	89 e5                	mov    %esp,%ebp
c00033d3:	83 ec 18             	sub    $0x18,%esp
  ASSERT(intr_get_status() == INTR_OFF); // 关中断状态
c00033d6:	e8 16 e6 ff ff       	call   c00019f1 <intr_get_status>
c00033db:	85 c0                	test   %eax,%eax
c00033dd:	74 19                	je     c00033f8 <schedule+0x28>
c00033df:	68 8d 57 00 c0       	push   $0xc000578d
c00033e4:	68 74 59 00 c0       	push   $0xc0005974
c00033e9:	6a 65                	push   $0x65
c00033eb:	68 05 57 00 c0       	push   $0xc0005705
c00033f0:	e8 7b ee ff ff       	call   c0002270 <panic_spin>
c00033f5:	83 c4 10             	add    $0x10,%esp

  struct task_struct *cur = running_thread();
c00033f8:	e8 45 fd ff ff       	call   c0003142 <running_thread>
c00033fd:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (cur->status == TASK_RUNNING) { // 时间片到了-> 加入就绪队列队尾
c0003400:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003403:	8b 40 04             	mov    0x4(%eax),%eax
c0003406:	85 c0                	test   %eax,%eax
c0003408:	75 62                	jne    c000346c <schedule+0x9c>
    ASSERT(!elem_find(&thread_ready_list, &cur->general_tag));
c000340a:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000340d:	83 c0 20             	add    $0x20,%eax
c0003410:	83 ec 08             	sub    $0x8,%esp
c0003413:	50                   	push   %eax
c0003414:	68 1c 85 00 c0       	push   $0xc000851c
c0003419:	e8 87 03 00 00       	call   c00037a5 <elem_find>
c000341e:	83 c4 10             	add    $0x10,%esp
c0003421:	85 c0                	test   %eax,%eax
c0003423:	74 19                	je     c000343e <schedule+0x6e>
c0003425:	68 ac 57 00 c0       	push   $0xc00057ac
c000342a:	68 74 59 00 c0       	push   $0xc0005974
c000342f:	6a 69                	push   $0x69
c0003431:	68 05 57 00 c0       	push   $0xc0005705
c0003436:	e8 35 ee ff ff       	call   c0002270 <panic_spin>
c000343b:	83 c4 10             	add    $0x10,%esp
    list_append(&thread_ready_list, &cur->general_tag);
c000343e:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003441:	83 c0 20             	add    $0x20,%eax
c0003444:	83 ec 08             	sub    $0x8,%esp
c0003447:	50                   	push   %eax
c0003448:	68 1c 85 00 c0       	push   $0xc000851c
c000344d:	e8 d9 02 00 00       	call   c000372b <list_append>
c0003452:	83 c4 10             	add    $0x10,%esp
    cur->ticks = cur->priority;
c0003455:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003458:	0f b6 50 18          	movzbl 0x18(%eax),%edx
c000345c:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000345f:	88 50 19             	mov    %dl,0x19(%eax)
    cur->status = TASK_READY;
c0003462:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003465:	c7 40 04 01 00 00 00 	movl   $0x1,0x4(%eax)
  } else {
    // TODO：阻塞情况-> 加入阻塞队列
  }

  ASSERT(!list_empty(&thread_ready_list));
c000346c:	83 ec 0c             	sub    $0xc,%esp
c000346f:	68 1c 85 00 c0       	push   $0xc000851c
c0003474:	e8 f9 03 00 00       	call   c0003872 <list_empty>
c0003479:	83 c4 10             	add    $0x10,%esp
c000347c:	85 c0                	test   %eax,%eax
c000347e:	74 19                	je     c0003499 <schedule+0xc9>
c0003480:	68 e0 57 00 c0       	push   $0xc00057e0
c0003485:	68 74 59 00 c0       	push   $0xc0005974
c000348a:	6a 71                	push   $0x71
c000348c:	68 05 57 00 c0       	push   $0xc0005705
c0003491:	e8 da ed ff ff       	call   c0002270 <panic_spin>
c0003496:	83 c4 10             	add    $0x10,%esp
  thread_tag = NULL;
c0003499:	c7 05 3c 85 00 c0 00 	movl   $0x0,0xc000853c
c00034a0:	00 00 00 
  thread_tag =
      list_pop(&thread_ready_list); // 弹出就绪队列中的下一个处理线程结点（tag）
c00034a3:	83 ec 0c             	sub    $0xc,%esp
c00034a6:	68 1c 85 00 c0       	push   $0xc000851c
c00034ab:	e8 d3 02 00 00       	call   c0003783 <list_pop>
c00034b0:	83 c4 10             	add    $0x10,%esp
  thread_tag =
c00034b3:	a3 3c 85 00 c0       	mov    %eax,0xc000853c
  struct task_struct *next =
      elem2entry(struct task_struct, general_tag, thread_tag);
c00034b8:	a1 3c 85 00 c0       	mov    0xc000853c,%eax
c00034bd:	83 e8 20             	sub    $0x20,%eax
  struct task_struct *next =
c00034c0:	89 45 f0             	mov    %eax,-0x10(%ebp)
  next->status = TASK_RUNNING;
c00034c3:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00034c6:	c7 40 04 00 00 00 00 	movl   $0x0,0x4(%eax)

  /* 激活页表，并根据任务是否为进程来修改tss.esp0 */
  process_active(next);
c00034cd:	83 ec 0c             	sub    $0xc,%esp
c00034d0:	ff 75 f0             	push   -0x10(%ebp)
c00034d3:	e8 13 10 00 00       	call   c00044eb <process_active>
c00034d8:	83 c4 10             	add    $0x10,%esp
  // 从此之后进程/线程一律作为内核线程去处理（0特权级、使用内核页表）

  switch_to(cur, next); // 任务切换
c00034db:	83 ec 08             	sub    $0x8,%esp
c00034de:	ff 75 f0             	push   -0x10(%ebp)
c00034e1:	ff 75 f4             	push   -0xc(%ebp)
c00034e4:	e8 a7 03 00 00       	call   c0003890 <switch_to>
c00034e9:	83 c4 10             	add    $0x10,%esp
}
c00034ec:	90                   	nop
c00034ed:	c9                   	leave  
c00034ee:	c3                   	ret    

c00034ef <thread_init>:

// 初始化线程环境
void thread_init(void) {
c00034ef:	55                   	push   %ebp
c00034f0:	89 e5                	mov    %esp,%ebp
c00034f2:	83 ec 08             	sub    $0x8,%esp
  put_str("thread_init start\n");
c00034f5:	83 ec 0c             	sub    $0xc,%esp
c00034f8:	68 00 58 00 c0       	push   $0xc0005800
c00034fd:	e8 6e e5 ff ff       	call   c0001a70 <put_str>
c0003502:	83 c4 10             	add    $0x10,%esp
  list_init(&thread_ready_list);
c0003505:	83 ec 0c             	sub    $0xc,%esp
c0003508:	68 1c 85 00 c0       	push   $0xc000851c
c000350d:	e8 88 01 00 00       	call   c000369a <list_init>
c0003512:	83 c4 10             	add    $0x10,%esp
  list_init(&thread_all_list);
c0003515:	83 ec 0c             	sub    $0xc,%esp
c0003518:	68 2c 85 00 c0       	push   $0xc000852c
c000351d:	e8 78 01 00 00       	call   c000369a <list_init>
c0003522:	83 c4 10             	add    $0x10,%esp
  make_main_thread(); // 为当前main函数创建线程，在其pcb中写入线程信息
c0003525:	e8 2c fe ff ff       	call   c0003356 <make_main_thread>
  put_str("thread_init done\n");
c000352a:	83 ec 0c             	sub    $0xc,%esp
c000352d:	68 13 58 00 c0       	push   $0xc0005813
c0003532:	e8 39 e5 ff ff       	call   c0001a70 <put_str>
c0003537:	83 c4 10             	add    $0x10,%esp
}
c000353a:	90                   	nop
c000353b:	c9                   	leave  
c000353c:	c3                   	ret    

c000353d <thread_block>:

// 线程自愿阻塞，标志状态为stat
void thread_block(enum task_status stat) {
c000353d:	55                   	push   %ebp
c000353e:	89 e5                	mov    %esp,%ebp
c0003540:	83 ec 18             	sub    $0x18,%esp
  // TASK_BLOCKED、TASK_WAITING、TASK_HANGING三种状态不会被调度
  ASSERT(((stat == TASK_BLOCKED) || (stat == TASK_WAITING) ||
c0003543:	83 7d 08 02          	cmpl   $0x2,0x8(%ebp)
c0003547:	74 28                	je     c0003571 <thread_block+0x34>
c0003549:	83 7d 08 03          	cmpl   $0x3,0x8(%ebp)
c000354d:	74 22                	je     c0003571 <thread_block+0x34>
c000354f:	83 7d 08 04          	cmpl   $0x4,0x8(%ebp)
c0003553:	74 1c                	je     c0003571 <thread_block+0x34>
c0003555:	68 28 58 00 c0       	push   $0xc0005828
c000355a:	68 80 59 00 c0       	push   $0xc0005980
c000355f:	68 8c 00 00 00       	push   $0x8c
c0003564:	68 05 57 00 c0       	push   $0xc0005705
c0003569:	e8 02 ed ff ff       	call   c0002270 <panic_spin>
c000356e:	83 c4 10             	add    $0x10,%esp
          (stat == TASK_HANGING)));
  enum intr_status old_status = intr_disable();
c0003571:	e8 17 e4 ff ff       	call   c000198d <intr_disable>
c0003576:	89 45 f4             	mov    %eax,-0xc(%ebp)
  struct task_struct *cur_thread = running_thread();
c0003579:	e8 c4 fb ff ff       	call   c0003142 <running_thread>
c000357e:	89 45 f0             	mov    %eax,-0x10(%ebp)
  cur_thread->status = stat; // 修改状态为非RUNNING，不让其回到ready_list中
c0003581:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0003584:	8b 55 08             	mov    0x8(%ebp),%edx
c0003587:	89 50 04             	mov    %edx,0x4(%eax)
  schedule();                // 将当前线程换下处理器
c000358a:	e8 41 fe ff ff       	call   c00033d0 <schedule>
  intr_set_status(old_status); // 待当前线程被解除阻塞后才继续运行
c000358f:	83 ec 0c             	sub    $0xc,%esp
c0003592:	ff 75 f4             	push   -0xc(%ebp)
c0003595:	e8 39 e4 ff ff       	call   c00019d3 <intr_set_status>
c000359a:	83 c4 10             	add    $0x10,%esp
}
c000359d:	90                   	nop
c000359e:	c9                   	leave  
c000359f:	c3                   	ret    

c00035a0 <thread_unblock>:

// 线程唤醒
void thread_unblock(struct task_struct *pthread) {
c00035a0:	55                   	push   %ebp
c00035a1:	89 e5                	mov    %esp,%ebp
c00035a3:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status = intr_disable();
c00035a6:	e8 e2 e3 ff ff       	call   c000198d <intr_disable>
c00035ab:	89 45 f4             	mov    %eax,-0xc(%ebp)
  ASSERT(((pthread->status == TASK_BLOCKED) ||
c00035ae:	8b 45 08             	mov    0x8(%ebp),%eax
c00035b1:	8b 40 04             	mov    0x4(%eax),%eax
c00035b4:	83 f8 02             	cmp    $0x2,%eax
c00035b7:	74 32                	je     c00035eb <thread_unblock+0x4b>
c00035b9:	8b 45 08             	mov    0x8(%ebp),%eax
c00035bc:	8b 40 04             	mov    0x4(%eax),%eax
c00035bf:	83 f8 03             	cmp    $0x3,%eax
c00035c2:	74 27                	je     c00035eb <thread_unblock+0x4b>
c00035c4:	8b 45 08             	mov    0x8(%ebp),%eax
c00035c7:	8b 40 04             	mov    0x4(%eax),%eax
c00035ca:	83 f8 04             	cmp    $0x4,%eax
c00035cd:	74 1c                	je     c00035eb <thread_unblock+0x4b>
c00035cf:	68 78 58 00 c0       	push   $0xc0005878
c00035d4:	68 90 59 00 c0       	push   $0xc0005990
c00035d9:	68 98 00 00 00       	push   $0x98
c00035de:	68 05 57 00 c0       	push   $0xc0005705
c00035e3:	e8 88 ec ff ff       	call   c0002270 <panic_spin>
c00035e8:	83 c4 10             	add    $0x10,%esp
          (pthread->status == TASK_WAITING) ||
          (pthread->status == TASK_HANGING)));
  if (pthread->status != TASK_READY) {
c00035eb:	8b 45 08             	mov    0x8(%ebp),%eax
c00035ee:	8b 40 04             	mov    0x4(%eax),%eax
c00035f1:	83 f8 01             	cmp    $0x1,%eax
c00035f4:	0f 84 8f 00 00 00    	je     c0003689 <thread_unblock+0xe9>
    ASSERT(!elem_find(&thread_ready_list, &pthread->general_tag));
c00035fa:	8b 45 08             	mov    0x8(%ebp),%eax
c00035fd:	83 c0 20             	add    $0x20,%eax
c0003600:	83 ec 08             	sub    $0x8,%esp
c0003603:	50                   	push   %eax
c0003604:	68 1c 85 00 c0       	push   $0xc000851c
c0003609:	e8 97 01 00 00       	call   c00037a5 <elem_find>
c000360e:	83 c4 10             	add    $0x10,%esp
c0003611:	85 c0                	test   %eax,%eax
c0003613:	74 1c                	je     c0003631 <thread_unblock+0x91>
c0003615:	68 e8 58 00 c0       	push   $0xc00058e8
c000361a:	68 90 59 00 c0       	push   $0xc0005990
c000361f:	68 9c 00 00 00       	push   $0x9c
c0003624:	68 05 57 00 c0       	push   $0xc0005705
c0003629:	e8 42 ec ff ff       	call   c0002270 <panic_spin>
c000362e:	83 c4 10             	add    $0x10,%esp
    if (elem_find(&thread_ready_list, &pthread->general_tag)) {
c0003631:	8b 45 08             	mov    0x8(%ebp),%eax
c0003634:	83 c0 20             	add    $0x20,%eax
c0003637:	83 ec 08             	sub    $0x8,%esp
c000363a:	50                   	push   %eax
c000363b:	68 1c 85 00 c0       	push   $0xc000851c
c0003640:	e8 60 01 00 00       	call   c00037a5 <elem_find>
c0003645:	83 c4 10             	add    $0x10,%esp
c0003648:	85 c0                	test   %eax,%eax
c000364a:	74 1c                	je     c0003668 <thread_unblock+0xc8>
      PANIC("thread_unblock: blocked thread in ready_list\n");
c000364c:	68 20 59 00 c0       	push   $0xc0005920
c0003651:	68 90 59 00 c0       	push   $0xc0005990
c0003656:	68 9e 00 00 00       	push   $0x9e
c000365b:	68 05 57 00 c0       	push   $0xc0005705
c0003660:	e8 0b ec ff ff       	call   c0002270 <panic_spin>
c0003665:	83 c4 10             	add    $0x10,%esp
    }
    list_push(&thread_ready_list,
c0003668:	8b 45 08             	mov    0x8(%ebp),%eax
c000366b:	83 c0 20             	add    $0x20,%eax
c000366e:	83 ec 08             	sub    $0x8,%esp
c0003671:	50                   	push   %eax
c0003672:	68 1c 85 00 c0       	push   $0xc000851c
c0003677:	e8 91 00 00 00       	call   c000370d <list_push>
c000367c:	83 c4 10             	add    $0x10,%esp
              &pthread->general_tag); // 放在就绪队列最前面(尽快调度
    pthread->status = TASK_READY;
c000367f:	8b 45 08             	mov    0x8(%ebp),%eax
c0003682:	c7 40 04 01 00 00 00 	movl   $0x1,0x4(%eax)
  }
  intr_set_status(old_status);
c0003689:	83 ec 0c             	sub    $0xc,%esp
c000368c:	ff 75 f4             	push   -0xc(%ebp)
c000368f:	e8 3f e3 ff ff       	call   c00019d3 <intr_set_status>
c0003694:	83 c4 10             	add    $0x10,%esp
c0003697:	90                   	nop
c0003698:	c9                   	leave  
c0003699:	c3                   	ret    

c000369a <list_init>:
#include "list.h"
#include "global.h"
#include "interrupt.h"
#include <stdint.h>

void list_init(struct list *list) {
c000369a:	55                   	push   %ebp
c000369b:	89 e5                	mov    %esp,%ebp
  list->head.prev = NULL;
c000369d:	8b 45 08             	mov    0x8(%ebp),%eax
c00036a0:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
  list->head.next = &list->tail;
c00036a6:	8b 45 08             	mov    0x8(%ebp),%eax
c00036a9:	8d 50 08             	lea    0x8(%eax),%edx
c00036ac:	8b 45 08             	mov    0x8(%ebp),%eax
c00036af:	89 50 04             	mov    %edx,0x4(%eax)
  list->tail.prev = &list->head;
c00036b2:	8b 55 08             	mov    0x8(%ebp),%edx
c00036b5:	8b 45 08             	mov    0x8(%ebp),%eax
c00036b8:	89 50 08             	mov    %edx,0x8(%eax)
  list->tail.next = NULL;
c00036bb:	8b 45 08             	mov    0x8(%ebp),%eax
c00036be:	c7 40 0c 00 00 00 00 	movl   $0x0,0xc(%eax)
}
c00036c5:	90                   	nop
c00036c6:	5d                   	pop    %ebp
c00036c7:	c3                   	ret    

c00036c8 <list_insert_before>:

// 把elem插入在元素before之前
void list_insert_before(struct list_elem *before, struct list_elem *elem) {
c00036c8:	55                   	push   %ebp
c00036c9:	89 e5                	mov    %esp,%ebp
c00036cb:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status = intr_disable(); // 关中断保证原子性
c00036ce:	e8 ba e2 ff ff       	call   c000198d <intr_disable>
c00036d3:	89 45 f4             	mov    %eax,-0xc(%ebp)
  before->prev->next = elem;
c00036d6:	8b 45 08             	mov    0x8(%ebp),%eax
c00036d9:	8b 00                	mov    (%eax),%eax
c00036db:	8b 55 0c             	mov    0xc(%ebp),%edx
c00036de:	89 50 04             	mov    %edx,0x4(%eax)
  elem->prev = before->prev;
c00036e1:	8b 45 08             	mov    0x8(%ebp),%eax
c00036e4:	8b 10                	mov    (%eax),%edx
c00036e6:	8b 45 0c             	mov    0xc(%ebp),%eax
c00036e9:	89 10                	mov    %edx,(%eax)
  elem->next = before;
c00036eb:	8b 45 0c             	mov    0xc(%ebp),%eax
c00036ee:	8b 55 08             	mov    0x8(%ebp),%edx
c00036f1:	89 50 04             	mov    %edx,0x4(%eax)
  before->prev = elem;
c00036f4:	8b 45 08             	mov    0x8(%ebp),%eax
c00036f7:	8b 55 0c             	mov    0xc(%ebp),%edx
c00036fa:	89 10                	mov    %edx,(%eax)
  intr_set_status(old_status);
c00036fc:	83 ec 0c             	sub    $0xc,%esp
c00036ff:	ff 75 f4             	push   -0xc(%ebp)
c0003702:	e8 cc e2 ff ff       	call   c00019d3 <intr_set_status>
c0003707:	83 c4 10             	add    $0x10,%esp
}
c000370a:	90                   	nop
c000370b:	c9                   	leave  
c000370c:	c3                   	ret    

c000370d <list_push>:

// 添加元素到列表队首
void list_push(struct list *plist, struct list_elem *elem) {
c000370d:	55                   	push   %ebp
c000370e:	89 e5                	mov    %esp,%ebp
c0003710:	83 ec 08             	sub    $0x8,%esp
  list_insert_before(plist->head.next, elem);
c0003713:	8b 45 08             	mov    0x8(%ebp),%eax
c0003716:	8b 40 04             	mov    0x4(%eax),%eax
c0003719:	83 ec 08             	sub    $0x8,%esp
c000371c:	ff 75 0c             	push   0xc(%ebp)
c000371f:	50                   	push   %eax
c0003720:	e8 a3 ff ff ff       	call   c00036c8 <list_insert_before>
c0003725:	83 c4 10             	add    $0x10,%esp
}
c0003728:	90                   	nop
c0003729:	c9                   	leave  
c000372a:	c3                   	ret    

c000372b <list_append>:

// 追加元素到链表队尾
void list_append(struct list *plist, struct list_elem *elem) {
c000372b:	55                   	push   %ebp
c000372c:	89 e5                	mov    %esp,%ebp
c000372e:	83 ec 08             	sub    $0x8,%esp
  list_insert_before(&plist->tail, elem);
c0003731:	8b 45 08             	mov    0x8(%ebp),%eax
c0003734:	83 c0 08             	add    $0x8,%eax
c0003737:	83 ec 08             	sub    $0x8,%esp
c000373a:	ff 75 0c             	push   0xc(%ebp)
c000373d:	50                   	push   %eax
c000373e:	e8 85 ff ff ff       	call   c00036c8 <list_insert_before>
c0003743:	83 c4 10             	add    $0x10,%esp
}
c0003746:	90                   	nop
c0003747:	c9                   	leave  
c0003748:	c3                   	ret    

c0003749 <list_remove>:

void list_remove(struct list_elem *pelem) {
c0003749:	55                   	push   %ebp
c000374a:	89 e5                	mov    %esp,%ebp
c000374c:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status = intr_disable();
c000374f:	e8 39 e2 ff ff       	call   c000198d <intr_disable>
c0003754:	89 45 f4             	mov    %eax,-0xc(%ebp)
  pelem->prev->next = pelem->next;
c0003757:	8b 45 08             	mov    0x8(%ebp),%eax
c000375a:	8b 00                	mov    (%eax),%eax
c000375c:	8b 55 08             	mov    0x8(%ebp),%edx
c000375f:	8b 52 04             	mov    0x4(%edx),%edx
c0003762:	89 50 04             	mov    %edx,0x4(%eax)
  pelem->next->prev = pelem->prev;
c0003765:	8b 45 08             	mov    0x8(%ebp),%eax
c0003768:	8b 40 04             	mov    0x4(%eax),%eax
c000376b:	8b 55 08             	mov    0x8(%ebp),%edx
c000376e:	8b 12                	mov    (%edx),%edx
c0003770:	89 10                	mov    %edx,(%eax)
  intr_set_status(old_status);
c0003772:	83 ec 0c             	sub    $0xc,%esp
c0003775:	ff 75 f4             	push   -0xc(%ebp)
c0003778:	e8 56 e2 ff ff       	call   c00019d3 <intr_set_status>
c000377d:	83 c4 10             	add    $0x10,%esp
}
c0003780:	90                   	nop
c0003781:	c9                   	leave  
c0003782:	c3                   	ret    

c0003783 <list_pop>:

// 将链表第1个元素弹出并返回
struct list_elem *list_pop(struct list *plist) {
c0003783:	55                   	push   %ebp
c0003784:	89 e5                	mov    %esp,%ebp
c0003786:	83 ec 18             	sub    $0x18,%esp
  struct list_elem *elem = plist->head.next;
c0003789:	8b 45 08             	mov    0x8(%ebp),%eax
c000378c:	8b 40 04             	mov    0x4(%eax),%eax
c000378f:	89 45 f4             	mov    %eax,-0xc(%ebp)
  list_remove(elem);
c0003792:	83 ec 0c             	sub    $0xc,%esp
c0003795:	ff 75 f4             	push   -0xc(%ebp)
c0003798:	e8 ac ff ff ff       	call   c0003749 <list_remove>
c000379d:	83 c4 10             	add    $0x10,%esp
  return elem;
c00037a0:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c00037a3:	c9                   	leave  
c00037a4:	c3                   	ret    

c00037a5 <elem_find>:

bool elem_find(struct list *plist, struct list_elem *obj_elem) {
c00037a5:	55                   	push   %ebp
c00037a6:	89 e5                	mov    %esp,%ebp
c00037a8:	83 ec 10             	sub    $0x10,%esp
  struct list_elem *elem = plist->head.next;
c00037ab:	8b 45 08             	mov    0x8(%ebp),%eax
c00037ae:	8b 40 04             	mov    0x4(%eax),%eax
c00037b1:	89 45 fc             	mov    %eax,-0x4(%ebp)
  while (elem != &plist->tail) {
c00037b4:	eb 18                	jmp    c00037ce <elem_find+0x29>
    if (elem == obj_elem) {
c00037b6:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00037b9:	3b 45 0c             	cmp    0xc(%ebp),%eax
c00037bc:	75 07                	jne    c00037c5 <elem_find+0x20>
      return true;
c00037be:	b8 01 00 00 00       	mov    $0x1,%eax
c00037c3:	eb 19                	jmp    c00037de <elem_find+0x39>
    }
    elem = elem->next;
c00037c5:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00037c8:	8b 40 04             	mov    0x4(%eax),%eax
c00037cb:	89 45 fc             	mov    %eax,-0x4(%ebp)
  while (elem != &plist->tail) {
c00037ce:	8b 45 08             	mov    0x8(%ebp),%eax
c00037d1:	83 c0 08             	add    $0x8,%eax
c00037d4:	39 45 fc             	cmp    %eax,-0x4(%ebp)
c00037d7:	75 dd                	jne    c00037b6 <elem_find+0x11>
  }
  return false;
c00037d9:	b8 00 00 00 00       	mov    $0x0,%eax
}
c00037de:	c9                   	leave  
c00037df:	c3                   	ret    

c00037e0 <list_traversal>:

// 遍历逐个判断是否有符合条件(回调函数f)的元素
struct list_elem *list_traversal(struct list *plist, func f, int arg) {
c00037e0:	55                   	push   %ebp
c00037e1:	89 e5                	mov    %esp,%ebp
c00037e3:	83 ec 18             	sub    $0x18,%esp
  struct list_elem *elem = plist->head.next;
c00037e6:	8b 45 08             	mov    0x8(%ebp),%eax
c00037e9:	8b 40 04             	mov    0x4(%eax),%eax
c00037ec:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (list_empty(plist)) {
c00037ef:	83 ec 0c             	sub    $0xc,%esp
c00037f2:	ff 75 08             	push   0x8(%ebp)
c00037f5:	e8 78 00 00 00       	call   c0003872 <list_empty>
c00037fa:	83 c4 10             	add    $0x10,%esp
c00037fd:	85 c0                	test   %eax,%eax
c00037ff:	74 2a                	je     c000382b <list_traversal+0x4b>
    return NULL;
c0003801:	b8 00 00 00 00       	mov    $0x0,%eax
c0003806:	eb 33                	jmp    c000383b <list_traversal+0x5b>
  }
  while (elem != &plist->tail) {
    if (f(elem, arg)) {
c0003808:	83 ec 08             	sub    $0x8,%esp
c000380b:	ff 75 10             	push   0x10(%ebp)
c000380e:	ff 75 f4             	push   -0xc(%ebp)
c0003811:	8b 45 0c             	mov    0xc(%ebp),%eax
c0003814:	ff d0                	call   *%eax
c0003816:	83 c4 10             	add    $0x10,%esp
c0003819:	85 c0                	test   %eax,%eax
c000381b:	74 05                	je     c0003822 <list_traversal+0x42>
      return elem;
c000381d:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003820:	eb 19                	jmp    c000383b <list_traversal+0x5b>
    }
    elem = elem->next;
c0003822:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003825:	8b 40 04             	mov    0x4(%eax),%eax
c0003828:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while (elem != &plist->tail) {
c000382b:	8b 45 08             	mov    0x8(%ebp),%eax
c000382e:	83 c0 08             	add    $0x8,%eax
c0003831:	39 45 f4             	cmp    %eax,-0xc(%ebp)
c0003834:	75 d2                	jne    c0003808 <list_traversal+0x28>
  }
  return NULL;
c0003836:	b8 00 00 00 00       	mov    $0x0,%eax
}
c000383b:	c9                   	leave  
c000383c:	c3                   	ret    

c000383d <list_len>:

uint32_t list_len(struct list *plist) {
c000383d:	55                   	push   %ebp
c000383e:	89 e5                	mov    %esp,%ebp
c0003840:	83 ec 10             	sub    $0x10,%esp
  struct list_elem *elem = plist->head.next;
c0003843:	8b 45 08             	mov    0x8(%ebp),%eax
c0003846:	8b 40 04             	mov    0x4(%eax),%eax
c0003849:	89 45 fc             	mov    %eax,-0x4(%ebp)
  uint32_t len = 0;
c000384c:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%ebp)
  while (elem != &plist->tail) {
c0003853:	eb 0d                	jmp    c0003862 <list_len+0x25>
    len++;
c0003855:	83 45 f8 01          	addl   $0x1,-0x8(%ebp)
    elem = elem->next;
c0003859:	8b 45 fc             	mov    -0x4(%ebp),%eax
c000385c:	8b 40 04             	mov    0x4(%eax),%eax
c000385f:	89 45 fc             	mov    %eax,-0x4(%ebp)
  while (elem != &plist->tail) {
c0003862:	8b 45 08             	mov    0x8(%ebp),%eax
c0003865:	83 c0 08             	add    $0x8,%eax
c0003868:	39 45 fc             	cmp    %eax,-0x4(%ebp)
c000386b:	75 e8                	jne    c0003855 <list_len+0x18>
  }
  return len;
c000386d:	8b 45 f8             	mov    -0x8(%ebp),%eax
}
c0003870:	c9                   	leave  
c0003871:	c3                   	ret    

c0003872 <list_empty>:

bool list_empty(struct list *plist) {
c0003872:	55                   	push   %ebp
c0003873:	89 e5                	mov    %esp,%ebp
  return (plist->head.next == &plist->tail ? true : false);
c0003875:	8b 45 08             	mov    0x8(%ebp),%eax
c0003878:	8b 40 04             	mov    0x4(%eax),%eax
c000387b:	8b 55 08             	mov    0x8(%ebp),%edx
c000387e:	83 c2 08             	add    $0x8,%edx
c0003881:	39 d0                	cmp    %edx,%eax
c0003883:	0f 94 c0             	sete   %al
c0003886:	0f b6 c0             	movzbl %al,%eax
c0003889:	5d                   	pop    %ebp
c000388a:	c3                   	ret    
c000388b:	66 90                	xchg   %ax,%ax
c000388d:	66 90                	xchg   %ax,%ax
c000388f:	90                   	nop

c0003890 <switch_to>:
c0003890:	56                   	push   %esi
c0003891:	57                   	push   %edi
c0003892:	53                   	push   %ebx
c0003893:	55                   	push   %ebp
c0003894:	8b 44 24 14          	mov    0x14(%esp),%eax
c0003898:	89 20                	mov    %esp,(%eax)
c000389a:	8b 44 24 18          	mov    0x18(%esp),%eax
c000389e:	8b 20                	mov    (%eax),%esp
c00038a0:	5d                   	pop    %ebp
c00038a1:	5b                   	pop    %ebx
c00038a2:	5f                   	pop    %edi
c00038a3:	5e                   	pop    %esi
c00038a4:	c3                   	ret    

c00038a5 <sema_init>:
#include "interrupt.h"
#include "list.h"
#include "stdint.h"
#include "thread.h"

void sema_init(struct semaphore *psema, uint8_t value) {
c00038a5:	55                   	push   %ebp
c00038a6:	89 e5                	mov    %esp,%ebp
c00038a8:	83 ec 18             	sub    $0x18,%esp
c00038ab:	8b 45 0c             	mov    0xc(%ebp),%eax
c00038ae:	88 45 f4             	mov    %al,-0xc(%ebp)
  psema->value = value;
c00038b1:	8b 45 08             	mov    0x8(%ebp),%eax
c00038b4:	0f b6 55 f4          	movzbl -0xc(%ebp),%edx
c00038b8:	88 10                	mov    %dl,(%eax)
  list_init(&psema->waiters);
c00038ba:	8b 45 08             	mov    0x8(%ebp),%eax
c00038bd:	83 c0 04             	add    $0x4,%eax
c00038c0:	83 ec 0c             	sub    $0xc,%esp
c00038c3:	50                   	push   %eax
c00038c4:	e8 d1 fd ff ff       	call   c000369a <list_init>
c00038c9:	83 c4 10             	add    $0x10,%esp
}
c00038cc:	90                   	nop
c00038cd:	c9                   	leave  
c00038ce:	c3                   	ret    

c00038cf <lock_init>:

void lock_init(struct lock *plock) {
c00038cf:	55                   	push   %ebp
c00038d0:	89 e5                	mov    %esp,%ebp
c00038d2:	83 ec 08             	sub    $0x8,%esp
  plock->holder = NULL;
c00038d5:	8b 45 08             	mov    0x8(%ebp),%eax
c00038d8:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
  plock->holder_repeat_nr = 0;
c00038de:	8b 45 08             	mov    0x8(%ebp),%eax
c00038e1:	c7 40 18 00 00 00 00 	movl   $0x0,0x18(%eax)
  sema_init(&plock->semaphore, 1);
c00038e8:	8b 45 08             	mov    0x8(%ebp),%eax
c00038eb:	83 c0 04             	add    $0x4,%eax
c00038ee:	83 ec 08             	sub    $0x8,%esp
c00038f1:	6a 01                	push   $0x1
c00038f3:	50                   	push   %eax
c00038f4:	e8 ac ff ff ff       	call   c00038a5 <sema_init>
c00038f9:	83 c4 10             	add    $0x10,%esp
}
c00038fc:	90                   	nop
c00038fd:	c9                   	leave  
c00038fe:	c3                   	ret    

c00038ff <sema_down>:

void sema_down(struct semaphore *psema) {
c00038ff:	55                   	push   %ebp
c0003900:	89 e5                	mov    %esp,%ebp
c0003902:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status = intr_disable();
c0003905:	e8 83 e0 ff ff       	call   c000198d <intr_disable>
c000390a:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while (psema->value == 0) { // 已经被别人持有
c000390d:	e9 98 00 00 00       	jmp    c00039aa <sema_down+0xab>
    ASSERT(!elem_find(&psema->waiters, &running_thread()->general_tag));
c0003912:	e8 2b f8 ff ff       	call   c0003142 <running_thread>
c0003917:	8d 50 20             	lea    0x20(%eax),%edx
c000391a:	8b 45 08             	mov    0x8(%ebp),%eax
c000391d:	83 c0 04             	add    $0x4,%eax
c0003920:	83 ec 08             	sub    $0x8,%esp
c0003923:	52                   	push   %edx
c0003924:	50                   	push   %eax
c0003925:	e8 7b fe ff ff       	call   c00037a5 <elem_find>
c000392a:	83 c4 10             	add    $0x10,%esp
c000392d:	85 c0                	test   %eax,%eax
c000392f:	74 19                	je     c000394a <sema_down+0x4b>
c0003931:	68 a0 59 00 c0       	push   $0xc00059a0
c0003936:	68 a4 5a 00 c0       	push   $0xc0005aa4
c000393b:	6a 16                	push   $0x16
c000393d:	68 dc 59 00 c0       	push   $0xc00059dc
c0003942:	e8 29 e9 ff ff       	call   c0002270 <panic_spin>
c0003947:	83 c4 10             	add    $0x10,%esp
    if (elem_find(&psema->waiters, &running_thread()->general_tag)) {
c000394a:	e8 f3 f7 ff ff       	call   c0003142 <running_thread>
c000394f:	8d 50 20             	lea    0x20(%eax),%edx
c0003952:	8b 45 08             	mov    0x8(%ebp),%eax
c0003955:	83 c0 04             	add    $0x4,%eax
c0003958:	83 ec 08             	sub    $0x8,%esp
c000395b:	52                   	push   %edx
c000395c:	50                   	push   %eax
c000395d:	e8 43 fe ff ff       	call   c00037a5 <elem_find>
c0003962:	83 c4 10             	add    $0x10,%esp
c0003965:	85 c0                	test   %eax,%eax
c0003967:	74 19                	je     c0003982 <sema_down+0x83>
      PANIC("sema_down: thread blocked has been in waiters_list\n");
c0003969:	68 ec 59 00 c0       	push   $0xc00059ec
c000396e:	68 a4 5a 00 c0       	push   $0xc0005aa4
c0003973:	6a 18                	push   $0x18
c0003975:	68 dc 59 00 c0       	push   $0xc00059dc
c000397a:	e8 f1 e8 ff ff       	call   c0002270 <panic_spin>
c000397f:	83 c4 10             	add    $0x10,%esp
    }
    // 当前线程把自己加入该锁的等待队列，然后阻塞自己
    list_append(&psema->waiters, &running_thread()->general_tag);
c0003982:	e8 bb f7 ff ff       	call   c0003142 <running_thread>
c0003987:	8d 50 20             	lea    0x20(%eax),%edx
c000398a:	8b 45 08             	mov    0x8(%ebp),%eax
c000398d:	83 c0 04             	add    $0x4,%eax
c0003990:	83 ec 08             	sub    $0x8,%esp
c0003993:	52                   	push   %edx
c0003994:	50                   	push   %eax
c0003995:	e8 91 fd ff ff       	call   c000372b <list_append>
c000399a:	83 c4 10             	add    $0x10,%esp
    thread_block(TASK_BLOCKED);
c000399d:	83 ec 0c             	sub    $0xc,%esp
c00039a0:	6a 02                	push   $0x2
c00039a2:	e8 96 fb ff ff       	call   c000353d <thread_block>
c00039a7:	83 c4 10             	add    $0x10,%esp
  while (psema->value == 0) { // 已经被别人持有
c00039aa:	8b 45 08             	mov    0x8(%ebp),%eax
c00039ad:	0f b6 00             	movzbl (%eax),%eax
c00039b0:	84 c0                	test   %al,%al
c00039b2:	0f 84 5a ff ff ff    	je     c0003912 <sema_down+0x13>
  }
  // value=1或被唤醒后-> 获得锁
  psema->value--;
c00039b8:	8b 45 08             	mov    0x8(%ebp),%eax
c00039bb:	0f b6 00             	movzbl (%eax),%eax
c00039be:	8d 50 ff             	lea    -0x1(%eax),%edx
c00039c1:	8b 45 08             	mov    0x8(%ebp),%eax
c00039c4:	88 10                	mov    %dl,(%eax)
  ASSERT(psema->value == 0);
c00039c6:	8b 45 08             	mov    0x8(%ebp),%eax
c00039c9:	0f b6 00             	movzbl (%eax),%eax
c00039cc:	84 c0                	test   %al,%al
c00039ce:	74 19                	je     c00039e9 <sema_down+0xea>
c00039d0:	68 20 5a 00 c0       	push   $0xc0005a20
c00039d5:	68 a4 5a 00 c0       	push   $0xc0005aa4
c00039da:	6a 20                	push   $0x20
c00039dc:	68 dc 59 00 c0       	push   $0xc00059dc
c00039e1:	e8 8a e8 ff ff       	call   c0002270 <panic_spin>
c00039e6:	83 c4 10             	add    $0x10,%esp
  intr_set_status(old_status);
c00039e9:	83 ec 0c             	sub    $0xc,%esp
c00039ec:	ff 75 f4             	push   -0xc(%ebp)
c00039ef:	e8 df df ff ff       	call   c00019d3 <intr_set_status>
c00039f4:	83 c4 10             	add    $0x10,%esp
}
c00039f7:	90                   	nop
c00039f8:	c9                   	leave  
c00039f9:	c3                   	ret    

c00039fa <sema_up>:

void sema_up(struct semaphore *psema) {
c00039fa:	55                   	push   %ebp
c00039fb:	89 e5                	mov    %esp,%ebp
c00039fd:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status = intr_disable();
c0003a00:	e8 88 df ff ff       	call   c000198d <intr_disable>
c0003a05:	89 45 f4             	mov    %eax,-0xc(%ebp)
  ASSERT(psema->value == 0);
c0003a08:	8b 45 08             	mov    0x8(%ebp),%eax
c0003a0b:	0f b6 00             	movzbl (%eax),%eax
c0003a0e:	84 c0                	test   %al,%al
c0003a10:	74 19                	je     c0003a2b <sema_up+0x31>
c0003a12:	68 20 5a 00 c0       	push   $0xc0005a20
c0003a17:	68 b0 5a 00 c0       	push   $0xc0005ab0
c0003a1c:	6a 26                	push   $0x26
c0003a1e:	68 dc 59 00 c0       	push   $0xc00059dc
c0003a23:	e8 48 e8 ff ff       	call   c0002270 <panic_spin>
c0003a28:	83 c4 10             	add    $0x10,%esp
  if (!list_empty(&psema->waiters)) {
c0003a2b:	8b 45 08             	mov    0x8(%ebp),%eax
c0003a2e:	83 c0 04             	add    $0x4,%eax
c0003a31:	83 ec 0c             	sub    $0xc,%esp
c0003a34:	50                   	push   %eax
c0003a35:	e8 38 fe ff ff       	call   c0003872 <list_empty>
c0003a3a:	83 c4 10             	add    $0x10,%esp
c0003a3d:	85 c0                	test   %eax,%eax
c0003a3f:	75 26                	jne    c0003a67 <sema_up+0x6d>
    struct task_struct *thread_blocked =
        elem2entry(struct task_struct, general_tag, list_pop(&psema->waiters));
c0003a41:	8b 45 08             	mov    0x8(%ebp),%eax
c0003a44:	83 c0 04             	add    $0x4,%eax
c0003a47:	83 ec 0c             	sub    $0xc,%esp
c0003a4a:	50                   	push   %eax
c0003a4b:	e8 33 fd ff ff       	call   c0003783 <list_pop>
c0003a50:	83 c4 10             	add    $0x10,%esp
c0003a53:	83 e8 20             	sub    $0x20,%eax
    struct task_struct *thread_blocked =
c0003a56:	89 45 f0             	mov    %eax,-0x10(%ebp)
    thread_unblock(thread_blocked);
c0003a59:	83 ec 0c             	sub    $0xc,%esp
c0003a5c:	ff 75 f0             	push   -0x10(%ebp)
c0003a5f:	e8 3c fb ff ff       	call   c00035a0 <thread_unblock>
c0003a64:	83 c4 10             	add    $0x10,%esp
  }
  psema->value++;
c0003a67:	8b 45 08             	mov    0x8(%ebp),%eax
c0003a6a:	0f b6 00             	movzbl (%eax),%eax
c0003a6d:	8d 50 01             	lea    0x1(%eax),%edx
c0003a70:	8b 45 08             	mov    0x8(%ebp),%eax
c0003a73:	88 10                	mov    %dl,(%eax)
  ASSERT(psema->value == 1);
c0003a75:	8b 45 08             	mov    0x8(%ebp),%eax
c0003a78:	0f b6 00             	movzbl (%eax),%eax
c0003a7b:	3c 01                	cmp    $0x1,%al
c0003a7d:	74 19                	je     c0003a98 <sema_up+0x9e>
c0003a7f:	68 32 5a 00 c0       	push   $0xc0005a32
c0003a84:	68 b0 5a 00 c0       	push   $0xc0005ab0
c0003a89:	6a 2d                	push   $0x2d
c0003a8b:	68 dc 59 00 c0       	push   $0xc00059dc
c0003a90:	e8 db e7 ff ff       	call   c0002270 <panic_spin>
c0003a95:	83 c4 10             	add    $0x10,%esp
  intr_set_status(old_status);
c0003a98:	83 ec 0c             	sub    $0xc,%esp
c0003a9b:	ff 75 f4             	push   -0xc(%ebp)
c0003a9e:	e8 30 df ff ff       	call   c00019d3 <intr_set_status>
c0003aa3:	83 c4 10             	add    $0x10,%esp
}
c0003aa6:	90                   	nop
c0003aa7:	c9                   	leave  
c0003aa8:	c3                   	ret    

c0003aa9 <lock_acquire>:

// 获取锁plock
void lock_acquire(struct lock *plock) {
c0003aa9:	55                   	push   %ebp
c0003aaa:	89 e5                	mov    %esp,%ebp
c0003aac:	53                   	push   %ebx
c0003aad:	83 ec 04             	sub    $0x4,%esp
  if (plock->holder != running_thread()) { // 判断是否已持有该锁
c0003ab0:	8b 45 08             	mov    0x8(%ebp),%eax
c0003ab3:	8b 18                	mov    (%eax),%ebx
c0003ab5:	e8 88 f6 ff ff       	call   c0003142 <running_thread>
c0003aba:	39 c3                	cmp    %eax,%ebx
c0003abc:	74 4b                	je     c0003b09 <lock_acquire+0x60>
    sema_down(&plock->semaphore);          // 信号量P操作(原子
c0003abe:	8b 45 08             	mov    0x8(%ebp),%eax
c0003ac1:	83 c0 04             	add    $0x4,%eax
c0003ac4:	83 ec 0c             	sub    $0xc,%esp
c0003ac7:	50                   	push   %eax
c0003ac8:	e8 32 fe ff ff       	call   c00038ff <sema_down>
c0003acd:	83 c4 10             	add    $0x10,%esp
    plock->holder = running_thread();
c0003ad0:	e8 6d f6 ff ff       	call   c0003142 <running_thread>
c0003ad5:	8b 55 08             	mov    0x8(%ebp),%edx
c0003ad8:	89 02                	mov    %eax,(%edx)
    ASSERT(plock->holder_repeat_nr == 0);
c0003ada:	8b 45 08             	mov    0x8(%ebp),%eax
c0003add:	8b 40 18             	mov    0x18(%eax),%eax
c0003ae0:	85 c0                	test   %eax,%eax
c0003ae2:	74 19                	je     c0003afd <lock_acquire+0x54>
c0003ae4:	68 44 5a 00 c0       	push   $0xc0005a44
c0003ae9:	68 b8 5a 00 c0       	push   $0xc0005ab8
c0003aee:	6a 36                	push   $0x36
c0003af0:	68 dc 59 00 c0       	push   $0xc00059dc
c0003af5:	e8 76 e7 ff ff       	call   c0002270 <panic_spin>
c0003afa:	83 c4 10             	add    $0x10,%esp
    plock->holder_repeat_nr = 1;
c0003afd:	8b 45 08             	mov    0x8(%ebp),%eax
c0003b00:	c7 40 18 01 00 00 00 	movl   $0x1,0x18(%eax)
  } else {
    plock->holder_repeat_nr++;
  }
}
c0003b07:	eb 0f                	jmp    c0003b18 <lock_acquire+0x6f>
    plock->holder_repeat_nr++;
c0003b09:	8b 45 08             	mov    0x8(%ebp),%eax
c0003b0c:	8b 40 18             	mov    0x18(%eax),%eax
c0003b0f:	8d 50 01             	lea    0x1(%eax),%edx
c0003b12:	8b 45 08             	mov    0x8(%ebp),%eax
c0003b15:	89 50 18             	mov    %edx,0x18(%eax)
}
c0003b18:	90                   	nop
c0003b19:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c0003b1c:	c9                   	leave  
c0003b1d:	c3                   	ret    

c0003b1e <lock_release>:

// 释放锁plock
void lock_release(struct lock *plock) {
c0003b1e:	55                   	push   %ebp
c0003b1f:	89 e5                	mov    %esp,%ebp
c0003b21:	53                   	push   %ebx
c0003b22:	83 ec 04             	sub    $0x4,%esp
  ASSERT(plock->holder == running_thread());
c0003b25:	8b 45 08             	mov    0x8(%ebp),%eax
c0003b28:	8b 18                	mov    (%eax),%ebx
c0003b2a:	e8 13 f6 ff ff       	call   c0003142 <running_thread>
c0003b2f:	39 c3                	cmp    %eax,%ebx
c0003b31:	74 19                	je     c0003b4c <lock_release+0x2e>
c0003b33:	68 64 5a 00 c0       	push   $0xc0005a64
c0003b38:	68 c8 5a 00 c0       	push   $0xc0005ac8
c0003b3d:	6a 3f                	push   $0x3f
c0003b3f:	68 dc 59 00 c0       	push   $0xc00059dc
c0003b44:	e8 27 e7 ff ff       	call   c0002270 <panic_spin>
c0003b49:	83 c4 10             	add    $0x10,%esp
  if (plock->holder_repeat_nr > 1) {
c0003b4c:	8b 45 08             	mov    0x8(%ebp),%eax
c0003b4f:	8b 40 18             	mov    0x18(%eax),%eax
c0003b52:	83 f8 01             	cmp    $0x1,%eax
c0003b55:	76 11                	jbe    c0003b68 <lock_release+0x4a>
    // 此时还不能释放锁
    plock->holder_repeat_nr--;
c0003b57:	8b 45 08             	mov    0x8(%ebp),%eax
c0003b5a:	8b 40 18             	mov    0x18(%eax),%eax
c0003b5d:	8d 50 ff             	lea    -0x1(%eax),%edx
c0003b60:	8b 45 08             	mov    0x8(%ebp),%eax
c0003b63:	89 50 18             	mov    %edx,0x18(%eax)
    return;
c0003b66:	eb 49                	jmp    c0003bb1 <lock_release+0x93>
  }
  ASSERT(plock->holder_repeat_nr == 1);
c0003b68:	8b 45 08             	mov    0x8(%ebp),%eax
c0003b6b:	8b 40 18             	mov    0x18(%eax),%eax
c0003b6e:	83 f8 01             	cmp    $0x1,%eax
c0003b71:	74 19                	je     c0003b8c <lock_release+0x6e>
c0003b73:	68 86 5a 00 c0       	push   $0xc0005a86
c0003b78:	68 c8 5a 00 c0       	push   $0xc0005ac8
c0003b7d:	6a 45                	push   $0x45
c0003b7f:	68 dc 59 00 c0       	push   $0xc00059dc
c0003b84:	e8 e7 e6 ff ff       	call   c0002270 <panic_spin>
c0003b89:	83 c4 10             	add    $0x10,%esp

  plock->holder = NULL; // 把锁的持有者置空放在V操作前
c0003b8c:	8b 45 08             	mov    0x8(%ebp),%eax
c0003b8f:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
  plock->holder_repeat_nr = 0;
c0003b95:	8b 45 08             	mov    0x8(%ebp),%eax
c0003b98:	c7 40 18 00 00 00 00 	movl   $0x0,0x18(%eax)
  sema_up(&plock->semaphore); // 信号量V操作(原子
c0003b9f:	8b 45 08             	mov    0x8(%ebp),%eax
c0003ba2:	83 c0 04             	add    $0x4,%eax
c0003ba5:	83 ec 0c             	sub    $0xc,%esp
c0003ba8:	50                   	push   %eax
c0003ba9:	e8 4c fe ff ff       	call   c00039fa <sema_up>
c0003bae:	83 c4 10             	add    $0x10,%esp
c0003bb1:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c0003bb4:	c9                   	leave  
c0003bb5:	c3                   	ret    

c0003bb6 <console_init>:
#include "print.h"
#include "sync.h"

static struct lock console_lock; // 终端锁

void console_init() { lock_init(&console_lock); }
c0003bb6:	55                   	push   %ebp
c0003bb7:	89 e5                	mov    %esp,%ebp
c0003bb9:	83 ec 08             	sub    $0x8,%esp
c0003bbc:	83 ec 0c             	sub    $0xc,%esp
c0003bbf:	68 40 85 00 c0       	push   $0xc0008540
c0003bc4:	e8 06 fd ff ff       	call   c00038cf <lock_init>
c0003bc9:	83 c4 10             	add    $0x10,%esp
c0003bcc:	90                   	nop
c0003bcd:	c9                   	leave  
c0003bce:	c3                   	ret    

c0003bcf <console_acquire>:

// 获取终端
void console_acquire() { lock_acquire(&console_lock); }
c0003bcf:	55                   	push   %ebp
c0003bd0:	89 e5                	mov    %esp,%ebp
c0003bd2:	83 ec 08             	sub    $0x8,%esp
c0003bd5:	83 ec 0c             	sub    $0xc,%esp
c0003bd8:	68 40 85 00 c0       	push   $0xc0008540
c0003bdd:	e8 c7 fe ff ff       	call   c0003aa9 <lock_acquire>
c0003be2:	83 c4 10             	add    $0x10,%esp
c0003be5:	90                   	nop
c0003be6:	c9                   	leave  
c0003be7:	c3                   	ret    

c0003be8 <console_release>:

// 释放终端
void console_release() { lock_release(&console_lock); }
c0003be8:	55                   	push   %ebp
c0003be9:	89 e5                	mov    %esp,%ebp
c0003beb:	83 ec 08             	sub    $0x8,%esp
c0003bee:	83 ec 0c             	sub    $0xc,%esp
c0003bf1:	68 40 85 00 c0       	push   $0xc0008540
c0003bf6:	e8 23 ff ff ff       	call   c0003b1e <lock_release>
c0003bfb:	83 c4 10             	add    $0x10,%esp
c0003bfe:	90                   	nop
c0003bff:	c9                   	leave  
c0003c00:	c3                   	ret    

c0003c01 <console_put_str>:

// 终端中输出字符串
void console_put_str(char *str) {
c0003c01:	55                   	push   %ebp
c0003c02:	89 e5                	mov    %esp,%ebp
c0003c04:	83 ec 08             	sub    $0x8,%esp
  console_acquire();
c0003c07:	e8 c3 ff ff ff       	call   c0003bcf <console_acquire>
  put_str(str);
c0003c0c:	83 ec 0c             	sub    $0xc,%esp
c0003c0f:	ff 75 08             	push   0x8(%ebp)
c0003c12:	e8 59 de ff ff       	call   c0001a70 <put_str>
c0003c17:	83 c4 10             	add    $0x10,%esp
  console_release();
c0003c1a:	e8 c9 ff ff ff       	call   c0003be8 <console_release>
}
c0003c1f:	90                   	nop
c0003c20:	c9                   	leave  
c0003c21:	c3                   	ret    

c0003c22 <console_put_char>:

// 终端中输出字符
void console_put_char(uint8_t char_asci) {
c0003c22:	55                   	push   %ebp
c0003c23:	89 e5                	mov    %esp,%ebp
c0003c25:	83 ec 18             	sub    $0x18,%esp
c0003c28:	8b 45 08             	mov    0x8(%ebp),%eax
c0003c2b:	88 45 f4             	mov    %al,-0xc(%ebp)
  console_acquire();
c0003c2e:	e8 9c ff ff ff       	call   c0003bcf <console_acquire>
  put_char(char_asci);
c0003c33:	0f b6 45 f4          	movzbl -0xc(%ebp),%eax
c0003c37:	83 ec 0c             	sub    $0xc,%esp
c0003c3a:	50                   	push   %eax
c0003c3b:	e8 4e de ff ff       	call   c0001a8e <put_char>
c0003c40:	83 c4 10             	add    $0x10,%esp
  console_release();
c0003c43:	e8 a0 ff ff ff       	call   c0003be8 <console_release>
}
c0003c48:	90                   	nop
c0003c49:	c9                   	leave  
c0003c4a:	c3                   	ret    

c0003c4b <console_put_int>:

// 终端中输出十六进制整数
void console_put_int(uint32_t num) {
c0003c4b:	55                   	push   %ebp
c0003c4c:	89 e5                	mov    %esp,%ebp
c0003c4e:	83 ec 08             	sub    $0x8,%esp
  console_acquire();
c0003c51:	e8 79 ff ff ff       	call   c0003bcf <console_acquire>
  put_int(num);
c0003c56:	83 ec 0c             	sub    $0xc,%esp
c0003c59:	ff 75 08             	push   0x8(%ebp)
c0003c5c:	e8 fb de ff ff       	call   c0001b5c <put_int>
c0003c61:	83 c4 10             	add    $0x10,%esp
  console_release();
c0003c64:	e8 7f ff ff ff       	call   c0003be8 <console_release>
c0003c69:	90                   	nop
c0003c6a:	c9                   	leave  
c0003c6b:	c3                   	ret    

c0003c6c <inb>:
static inline void outsw(uint16_t port, const void *addr, uint32_t word_cnt) {
  asm volatile("cld; rep outsw" : "+S"(addr), "+c"(word_cnt) : "d"(port));
}

// 从端口读1字节
static inline uint8_t inb(uint16_t port) {
c0003c6c:	55                   	push   %ebp
c0003c6d:	89 e5                	mov    %esp,%ebp
c0003c6f:	83 ec 14             	sub    $0x14,%esp
c0003c72:	8b 45 08             	mov    0x8(%ebp),%eax
c0003c75:	66 89 45 ec          	mov    %ax,-0x14(%ebp)
  uint8_t data;
  asm volatile("inb %w1, %b0" : "=a"(data) : "Nd"(port));
c0003c79:	0f b7 45 ec          	movzwl -0x14(%ebp),%eax
c0003c7d:	89 c2                	mov    %eax,%edx
c0003c7f:	ec                   	in     (%dx),%al
c0003c80:	88 45 ff             	mov    %al,-0x1(%ebp)
  return data;
c0003c83:	0f b6 45 ff          	movzbl -0x1(%ebp),%eax
}
c0003c87:	c9                   	leave  
c0003c88:	c3                   	ret    

c0003c89 <intr_keyboard_handler>:
    /* 0x3A */ {caps_lock_char, caps_lock_char}
    /*其他按键暂不处理*/
};

// 键盘中断处理程序
static void intr_keyboard_handler(void) {
c0003c89:	55                   	push   %ebp
c0003c8a:	89 e5                	mov    %esp,%ebp
c0003c8c:	83 ec 28             	sub    $0x28,%esp
  bool ctrl_down_last = ctrl_status; // 记录三个组合键是否被按下
c0003c8f:	a1 cc 85 00 c0       	mov    0xc00085cc,%eax
c0003c94:	89 45 ec             	mov    %eax,-0x14(%ebp)
  bool shift_down_last = shift_status;
c0003c97:	a1 d0 85 00 c0       	mov    0xc00085d0,%eax
c0003c9c:	89 45 e8             	mov    %eax,-0x18(%ebp)
  bool caps_lock_last = caps_lock_status;
c0003c9f:	a1 d8 85 00 c0       	mov    0xc00085d8,%eax
c0003ca4:	89 45 e4             	mov    %eax,-0x1c(%ebp)
  bool break_code;

  uint16_t scancode = inb(KBD_BUF_PORT); // 获取扫描码
c0003ca7:	6a 60                	push   $0x60
c0003ca9:	e8 be ff ff ff       	call   c0003c6c <inb>
c0003cae:	83 c4 04             	add    $0x4,%esp
c0003cb1:	0f b6 c0             	movzbl %al,%eax
c0003cb4:	66 89 45 f6          	mov    %ax,-0xa(%ebp)

  // scancode是e0开头-> 有多个扫描码，所以马上结束此次函数等下个码进来
  if (scancode == 0xe0) {
c0003cb8:	66 81 7d f6 e0 00    	cmpw   $0xe0,-0xa(%ebp)
c0003cbe:	75 0f                	jne    c0003ccf <intr_keyboard_handler+0x46>
    ext_scancode = true; // 打开e0标记
c0003cc0:	c7 05 dc 85 00 c0 01 	movl   $0x1,0xc00085dc
c0003cc7:	00 00 00 
    return;
c0003cca:	e9 40 02 00 00       	jmp    c0003f0f <intr_keyboard_handler+0x286>
  }

  // 上次以0xe0开头-> 将扫描码合并
  if (ext_scancode) {
c0003ccf:	a1 dc 85 00 c0       	mov    0xc00085dc,%eax
c0003cd4:	85 c0                	test   %eax,%eax
c0003cd6:	74 10                	je     c0003ce8 <intr_keyboard_handler+0x5f>
    scancode = ((0xe000) | scancode);
c0003cd8:	66 81 4d f6 00 e0    	orw    $0xe000,-0xa(%ebp)
    ext_scancode = false; // 关闭e0标记
c0003cde:	c7 05 dc 85 00 c0 00 	movl   $0x0,0xc00085dc
c0003ce5:	00 00 00 
  }

  break_code = ((scancode & 0x0080) != 0); // 获取break_code
c0003ce8:	0f b7 45 f6          	movzwl -0xa(%ebp),%eax
c0003cec:	25 80 00 00 00       	and    $0x80,%eax
c0003cf1:	85 c0                	test   %eax,%eax
c0003cf3:	0f 95 c0             	setne  %al
c0003cf6:	0f b6 c0             	movzbl %al,%eax
c0003cf9:	89 45 e0             	mov    %eax,-0x20(%ebp)

  if (break_code) {                            // 断码处理
c0003cfc:	83 7d e0 00          	cmpl   $0x0,-0x20(%ebp)
c0003d00:	74 6a                	je     c0003d6c <intr_keyboard_handler+0xe3>
    uint16_t make_code = (scancode &= 0xff7f); // 通过将第8位置0来获得其通码
c0003d02:	66 81 65 f6 7f ff    	andw   $0xff7f,-0xa(%ebp)
c0003d08:	0f b7 45 f6          	movzwl -0xa(%ebp),%eax
c0003d0c:	66 89 45 dc          	mov    %ax,-0x24(%ebp)

    // 判断三个键是否弹起
    if (make_code == ctrl_l_make || make_code == ctrl_r_make) {
c0003d10:	66 83 7d dc 1d       	cmpw   $0x1d,-0x24(%ebp)
c0003d15:	74 08                	je     c0003d1f <intr_keyboard_handler+0x96>
c0003d17:	66 81 7d dc 1d e0    	cmpw   $0xe01d,-0x24(%ebp)
c0003d1d:	75 0c                	jne    c0003d2b <intr_keyboard_handler+0xa2>
      ctrl_status = false;
c0003d1f:	c7 05 cc 85 00 c0 00 	movl   $0x0,0xc00085cc
c0003d26:	00 00 00 
c0003d29:	eb 3c                	jmp    c0003d67 <intr_keyboard_handler+0xde>
    } else if (make_code == shift_l_make || make_code == shift_r_make) {
c0003d2b:	66 83 7d dc 2a       	cmpw   $0x2a,-0x24(%ebp)
c0003d30:	74 07                	je     c0003d39 <intr_keyboard_handler+0xb0>
c0003d32:	66 83 7d dc 36       	cmpw   $0x36,-0x24(%ebp)
c0003d37:	75 0c                	jne    c0003d45 <intr_keyboard_handler+0xbc>
      shift_status = false;
c0003d39:	c7 05 d0 85 00 c0 00 	movl   $0x0,0xc00085d0
c0003d40:	00 00 00 
c0003d43:	eb 22                	jmp    c0003d67 <intr_keyboard_handler+0xde>
    } else if (make_code == alt_l_make || make_code == alt_r_make) {
c0003d45:	66 83 7d dc 38       	cmpw   $0x38,-0x24(%ebp)
c0003d4a:	74 0c                	je     c0003d58 <intr_keyboard_handler+0xcf>
c0003d4c:	66 81 7d dc 38 e0    	cmpw   $0xe038,-0x24(%ebp)
c0003d52:	0f 85 b0 01 00 00    	jne    c0003f08 <intr_keyboard_handler+0x27f>
      alt_status = false;
c0003d58:	c7 05 d4 85 00 c0 00 	movl   $0x0,0xc00085d4
c0003d5f:	00 00 00 
    } // caps_lock不是弹起后关闭，需单独处理

    return;
c0003d62:	e9 a1 01 00 00       	jmp    c0003f08 <intr_keyboard_handler+0x27f>
c0003d67:	e9 9c 01 00 00       	jmp    c0003f08 <intr_keyboard_handler+0x27f>
  } else if ((scancode > 0x00 && scancode < 0x3b) || (scancode == alt_r_make) ||
c0003d6c:	66 83 7d f6 00       	cmpw   $0x0,-0xa(%ebp)
c0003d71:	74 07                	je     c0003d7a <intr_keyboard_handler+0xf1>
c0003d73:	66 83 7d f6 3a       	cmpw   $0x3a,-0xa(%ebp)
c0003d78:	76 14                	jbe    c0003d8e <intr_keyboard_handler+0x105>
c0003d7a:	66 81 7d f6 38 e0    	cmpw   $0xe038,-0xa(%ebp)
c0003d80:	74 0c                	je     c0003d8e <intr_keyboard_handler+0x105>
c0003d82:	66 81 7d f6 1d e0    	cmpw   $0xe01d,-0xa(%ebp)
c0003d88:	0f 85 68 01 00 00    	jne    c0003ef6 <intr_keyboard_handler+0x26d>
             (scancode == ctrl_r_make)) { // 通码处理
    bool shift = false;                   // 判断是否与shift组合
c0003d8e:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
    if ((scancode < 0x0e) || (scancode == 0x29) || (scancode == 0x1a) ||
c0003d95:	66 83 7d f6 0d       	cmpw   $0xd,-0xa(%ebp)
c0003d9a:	76 3f                	jbe    c0003ddb <intr_keyboard_handler+0x152>
c0003d9c:	66 83 7d f6 29       	cmpw   $0x29,-0xa(%ebp)
c0003da1:	74 38                	je     c0003ddb <intr_keyboard_handler+0x152>
c0003da3:	66 83 7d f6 1a       	cmpw   $0x1a,-0xa(%ebp)
c0003da8:	74 31                	je     c0003ddb <intr_keyboard_handler+0x152>
c0003daa:	66 83 7d f6 1b       	cmpw   $0x1b,-0xa(%ebp)
c0003daf:	74 2a                	je     c0003ddb <intr_keyboard_handler+0x152>
        (scancode == 0x1b) || (scancode == 0x2b) || (scancode == 0x27) ||
c0003db1:	66 83 7d f6 2b       	cmpw   $0x2b,-0xa(%ebp)
c0003db6:	74 23                	je     c0003ddb <intr_keyboard_handler+0x152>
c0003db8:	66 83 7d f6 27       	cmpw   $0x27,-0xa(%ebp)
c0003dbd:	74 1c                	je     c0003ddb <intr_keyboard_handler+0x152>
c0003dbf:	66 83 7d f6 28       	cmpw   $0x28,-0xa(%ebp)
c0003dc4:	74 15                	je     c0003ddb <intr_keyboard_handler+0x152>
        (scancode == 0x28) || (scancode == 0x33) || (scancode == 0x34) ||
c0003dc6:	66 83 7d f6 33       	cmpw   $0x33,-0xa(%ebp)
c0003dcb:	74 0e                	je     c0003ddb <intr_keyboard_handler+0x152>
c0003dcd:	66 83 7d f6 34       	cmpw   $0x34,-0xa(%ebp)
c0003dd2:	74 07                	je     c0003ddb <intr_keyboard_handler+0x152>
c0003dd4:	66 83 7d f6 35       	cmpw   $0x35,-0xa(%ebp)
c0003dd9:	75 0f                	jne    c0003dea <intr_keyboard_handler+0x161>
        (scancode == 0x35)) { // 双字符键
      if (shift_down_last) {
c0003ddb:	83 7d e8 00          	cmpl   $0x0,-0x18(%ebp)
c0003ddf:	74 3a                	je     c0003e1b <intr_keyboard_handler+0x192>
        shift = true;
c0003de1:	c7 45 f0 01 00 00 00 	movl   $0x1,-0x10(%ebp)
      if (shift_down_last) {
c0003de8:	eb 31                	jmp    c0003e1b <intr_keyboard_handler+0x192>
      }
    } else { // 字母键
      if (shift_down_last && caps_lock_last) {
c0003dea:	83 7d e8 00          	cmpl   $0x0,-0x18(%ebp)
c0003dee:	74 0f                	je     c0003dff <intr_keyboard_handler+0x176>
c0003df0:	83 7d e4 00          	cmpl   $0x0,-0x1c(%ebp)
c0003df4:	74 09                	je     c0003dff <intr_keyboard_handler+0x176>
        shift = false;
c0003df6:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
c0003dfd:	eb 1c                	jmp    c0003e1b <intr_keyboard_handler+0x192>
      } else if (shift_down_last || caps_lock_last) {
c0003dff:	83 7d e8 00          	cmpl   $0x0,-0x18(%ebp)
c0003e03:	75 06                	jne    c0003e0b <intr_keyboard_handler+0x182>
c0003e05:	83 7d e4 00          	cmpl   $0x0,-0x1c(%ebp)
c0003e09:	74 09                	je     c0003e14 <intr_keyboard_handler+0x18b>
        shift = true;
c0003e0b:	c7 45 f0 01 00 00 00 	movl   $0x1,-0x10(%ebp)
c0003e12:	eb 07                	jmp    c0003e1b <intr_keyboard_handler+0x192>
      } else {
        shift = false;
c0003e14:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
      }
    }

    uint8_t index = (scancode &= 0x00ff); // 针对高字节是e0的码,将高字节置0
c0003e1b:	66 81 65 f6 ff 00    	andw   $0xff,-0xa(%ebp)
c0003e21:	0f b7 45 f6          	movzwl -0xa(%ebp),%eax
c0003e25:	88 45 df             	mov    %al,-0x21(%ebp)
    char cur_char = keymap[index][shift]; // 找到对应ASCII字符
c0003e28:	0f b6 45 df          	movzbl -0x21(%ebp),%eax
c0003e2c:	8d 14 00             	lea    (%eax,%eax,1),%edx
c0003e2f:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0003e32:	01 d0                	add    %edx,%eax
c0003e34:	05 e0 80 00 c0       	add    $0xc00080e0,%eax
c0003e39:	0f b6 00             	movzbl (%eax),%eax
c0003e3c:	88 45 de             	mov    %al,-0x22(%ebp)

    if (cur_char) { // 只处理ASCII码不为0的键
c0003e3f:	80 7d de 00          	cmpb   $0x0,-0x22(%ebp)
c0003e43:	74 45                	je     c0003e8a <intr_keyboard_handler+0x201>
      // 若缓冲区未满且待加入的cur_char不为0，则将其加入到缓冲区中
      if (!ioq_full(&kbd_buf)) {
c0003e45:	83 ec 0c             	sub    $0xc,%esp
c0003e48:	68 60 85 00 c0       	push   $0xc0008560
c0003e4d:	e8 64 01 00 00       	call   c0003fb6 <ioq_full>
c0003e52:	83 c4 10             	add    $0x10,%esp
c0003e55:	85 c0                	test   %eax,%eax
c0003e57:	0f 85 ae 00 00 00    	jne    c0003f0b <intr_keyboard_handler+0x282>
        put_char(cur_char); // 临时的
c0003e5d:	0f b6 45 de          	movzbl -0x22(%ebp),%eax
c0003e61:	0f b6 c0             	movzbl %al,%eax
c0003e64:	83 ec 0c             	sub    $0xc,%esp
c0003e67:	50                   	push   %eax
c0003e68:	e8 21 dc ff ff       	call   c0001a8e <put_char>
c0003e6d:	83 c4 10             	add    $0x10,%esp
        ioq_putchar(&kbd_buf, cur_char);
c0003e70:	0f be 45 de          	movsbl -0x22(%ebp),%eax
c0003e74:	83 ec 08             	sub    $0x8,%esp
c0003e77:	50                   	push   %eax
c0003e78:	68 60 85 00 c0       	push   $0xc0008560
c0003e7d:	e8 00 03 00 00       	call   c0004182 <ioq_putchar>
c0003e82:	83 c4 10             	add    $0x10,%esp
      }
      return;
c0003e85:	e9 81 00 00 00       	jmp    c0003f0b <intr_keyboard_handler+0x282>
    }

    if (scancode == ctrl_l_char || scancode == ctrl_r_char) {
c0003e8a:	66 83 7d f6 00       	cmpw   $0x0,-0xa(%ebp)
c0003e8f:	74 07                	je     c0003e98 <intr_keyboard_handler+0x20f>
c0003e91:	66 83 7d f6 00       	cmpw   $0x0,-0xa(%ebp)
c0003e96:	75 0c                	jne    c0003ea4 <intr_keyboard_handler+0x21b>
      ctrl_status = true;
c0003e98:	c7 05 cc 85 00 c0 01 	movl   $0x1,0xc00085cc
c0003e9f:	00 00 00 
c0003ea2:	eb 50                	jmp    c0003ef4 <intr_keyboard_handler+0x26b>
    } else if (scancode == shift_l_make || scancode == shift_r_make) {
c0003ea4:	66 83 7d f6 2a       	cmpw   $0x2a,-0xa(%ebp)
c0003ea9:	74 07                	je     c0003eb2 <intr_keyboard_handler+0x229>
c0003eab:	66 83 7d f6 36       	cmpw   $0x36,-0xa(%ebp)
c0003eb0:	75 0c                	jne    c0003ebe <intr_keyboard_handler+0x235>
      shift_status = true;
c0003eb2:	c7 05 d0 85 00 c0 01 	movl   $0x1,0xc00085d0
c0003eb9:	00 00 00 
c0003ebc:	eb 36                	jmp    c0003ef4 <intr_keyboard_handler+0x26b>
    } else if (scancode == alt_l_make || scancode == alt_r_make) {
c0003ebe:	66 83 7d f6 38       	cmpw   $0x38,-0xa(%ebp)
c0003ec3:	74 08                	je     c0003ecd <intr_keyboard_handler+0x244>
c0003ec5:	66 81 7d f6 38 e0    	cmpw   $0xe038,-0xa(%ebp)
c0003ecb:	75 0c                	jne    c0003ed9 <intr_keyboard_handler+0x250>
      alt_status = true;
c0003ecd:	c7 05 d4 85 00 c0 01 	movl   $0x1,0xc00085d4
c0003ed4:	00 00 00 
c0003ed7:	eb 1b                	jmp    c0003ef4 <intr_keyboard_handler+0x26b>
    } else if (scancode == caps_lock_make) {
c0003ed9:	66 83 7d f6 3a       	cmpw   $0x3a,-0xa(%ebp)
c0003ede:	75 2e                	jne    c0003f0e <intr_keyboard_handler+0x285>
      caps_lock_status = !caps_lock_status;
c0003ee0:	a1 d8 85 00 c0       	mov    0xc00085d8,%eax
c0003ee5:	85 c0                	test   %eax,%eax
c0003ee7:	0f 94 c0             	sete   %al
c0003eea:	0f b6 c0             	movzbl %al,%eax
c0003eed:	a3 d8 85 00 c0       	mov    %eax,0xc00085d8
             (scancode == ctrl_r_make)) { // 通码处理
c0003ef2:	eb 1a                	jmp    c0003f0e <intr_keyboard_handler+0x285>
c0003ef4:	eb 18                	jmp    c0003f0e <intr_keyboard_handler+0x285>
    }
  } else {
    put_str("unknown key\n");
c0003ef6:	83 ec 0c             	sub    $0xc,%esp
c0003ef9:	68 d5 5a 00 c0       	push   $0xc0005ad5
c0003efe:	e8 6d db ff ff       	call   c0001a70 <put_str>
c0003f03:	83 c4 10             	add    $0x10,%esp
c0003f06:	eb 07                	jmp    c0003f0f <intr_keyboard_handler+0x286>
    return;
c0003f08:	90                   	nop
c0003f09:	eb 04                	jmp    c0003f0f <intr_keyboard_handler+0x286>
      return;
c0003f0b:	90                   	nop
c0003f0c:	eb 01                	jmp    c0003f0f <intr_keyboard_handler+0x286>
             (scancode == ctrl_r_make)) { // 通码处理
c0003f0e:	90                   	nop
  }
}
c0003f0f:	c9                   	leave  
c0003f10:	c3                   	ret    

c0003f11 <keyboard_init>:

// 键盘初始化
void keyboard_init() {
c0003f11:	55                   	push   %ebp
c0003f12:	89 e5                	mov    %esp,%ebp
c0003f14:	83 ec 08             	sub    $0x8,%esp
  put_str("keyboard_init start\n");
c0003f17:	83 ec 0c             	sub    $0xc,%esp
c0003f1a:	68 e2 5a 00 c0       	push   $0xc0005ae2
c0003f1f:	e8 4c db ff ff       	call   c0001a70 <put_str>
c0003f24:	83 c4 10             	add    $0x10,%esp
  ioqueue_init(&kbd_buf);
c0003f27:	83 ec 0c             	sub    $0xc,%esp
c0003f2a:	68 60 85 00 c0       	push   $0xc0008560
c0003f2f:	e8 28 00 00 00       	call   c0003f5c <ioqueue_init>
c0003f34:	83 c4 10             	add    $0x10,%esp
  register_handler(0x21, intr_keyboard_handler);
c0003f37:	83 ec 08             	sub    $0x8,%esp
c0003f3a:	68 89 3c 00 c0       	push   $0xc0003c89
c0003f3f:	6a 21                	push   $0x21
c0003f41:	e8 70 da ff ff       	call   c00019b6 <register_handler>
c0003f46:	83 c4 10             	add    $0x10,%esp
  put_str("keyboard_init done\n");
c0003f49:	83 ec 0c             	sub    $0xc,%esp
c0003f4c:	68 f7 5a 00 c0       	push   $0xc0005af7
c0003f51:	e8 1a db ff ff       	call   c0001a70 <put_str>
c0003f56:	83 c4 10             	add    $0x10,%esp
c0003f59:	90                   	nop
c0003f5a:	c9                   	leave  
c0003f5b:	c3                   	ret    

c0003f5c <ioqueue_init>:
#include "debug.h"
#include "global.h"
#include "interrupt.h"
#include "stdint.h"

void ioqueue_init(struct ioqueue *ioq) {
c0003f5c:	55                   	push   %ebp
c0003f5d:	89 e5                	mov    %esp,%ebp
c0003f5f:	83 ec 08             	sub    $0x8,%esp
  lock_init(&ioq->lock);
c0003f62:	8b 45 08             	mov    0x8(%ebp),%eax
c0003f65:	83 ec 0c             	sub    $0xc,%esp
c0003f68:	50                   	push   %eax
c0003f69:	e8 61 f9 ff ff       	call   c00038cf <lock_init>
c0003f6e:	83 c4 10             	add    $0x10,%esp
  ioq->producer = ioq->consumer = NULL;
c0003f71:	8b 45 08             	mov    0x8(%ebp),%eax
c0003f74:	c7 40 20 00 00 00 00 	movl   $0x0,0x20(%eax)
c0003f7b:	8b 45 08             	mov    0x8(%ebp),%eax
c0003f7e:	8b 50 20             	mov    0x20(%eax),%edx
c0003f81:	8b 45 08             	mov    0x8(%ebp),%eax
c0003f84:	89 50 1c             	mov    %edx,0x1c(%eax)
  ioq->head = ioq->tail = 0;
c0003f87:	8b 45 08             	mov    0x8(%ebp),%eax
c0003f8a:	c7 40 68 00 00 00 00 	movl   $0x0,0x68(%eax)
c0003f91:	8b 45 08             	mov    0x8(%ebp),%eax
c0003f94:	8b 50 68             	mov    0x68(%eax),%edx
c0003f97:	8b 45 08             	mov    0x8(%ebp),%eax
c0003f9a:	89 50 64             	mov    %edx,0x64(%eax)
}
c0003f9d:	90                   	nop
c0003f9e:	c9                   	leave  
c0003f9f:	c3                   	ret    

c0003fa0 <next_pos>:

// 返回pos在缓冲区中的下一个位置值
static int32_t next_pos(int32_t pos) { return (pos + 1) % bufsize; }
c0003fa0:	55                   	push   %ebp
c0003fa1:	89 e5                	mov    %esp,%ebp
c0003fa3:	8b 45 08             	mov    0x8(%ebp),%eax
c0003fa6:	83 c0 01             	add    $0x1,%eax
c0003fa9:	99                   	cltd   
c0003faa:	c1 ea 1a             	shr    $0x1a,%edx
c0003fad:	01 d0                	add    %edx,%eax
c0003faf:	83 e0 3f             	and    $0x3f,%eax
c0003fb2:	29 d0                	sub    %edx,%eax
c0003fb4:	5d                   	pop    %ebp
c0003fb5:	c3                   	ret    

c0003fb6 <ioq_full>:

bool ioq_full(struct ioqueue *ioq) {
c0003fb6:	55                   	push   %ebp
c0003fb7:	89 e5                	mov    %esp,%ebp
c0003fb9:	83 ec 08             	sub    $0x8,%esp
  ASSERT(intr_get_status() == INTR_OFF);
c0003fbc:	e8 30 da ff ff       	call   c00019f1 <intr_get_status>
c0003fc1:	85 c0                	test   %eax,%eax
c0003fc3:	74 19                	je     c0003fde <ioq_full+0x28>
c0003fc5:	68 0c 5b 00 c0       	push   $0xc0005b0c
c0003fca:	68 70 5b 00 c0       	push   $0xc0005b70
c0003fcf:	6a 11                	push   $0x11
c0003fd1:	68 2a 5b 00 c0       	push   $0xc0005b2a
c0003fd6:	e8 95 e2 ff ff       	call   c0002270 <panic_spin>
c0003fdb:	83 c4 10             	add    $0x10,%esp
  return next_pos(ioq->head) == ioq->tail;
c0003fde:	8b 45 08             	mov    0x8(%ebp),%eax
c0003fe1:	8b 40 64             	mov    0x64(%eax),%eax
c0003fe4:	83 ec 0c             	sub    $0xc,%esp
c0003fe7:	50                   	push   %eax
c0003fe8:	e8 b3 ff ff ff       	call   c0003fa0 <next_pos>
c0003fed:	83 c4 10             	add    $0x10,%esp
c0003ff0:	8b 55 08             	mov    0x8(%ebp),%edx
c0003ff3:	8b 52 68             	mov    0x68(%edx),%edx
c0003ff6:	39 d0                	cmp    %edx,%eax
c0003ff8:	0f 94 c0             	sete   %al
c0003ffb:	0f b6 c0             	movzbl %al,%eax
}
c0003ffe:	c9                   	leave  
c0003fff:	c3                   	ret    

c0004000 <ioq_empty>:

bool ioq_empty(struct ioqueue *ioq) {
c0004000:	55                   	push   %ebp
c0004001:	89 e5                	mov    %esp,%ebp
c0004003:	83 ec 08             	sub    $0x8,%esp
  ASSERT(intr_get_status() == INTR_OFF);
c0004006:	e8 e6 d9 ff ff       	call   c00019f1 <intr_get_status>
c000400b:	85 c0                	test   %eax,%eax
c000400d:	74 19                	je     c0004028 <ioq_empty+0x28>
c000400f:	68 0c 5b 00 c0       	push   $0xc0005b0c
c0004014:	68 7c 5b 00 c0       	push   $0xc0005b7c
c0004019:	6a 16                	push   $0x16
c000401b:	68 2a 5b 00 c0       	push   $0xc0005b2a
c0004020:	e8 4b e2 ff ff       	call   c0002270 <panic_spin>
c0004025:	83 c4 10             	add    $0x10,%esp
  return ioq->head == ioq->tail;
c0004028:	8b 45 08             	mov    0x8(%ebp),%eax
c000402b:	8b 50 64             	mov    0x64(%eax),%edx
c000402e:	8b 45 08             	mov    0x8(%ebp),%eax
c0004031:	8b 40 68             	mov    0x68(%eax),%eax
c0004034:	39 c2                	cmp    %eax,%edx
c0004036:	0f 94 c0             	sete   %al
c0004039:	0f b6 c0             	movzbl %al,%eax
}
c000403c:	c9                   	leave  
c000403d:	c3                   	ret    

c000403e <ioq_wait>:

// 使当前生产者/消费者在此缓冲区上等待
static void ioq_wait(struct task_struct **waiter) {
c000403e:	55                   	push   %ebp
c000403f:	89 e5                	mov    %esp,%ebp
c0004041:	83 ec 08             	sub    $0x8,%esp
  ASSERT(*waiter == NULL && waiter != NULL);
c0004044:	8b 45 08             	mov    0x8(%ebp),%eax
c0004047:	8b 00                	mov    (%eax),%eax
c0004049:	85 c0                	test   %eax,%eax
c000404b:	75 06                	jne    c0004053 <ioq_wait+0x15>
c000404d:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c0004051:	75 19                	jne    c000406c <ioq_wait+0x2e>
c0004053:	68 3c 5b 00 c0       	push   $0xc0005b3c
c0004058:	68 88 5b 00 c0       	push   $0xc0005b88
c000405d:	6a 1c                	push   $0x1c
c000405f:	68 2a 5b 00 c0       	push   $0xc0005b2a
c0004064:	e8 07 e2 ff ff       	call   c0002270 <panic_spin>
c0004069:	83 c4 10             	add    $0x10,%esp
  *waiter = running_thread();
c000406c:	e8 d1 f0 ff ff       	call   c0003142 <running_thread>
c0004071:	8b 55 08             	mov    0x8(%ebp),%edx
c0004074:	89 02                	mov    %eax,(%edx)
  thread_block(TASK_BLOCKED);
c0004076:	83 ec 0c             	sub    $0xc,%esp
c0004079:	6a 02                	push   $0x2
c000407b:	e8 bd f4 ff ff       	call   c000353d <thread_block>
c0004080:	83 c4 10             	add    $0x10,%esp
}
c0004083:	90                   	nop
c0004084:	c9                   	leave  
c0004085:	c3                   	ret    

c0004086 <wakeup>:

// 唤醒waiter
static void wakeup(struct task_struct **waiter) {
c0004086:	55                   	push   %ebp
c0004087:	89 e5                	mov    %esp,%ebp
c0004089:	83 ec 08             	sub    $0x8,%esp
  ASSERT(*waiter != NULL);
c000408c:	8b 45 08             	mov    0x8(%ebp),%eax
c000408f:	8b 00                	mov    (%eax),%eax
c0004091:	85 c0                	test   %eax,%eax
c0004093:	75 19                	jne    c00040ae <wakeup+0x28>
c0004095:	68 5e 5b 00 c0       	push   $0xc0005b5e
c000409a:	68 94 5b 00 c0       	push   $0xc0005b94
c000409f:	6a 23                	push   $0x23
c00040a1:	68 2a 5b 00 c0       	push   $0xc0005b2a
c00040a6:	e8 c5 e1 ff ff       	call   c0002270 <panic_spin>
c00040ab:	83 c4 10             	add    $0x10,%esp
  thread_unblock(*waiter);
c00040ae:	8b 45 08             	mov    0x8(%ebp),%eax
c00040b1:	8b 00                	mov    (%eax),%eax
c00040b3:	83 ec 0c             	sub    $0xc,%esp
c00040b6:	50                   	push   %eax
c00040b7:	e8 e4 f4 ff ff       	call   c00035a0 <thread_unblock>
c00040bc:	83 c4 10             	add    $0x10,%esp
  *waiter = NULL;
c00040bf:	8b 45 08             	mov    0x8(%ebp),%eax
c00040c2:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
}
c00040c8:	90                   	nop
c00040c9:	c9                   	leave  
c00040ca:	c3                   	ret    

c00040cb <ioq_getchar>:

// 消费者从ioq队列中读一字节
char ioq_getchar(struct ioqueue *ioq) {
c00040cb:	55                   	push   %ebp
c00040cc:	89 e5                	mov    %esp,%ebp
c00040ce:	83 ec 18             	sub    $0x18,%esp
  ASSERT(intr_get_status() == INTR_OFF);
c00040d1:	e8 1b d9 ff ff       	call   c00019f1 <intr_get_status>
c00040d6:	85 c0                	test   %eax,%eax
c00040d8:	74 4b                	je     c0004125 <ioq_getchar+0x5a>
c00040da:	68 0c 5b 00 c0       	push   $0xc0005b0c
c00040df:	68 9c 5b 00 c0       	push   $0xc0005b9c
c00040e4:	6a 2a                	push   $0x2a
c00040e6:	68 2a 5b 00 c0       	push   $0xc0005b2a
c00040eb:	e8 80 e1 ff ff       	call   c0002270 <panic_spin>
c00040f0:	83 c4 10             	add    $0x10,%esp
  while (ioq_empty(ioq)) {
c00040f3:	eb 30                	jmp    c0004125 <ioq_getchar+0x5a>
    // 缓冲区为空-> 先睡眠
    lock_acquire(&ioq->lock);
c00040f5:	8b 45 08             	mov    0x8(%ebp),%eax
c00040f8:	83 ec 0c             	sub    $0xc,%esp
c00040fb:	50                   	push   %eax
c00040fc:	e8 a8 f9 ff ff       	call   c0003aa9 <lock_acquire>
c0004101:	83 c4 10             	add    $0x10,%esp
    ioq_wait(&ioq->consumer);
c0004104:	8b 45 08             	mov    0x8(%ebp),%eax
c0004107:	83 c0 20             	add    $0x20,%eax
c000410a:	83 ec 0c             	sub    $0xc,%esp
c000410d:	50                   	push   %eax
c000410e:	e8 2b ff ff ff       	call   c000403e <ioq_wait>
c0004113:	83 c4 10             	add    $0x10,%esp
    lock_release(&ioq->lock);
c0004116:	8b 45 08             	mov    0x8(%ebp),%eax
c0004119:	83 ec 0c             	sub    $0xc,%esp
c000411c:	50                   	push   %eax
c000411d:	e8 fc f9 ff ff       	call   c0003b1e <lock_release>
c0004122:	83 c4 10             	add    $0x10,%esp
  while (ioq_empty(ioq)) {
c0004125:	83 ec 0c             	sub    $0xc,%esp
c0004128:	ff 75 08             	push   0x8(%ebp)
c000412b:	e8 d0 fe ff ff       	call   c0004000 <ioq_empty>
c0004130:	83 c4 10             	add    $0x10,%esp
c0004133:	85 c0                	test   %eax,%eax
c0004135:	75 be                	jne    c00040f5 <ioq_getchar+0x2a>
  }
  char byte = ioq->buf[ioq->tail]; // 从缓冲区中取出
c0004137:	8b 45 08             	mov    0x8(%ebp),%eax
c000413a:	8b 40 68             	mov    0x68(%eax),%eax
c000413d:	8b 55 08             	mov    0x8(%ebp),%edx
c0004140:	0f b6 44 02 24       	movzbl 0x24(%edx,%eax,1),%eax
c0004145:	88 45 f7             	mov    %al,-0x9(%ebp)
  ioq->tail = next_pos(ioq->tail); // 把读游标移到下一位置
c0004148:	8b 45 08             	mov    0x8(%ebp),%eax
c000414b:	8b 40 68             	mov    0x68(%eax),%eax
c000414e:	83 ec 0c             	sub    $0xc,%esp
c0004151:	50                   	push   %eax
c0004152:	e8 49 fe ff ff       	call   c0003fa0 <next_pos>
c0004157:	83 c4 10             	add    $0x10,%esp
c000415a:	8b 55 08             	mov    0x8(%ebp),%edx
c000415d:	89 42 68             	mov    %eax,0x68(%edx)
  if (ioq->producer != NULL) {
c0004160:	8b 45 08             	mov    0x8(%ebp),%eax
c0004163:	8b 40 1c             	mov    0x1c(%eax),%eax
c0004166:	85 c0                	test   %eax,%eax
c0004168:	74 12                	je     c000417c <ioq_getchar+0xb1>
    wakeup(&ioq->producer); // 唤醒生产者
c000416a:	8b 45 08             	mov    0x8(%ebp),%eax
c000416d:	83 c0 1c             	add    $0x1c,%eax
c0004170:	83 ec 0c             	sub    $0xc,%esp
c0004173:	50                   	push   %eax
c0004174:	e8 0d ff ff ff       	call   c0004086 <wakeup>
c0004179:	83 c4 10             	add    $0x10,%esp
  }
  return byte;
c000417c:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
}
c0004180:	c9                   	leave  
c0004181:	c3                   	ret    

c0004182 <ioq_putchar>:

// 生产者往ioq队列中写一字节
void ioq_putchar(struct ioqueue *ioq, char byte) {
c0004182:	55                   	push   %ebp
c0004183:	89 e5                	mov    %esp,%ebp
c0004185:	83 ec 18             	sub    $0x18,%esp
c0004188:	8b 45 0c             	mov    0xc(%ebp),%eax
c000418b:	88 45 f4             	mov    %al,-0xc(%ebp)
  ASSERT(intr_get_status() == INTR_OFF);
c000418e:	e8 5e d8 ff ff       	call   c00019f1 <intr_get_status>
c0004193:	85 c0                	test   %eax,%eax
c0004195:	74 4b                	je     c00041e2 <ioq_putchar+0x60>
c0004197:	68 0c 5b 00 c0       	push   $0xc0005b0c
c000419c:	68 a8 5b 00 c0       	push   $0xc0005ba8
c00041a1:	6a 3b                	push   $0x3b
c00041a3:	68 2a 5b 00 c0       	push   $0xc0005b2a
c00041a8:	e8 c3 e0 ff ff       	call   c0002270 <panic_spin>
c00041ad:	83 c4 10             	add    $0x10,%esp
  while (ioq_full(ioq)) {
c00041b0:	eb 30                	jmp    c00041e2 <ioq_putchar+0x60>
    // 缓冲区满-> 先睡眠
    lock_acquire(&ioq->lock); // 避免惊群情况出现
c00041b2:	8b 45 08             	mov    0x8(%ebp),%eax
c00041b5:	83 ec 0c             	sub    $0xc,%esp
c00041b8:	50                   	push   %eax
c00041b9:	e8 eb f8 ff ff       	call   c0003aa9 <lock_acquire>
c00041be:	83 c4 10             	add    $0x10,%esp
    ioq_wait(&ioq->producer);
c00041c1:	8b 45 08             	mov    0x8(%ebp),%eax
c00041c4:	83 c0 1c             	add    $0x1c,%eax
c00041c7:	83 ec 0c             	sub    $0xc,%esp
c00041ca:	50                   	push   %eax
c00041cb:	e8 6e fe ff ff       	call   c000403e <ioq_wait>
c00041d0:	83 c4 10             	add    $0x10,%esp
    lock_release(&ioq->lock);
c00041d3:	8b 45 08             	mov    0x8(%ebp),%eax
c00041d6:	83 ec 0c             	sub    $0xc,%esp
c00041d9:	50                   	push   %eax
c00041da:	e8 3f f9 ff ff       	call   c0003b1e <lock_release>
c00041df:	83 c4 10             	add    $0x10,%esp
  while (ioq_full(ioq)) {
c00041e2:	83 ec 0c             	sub    $0xc,%esp
c00041e5:	ff 75 08             	push   0x8(%ebp)
c00041e8:	e8 c9 fd ff ff       	call   c0003fb6 <ioq_full>
c00041ed:	83 c4 10             	add    $0x10,%esp
c00041f0:	85 c0                	test   %eax,%eax
c00041f2:	75 be                	jne    c00041b2 <ioq_putchar+0x30>
  }
  ioq->buf[ioq->head] = byte;      // 把字节放入缓冲区中
c00041f4:	8b 45 08             	mov    0x8(%ebp),%eax
c00041f7:	8b 40 64             	mov    0x64(%eax),%eax
c00041fa:	8b 55 08             	mov    0x8(%ebp),%edx
c00041fd:	0f b6 4d f4          	movzbl -0xc(%ebp),%ecx
c0004201:	88 4c 02 24          	mov    %cl,0x24(%edx,%eax,1)
  ioq->head = next_pos(ioq->head); // 把写游标移到下一位置
c0004205:	8b 45 08             	mov    0x8(%ebp),%eax
c0004208:	8b 40 64             	mov    0x64(%eax),%eax
c000420b:	83 ec 0c             	sub    $0xc,%esp
c000420e:	50                   	push   %eax
c000420f:	e8 8c fd ff ff       	call   c0003fa0 <next_pos>
c0004214:	83 c4 10             	add    $0x10,%esp
c0004217:	8b 55 08             	mov    0x8(%ebp),%edx
c000421a:	89 42 64             	mov    %eax,0x64(%edx)
  if (ioq->consumer != NULL) {
c000421d:	8b 45 08             	mov    0x8(%ebp),%eax
c0004220:	8b 40 20             	mov    0x20(%eax),%eax
c0004223:	85 c0                	test   %eax,%eax
c0004225:	74 12                	je     c0004239 <ioq_putchar+0xb7>
    wakeup(&ioq->consumer); // 唤醒消费者
c0004227:	8b 45 08             	mov    0x8(%ebp),%eax
c000422a:	83 c0 20             	add    $0x20,%eax
c000422d:	83 ec 0c             	sub    $0xc,%esp
c0004230:	50                   	push   %eax
c0004231:	e8 50 fe ff ff       	call   c0004086 <wakeup>
c0004236:	83 c4 10             	add    $0x10,%esp
  }
c0004239:	90                   	nop
c000423a:	c9                   	leave  
c000423b:	c3                   	ret    

c000423c <update_tss_esp>:
};
static struct tss tss;
#define PG_SIZE 4096

// 更新tss中的esp0-> pthread的0级栈
void update_tss_esp(struct task_struct *pthread) {
c000423c:	55                   	push   %ebp
c000423d:	89 e5                	mov    %esp,%ebp
  // Linux任务切换-> 仅修改TSS中特权级0对应的栈
  tss.esp0 = (uint32_t *)((uint32_t)pthread + PG_SIZE);
c000423f:	8b 45 08             	mov    0x8(%ebp),%eax
c0004242:	05 00 10 00 00       	add    $0x1000,%eax
c0004247:	a3 e4 85 00 c0       	mov    %eax,0xc00085e4
}
c000424c:	90                   	nop
c000424d:	5d                   	pop    %ebp
c000424e:	c3                   	ret    

c000424f <make_gdt_desc>:

// 创建GDT描述符
static struct gdt_desc make_gdt_desc(uint32_t *desc_addr, uint32_t limit,
                                     uint8_t attr_low, uint8_t attr_high) {
c000424f:	55                   	push   %ebp
c0004250:	89 e5                	mov    %esp,%ebp
c0004252:	83 ec 18             	sub    $0x18,%esp
c0004255:	8b 55 14             	mov    0x14(%ebp),%edx
c0004258:	8b 45 18             	mov    0x18(%ebp),%eax
c000425b:	88 55 ec             	mov    %dl,-0x14(%ebp)
c000425e:	88 45 e8             	mov    %al,-0x18(%ebp)
  uint32_t desc_base = (uint32_t)desc_addr;
c0004261:	8b 45 0c             	mov    0xc(%ebp),%eax
c0004264:	89 45 fc             	mov    %eax,-0x4(%ebp)
  struct gdt_desc desc;
  desc.limit_low_word = limit & 0x0000ffff;
c0004267:	8b 45 10             	mov    0x10(%ebp),%eax
c000426a:	66 89 45 f4          	mov    %ax,-0xc(%ebp)
  desc.limit_low_word = desc_base & 0x0000ffff;
c000426e:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0004271:	66 89 45 f4          	mov    %ax,-0xc(%ebp)
  desc.base_mid_byte = ((desc_base & 0x00ff0000) >> 16);
c0004275:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0004278:	c1 e8 10             	shr    $0x10,%eax
c000427b:	88 45 f8             	mov    %al,-0x8(%ebp)
  desc.attr_low_byte = (uint8_t)(attr_low);
c000427e:	0f b6 45 ec          	movzbl -0x14(%ebp),%eax
c0004282:	88 45 f9             	mov    %al,-0x7(%ebp)
  desc.limit_high_attr_high =
      (((limit & 0x000f0000) >> 16) + (uint8_t)(attr_high));
c0004285:	8b 45 10             	mov    0x10(%ebp),%eax
c0004288:	c1 e8 10             	shr    $0x10,%eax
c000428b:	83 e0 0f             	and    $0xf,%eax
c000428e:	89 c2                	mov    %eax,%edx
c0004290:	0f b6 45 e8          	movzbl -0x18(%ebp),%eax
c0004294:	01 d0                	add    %edx,%eax
  desc.limit_high_attr_high =
c0004296:	88 45 fa             	mov    %al,-0x6(%ebp)
  desc.base_high_byte = desc_base >> 24;
c0004299:	8b 45 fc             	mov    -0x4(%ebp),%eax
c000429c:	c1 e8 18             	shr    $0x18,%eax
c000429f:	88 45 fb             	mov    %al,-0x5(%ebp)
  return desc;
c00042a2:	8b 4d 08             	mov    0x8(%ebp),%ecx
c00042a5:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00042a8:	8b 55 f8             	mov    -0x8(%ebp),%edx
c00042ab:	89 01                	mov    %eax,(%ecx)
c00042ad:	89 51 04             	mov    %edx,0x4(%ecx)
}
c00042b0:	8b 45 08             	mov    0x8(%ebp),%eax
c00042b3:	c9                   	leave  
c00042b4:	c2 04 00             	ret    $0x4

c00042b7 <tss_init>:

// 初始化tss并装到GDT中，并在GDT中安装两个供用户进程用的描述符（DATA和CODE）
void tss_init() {
c00042b7:	55                   	push   %ebp
c00042b8:	89 e5                	mov    %esp,%ebp
c00042ba:	53                   	push   %ebx
c00042bb:	83 ec 24             	sub    $0x24,%esp
  put_str("tss_init start\n");
c00042be:	83 ec 0c             	sub    $0xc,%esp
c00042c1:	68 b4 5b 00 c0       	push   $0xc0005bb4
c00042c6:	e8 a5 d7 ff ff       	call   c0001a70 <put_str>
c00042cb:	83 c4 10             	add    $0x10,%esp
  uint32_t tss_size = sizeof(tss);
c00042ce:	c7 45 f4 6c 00 00 00 	movl   $0x6c,-0xc(%ebp)
  memset(&tss, 0, tss_size);
c00042d5:	83 ec 04             	sub    $0x4,%esp
c00042d8:	ff 75 f4             	push   -0xc(%ebp)
c00042db:	6a 00                	push   $0x0
c00042dd:	68 e0 85 00 c0       	push   $0xc00085e0
c00042e2:	e8 5f e0 ff ff       	call   c0002346 <memset>
c00042e7:	83 c4 10             	add    $0x10,%esp
  tss.ss0 = SELECTOR_K_STACK;
c00042ea:	c7 05 e8 85 00 c0 10 	movl   $0x10,0xc00085e8
c00042f1:	00 00 00 
  tss.io_base = tss_size; // 表示此TSS中没有IO位图
c00042f4:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00042f7:	a3 48 86 00 c0       	mov    %eax,0xc0008648

  // gdt段基址为0x900，tss放第4个也就是0x900+0x20

  // GDT中添加dpl=0的tss描述符、dpl=3的数据段和代码段描述符
  *((struct gdt_desc *)0xc0000920) = make_gdt_desc(
c00042fc:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00042ff:	8d 50 ff             	lea    -0x1(%eax),%edx
c0004302:	bb 20 09 00 c0       	mov    $0xc0000920,%ebx
c0004307:	8d 45 e0             	lea    -0x20(%ebp),%eax
c000430a:	83 ec 0c             	sub    $0xc,%esp
c000430d:	68 80 00 00 00       	push   $0x80
c0004312:	68 89 00 00 00       	push   $0x89
c0004317:	52                   	push   %edx
c0004318:	68 e0 85 00 c0       	push   $0xc00085e0
c000431d:	50                   	push   %eax
c000431e:	e8 2c ff ff ff       	call   c000424f <make_gdt_desc>
c0004323:	83 c4 1c             	add    $0x1c,%esp
c0004326:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0004329:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c000432c:	89 03                	mov    %eax,(%ebx)
c000432e:	89 53 04             	mov    %edx,0x4(%ebx)
      (uint32_t *)&tss, tss_size - 1, TSS_ATTR_LOW, TSS_ATTR_HIGH);
  *((struct gdt_desc *)0xc0000928) = make_gdt_desc(
c0004331:	bb 28 09 00 c0       	mov    $0xc0000928,%ebx
c0004336:	8d 45 e0             	lea    -0x20(%ebp),%eax
c0004339:	83 ec 0c             	sub    $0xc,%esp
c000433c:	68 c0 00 00 00       	push   $0xc0
c0004341:	68 f8 00 00 00       	push   $0xf8
c0004346:	68 ff ff 0f 00       	push   $0xfffff
c000434b:	6a 00                	push   $0x0
c000434d:	50                   	push   %eax
c000434e:	e8 fc fe ff ff       	call   c000424f <make_gdt_desc>
c0004353:	83 c4 1c             	add    $0x1c,%esp
c0004356:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0004359:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c000435c:	89 03                	mov    %eax,(%ebx)
c000435e:	89 53 04             	mov    %edx,0x4(%ebx)
      (uint32_t *)0, 0xfffff, GDT_CODE_ATTR_LOW_DPL3, GDT_ATTR_HIGH);
  *((struct gdt_desc *)0xc0000930) = make_gdt_desc(
c0004361:	bb 30 09 00 c0       	mov    $0xc0000930,%ebx
c0004366:	8d 45 e0             	lea    -0x20(%ebp),%eax
c0004369:	83 ec 0c             	sub    $0xc,%esp
c000436c:	68 c0 00 00 00       	push   $0xc0
c0004371:	68 f2 00 00 00       	push   $0xf2
c0004376:	68 ff ff 0f 00       	push   $0xfffff
c000437b:	6a 00                	push   $0x0
c000437d:	50                   	push   %eax
c000437e:	e8 cc fe ff ff       	call   c000424f <make_gdt_desc>
c0004383:	83 c4 1c             	add    $0x1c,%esp
c0004386:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0004389:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c000438c:	89 03                	mov    %eax,(%ebx)
c000438e:	89 53 04             	mov    %edx,0x4(%ebx)
      (uint32_t *)0, 0xfffff, GDT_DATA_ATTR_LOW_DPL3, GDT_ATTR_HIGH);

  // 16位表界限 & 32位表起始地址
  uint64_t gdt_operand = ((8 * 7 - 1) | ((uint64_t)(uint32_t)0xc0000900 << 16));
c0004391:	c7 45 e8 37 00 00 09 	movl   $0x9000037,-0x18(%ebp)
c0004398:	c7 45 ec 00 c0 00 00 	movl   $0xc000,-0x14(%ebp)
  asm volatile("lgdt %0" : : "m"(gdt_operand));  // GDT变更，重新加载GDT
c000439f:	0f 01 55 e8          	lgdtl  -0x18(%ebp)
  asm volatile("ltr %w0" : : "r"(SELECTOR_TSS)); // 将tss加载到TR
c00043a3:	b8 20 00 00 00       	mov    $0x20,%eax
c00043a8:	0f 00 d8             	ltr    %ax
  put_str("tss_init and ltr done\n");
c00043ab:	83 ec 0c             	sub    $0xc,%esp
c00043ae:	68 c4 5b 00 c0       	push   $0xc0005bc4
c00043b3:	e8 b8 d6 ff ff       	call   c0001a70 <put_str>
c00043b8:	83 c4 10             	add    $0x10,%esp
c00043bb:	90                   	nop
c00043bc:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c00043bf:	c9                   	leave  
c00043c0:	c3                   	ret    

 <start_processc00043c1>:
#include "userprog.h"

extern void intr_exit(void);

// 创建用户进程filename的上下文（填充用户进程的中断栈intr_stack
void start_process(void *filename_) {
c00043c1:	55                   	push   %ebp
c00043c2:	89 e5                	mov    %esp,%ebp
c00043c4:	83 ec 18             	sub    $0x18,%esp
  void *func = filename_;
c00043c7:	8b 45 08             	mov    0x8(%ebp),%eax
c00043ca:	89 45 f4             	mov    %eax,-0xc(%ebp)
  struct task_struct *cur = running_thread();
c00043cd:	e8 70 ed ff ff       	call   c0003142 <running_thread>
c00043d2:	89 45 f0             	mov    %eax,-0x10(%ebp)
  cur->self_kstack +=
c00043d5:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00043d8:	8b 00                	mov    (%eax),%eax
c00043da:	8d 90 80 00 00 00    	lea    0x80(%eax),%edx
c00043e0:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00043e3:	89 10                	mov    %edx,(%eax)
  /*
   *【创建线程的时候没预留但是运行正常的原因猜测】
   * 此时处与内核态，指针可能指向了内核空间。
   * PCB放在内核空间中，导致越界的空间可能是刚好初始化预留过的
   */
  struct intr_stack *proc_stack = (struct intr_stack *)cur->self_kstack;
c00043e5:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00043e8:	8b 00                	mov    (%eax),%eax
c00043ea:	89 45 ec             	mov    %eax,-0x14(%ebp)
  proc_stack->edi = 0;
c00043ed:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00043f0:	c7 40 04 00 00 00 00 	movl   $0x0,0x4(%eax)
  proc_stack->esi = 0;
c00043f7:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00043fa:	c7 40 08 00 00 00 00 	movl   $0x0,0x8(%eax)
  proc_stack->ebp = 0;
c0004401:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004404:	c7 40 0c 00 00 00 00 	movl   $0x0,0xc(%eax)
  proc_stack->esp_dummy = 0;
c000440b:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000440e:	c7 40 10 00 00 00 00 	movl   $0x0,0x10(%eax)

  proc_stack->ebx = 0;
c0004415:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004418:	c7 40 14 00 00 00 00 	movl   $0x0,0x14(%eax)
  proc_stack->edx = 0;
c000441f:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004422:	c7 40 18 00 00 00 00 	movl   $0x0,0x18(%eax)
  proc_stack->ecx = 0;
c0004429:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000442c:	c7 40 1c 00 00 00 00 	movl   $0x0,0x1c(%eax)
  proc_stack->eax = 0;
c0004433:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004436:	c7 40 20 00 00 00 00 	movl   $0x0,0x20(%eax)

  proc_stack->gs = 0; // 显存段用户态用不上
c000443d:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004440:	c7 40 24 00 00 00 00 	movl   $0x0,0x24(%eax)

  proc_stack->ds = SELECTOR_U_DATA;
c0004447:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000444a:	c7 40 30 33 00 00 00 	movl   $0x33,0x30(%eax)
  proc_stack->es = SELECTOR_U_DATA;
c0004451:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004454:	c7 40 2c 33 00 00 00 	movl   $0x33,0x2c(%eax)
  proc_stack->fs = SELECTOR_U_DATA;
c000445b:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000445e:	c7 40 28 33 00 00 00 	movl   $0x33,0x28(%eax)

  proc_stack->eip = func; // 待执行的用户程序
c0004465:	8b 55 f4             	mov    -0xc(%ebp),%edx
c0004468:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000446b:	89 50 38             	mov    %edx,0x38(%eax)
  proc_stack->cs = SELECTOR_U_CODE;
c000446e:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004471:	c7 40 3c 2b 00 00 00 	movl   $0x2b,0x3c(%eax)
  proc_stack->eflags = (EFLAGS_IOPL_0 | EFLAGS_MBS | EFLAGS_IF_1);
c0004478:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000447b:	c7 40 40 02 02 00 00 	movl   $0x202,0x40(%eax)

  // 为用户进程分配3特权级栈->（esp指向从用户内存池中分配的地址
  proc_stack->esp =
      (void *)((uint32_t)get_a_page(PF_USER, USER_STACK3_VADDR) + PG_SIZE);
c0004482:	83 ec 08             	sub    $0x8,%esp
c0004485:	68 00 f0 ff bf       	push   $0xbffff000
c000448a:	6a 02                	push   $0x2
c000448c:	e8 ea e8 ff ff       	call   c0002d7b <get_a_page>
c0004491:	83 c4 10             	add    $0x10,%esp
c0004494:	05 00 10 00 00       	add    $0x1000,%eax
c0004499:	89 c2                	mov    %eax,%edx
  proc_stack->esp =
c000449b:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000449e:	89 50 44             	mov    %edx,0x44(%eax)
  proc_stack->ss = SELECTOR_U_DATA; // 栈段
c00044a1:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00044a4:	c7 40 48 33 00 00 00 	movl   $0x33,0x48(%eax)

  asm volatile("movl %0, %%esp; jmp intr_exit" ::"g"(proc_stack) : "memory");
c00044ab:	8b 65 ec             	mov    -0x14(%ebp),%esp
c00044ae:	e9 0d d7 ff ff       	jmp    c0001bc0 <intr_exit>
}
c00044b3:	90                   	nop
c00044b4:	c9                   	leave  
c00044b5:	c3                   	ret    

c00044b6 <page_dir_activate>:

// 激活进程/线程页表-> 更新cr3
void page_dir_activate(struct task_struct *p_thread) {
c00044b6:	55                   	push   %ebp
c00044b7:	89 e5                	mov    %esp,%ebp
c00044b9:	83 ec 18             	sub    $0x18,%esp
  // 内核线程，默认为内核页目录物理地址
  uint32_t pagedir_phy_addr = 0x100000;
c00044bc:	c7 45 f4 00 00 10 00 	movl   $0x100000,-0xc(%ebp)
  if (p_thread->pgdir != NULL) { // 用户进程有自己的页目录表
c00044c3:	8b 45 08             	mov    0x8(%ebp),%eax
c00044c6:	8b 40 30             	mov    0x30(%eax),%eax
c00044c9:	85 c0                	test   %eax,%eax
c00044cb:	74 15                	je     c00044e2 <page_dir_activate+0x2c>
    pagedir_phy_addr = addr_v2p((uint32_t)p_thread->pgdir);
c00044cd:	8b 45 08             	mov    0x8(%ebp),%eax
c00044d0:	8b 40 30             	mov    0x30(%eax),%eax
c00044d3:	83 ec 0c             	sub    $0xc,%esp
c00044d6:	50                   	push   %eax
c00044d7:	e8 fa e9 ff ff       	call   c0002ed6 <addr_v2p>
c00044dc:	83 c4 10             	add    $0x10,%esp
c00044df:	89 45 f4             	mov    %eax,-0xc(%ebp)
  }
  asm volatile("movl %0, %%cr3" ::"r"(pagedir_phy_addr) : "memory");
c00044e2:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00044e5:	0f 22 d8             	mov    %eax,%cr3
}
c00044e8:	90                   	nop
c00044e9:	c9                   	leave  
c00044ea:	c3                   	ret    

c00044eb <process_active>:

// 激活页表，并根据任务是否为进程来修改tss.esp0
void process_active(struct task_struct *p_thread) {
c00044eb:	55                   	push   %ebp
c00044ec:	89 e5                	mov    %esp,%ebp
c00044ee:	83 ec 08             	sub    $0x8,%esp
  ASSERT(p_thread != NULL);
c00044f1:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c00044f5:	75 19                	jne    c0004510 <process_active+0x25>
c00044f7:	68 dc 5b 00 c0       	push   $0xc0005bdc
c00044fc:	68 9c 5c 00 c0       	push   $0xc0005c9c
c0004501:	6a 44                	push   $0x44
c0004503:	68 ed 5b 00 c0       	push   $0xc0005bed
c0004508:	e8 63 dd ff ff       	call   c0002270 <panic_spin>
c000450d:	83 c4 10             	add    $0x10,%esp
  page_dir_activate(p_thread);
c0004510:	83 ec 0c             	sub    $0xc,%esp
c0004513:	ff 75 08             	push   0x8(%ebp)
c0004516:	e8 9b ff ff ff       	call   c00044b6 <page_dir_activate>
c000451b:	83 c4 10             	add    $0x10,%esp

  if (p_thread->pgdir) {
c000451e:	8b 45 08             	mov    0x8(%ebp),%eax
c0004521:	8b 40 30             	mov    0x30(%eax),%eax
c0004524:	85 c0                	test   %eax,%eax
c0004526:	74 0e                	je     c0004536 <process_active+0x4b>
    // 更新tss.esp0-> 进程的特权级0栈，用于此进程中断进入内核态下保留上下文
    update_tss_esp(p_thread);
c0004528:	83 ec 0c             	sub    $0xc,%esp
c000452b:	ff 75 08             	push   0x8(%ebp)
c000452e:	e8 09 fd ff ff       	call   c000423c <update_tss_esp>
c0004533:	83 c4 10             	add    $0x10,%esp
  }
}
c0004536:	90                   	nop
c0004537:	c9                   	leave  
c0004538:	c3                   	ret    

c0004539 <create_page_dir>:

// 创建页目录表，返回页目录虚拟地址
uint32_t *create_page_dir(void) {
c0004539:	55                   	push   %ebp
c000453a:	89 e5                	mov    %esp,%ebp
c000453c:	83 ec 18             	sub    $0x18,%esp
  uint32_t *page_dir_vaddr = get_kernel_pages(1); // 内核空间申请
c000453f:	83 ec 0c             	sub    $0xc,%esp
c0004542:	6a 01                	push   $0x1
c0004544:	e8 9c e7 ff ff       	call   c0002ce5 <get_kernel_pages>
c0004549:	83 c4 10             	add    $0x10,%esp
c000454c:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (page_dir_vaddr == NULL) {
c000454f:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
c0004553:	75 17                	jne    c000456c <create_page_dir+0x33>
    console_put_str("create_page_dir: get_kernel_page failed!");
c0004555:	83 ec 0c             	sub    $0xc,%esp
c0004558:	68 00 5c 00 c0       	push   $0xc0005c00
c000455d:	e8 9f f6 ff ff       	call   c0003c01 <console_put_str>
c0004562:	83 c4 10             	add    $0x10,%esp
    return NULL;
c0004565:	b8 00 00 00 00       	mov    $0x0,%eax
c000456a:	eb 43                	jmp    c00045af <create_page_dir+0x76>
  }

  // 为让所有进程共享内核：将内核所在页目录项（访问内核的入口）复制到进程页目录项目的同等位置
  // 1、复制页表（page_dir_vaddr + 0x300*4 ：内核页目录第768项
  memcpy((uint32_t *)((uint32_t)page_dir_vaddr + 0x300 * 4),
c000456c:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000456f:	05 00 0c 00 00       	add    $0xc00,%eax
c0004574:	83 ec 04             	sub    $0x4,%esp
c0004577:	68 00 04 00 00       	push   $0x400
c000457c:	68 00 fc ff ff       	push   $0xfffffc00
c0004581:	50                   	push   %eax
c0004582:	e8 12 de ff ff       	call   c0002399 <memcpy>
c0004587:	83 c4 10             	add    $0x10,%esp
         (uint32_t *)(0xfffff000 + 0x300 * 4), 1024);
  // 2、更新页目录地址
  uint32_t new_page_dir_phy_addr = addr_v2p((uint32_t)page_dir_vaddr);
c000458a:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000458d:	83 ec 0c             	sub    $0xc,%esp
c0004590:	50                   	push   %eax
c0004591:	e8 40 e9 ff ff       	call   c0002ed6 <addr_v2p>
c0004596:	83 c4 10             	add    $0x10,%esp
c0004599:	89 45 f0             	mov    %eax,-0x10(%ebp)
  page_dir_vaddr[1023] =
c000459c:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000459f:	05 fc 0f 00 00       	add    $0xffc,%eax
      new_page_dir_phy_addr | PG_US_U | PG_RW_W | PG_P_1; // 最后一项指向自己
c00045a4:	8b 55 f0             	mov    -0x10(%ebp),%edx
c00045a7:	83 ca 07             	or     $0x7,%edx
  page_dir_vaddr[1023] =
c00045aa:	89 10                	mov    %edx,(%eax)

  return page_dir_vaddr;
c00045ac:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c00045af:	c9                   	leave  
c00045b0:	c3                   	ret    

c00045b1 <create_user_vaddr_bitmap>:

// 创建用户进程的虚拟内存池（bitmap
void create_user_vaddr_bitmap(struct task_struct *user_prog) {
c00045b1:	55                   	push   %ebp
c00045b2:	89 e5                	mov    %esp,%ebp
c00045b4:	83 ec 18             	sub    $0x18,%esp
  user_prog->userprog_vaddr.vaddr_start = USER_VADDR_START;
c00045b7:	8b 45 08             	mov    0x8(%ebp),%eax
c00045ba:	c7 40 3c 00 80 04 08 	movl   $0x8048000,0x3c(%eax)
  uint32_t bitmap_pg_cnt =
c00045c1:	c7 45 f4 17 00 00 00 	movl   $0x17,-0xc(%ebp)
      DIV_ROUND_UP((0xc0000000 - USER_VADDR_START) / PG_SIZE / 8, PG_SIZE);
  user_prog->userprog_vaddr.vaddr_bitmap.bits = get_kernel_pages(bitmap_pg_cnt);
c00045c8:	83 ec 0c             	sub    $0xc,%esp
c00045cb:	ff 75 f4             	push   -0xc(%ebp)
c00045ce:	e8 12 e7 ff ff       	call   c0002ce5 <get_kernel_pages>
c00045d3:	83 c4 10             	add    $0x10,%esp
c00045d6:	8b 55 08             	mov    0x8(%ebp),%edx
c00045d9:	89 42 38             	mov    %eax,0x38(%edx)
  user_prog->userprog_vaddr.vaddr_bitmap.btmp_bytes_len =
c00045dc:	8b 45 08             	mov    0x8(%ebp),%eax
c00045df:	c7 40 34 f7 6f 01 00 	movl   $0x16ff7,0x34(%eax)
      (0xc0000000 - USER_VADDR_START) / PG_SIZE / 8;
  bitmap_init(&user_prog->userprog_vaddr.vaddr_bitmap);
c00045e6:	8b 45 08             	mov    0x8(%ebp),%eax
c00045e9:	83 c0 34             	add    $0x34,%eax
c00045ec:	83 ec 0c             	sub    $0xc,%esp
c00045ef:	50                   	push   %eax
c00045f0:	e8 1f e1 ff ff       	call   c0002714 <bitmap_init>
c00045f5:	83 c4 10             	add    $0x10,%esp
}
c00045f8:	90                   	nop
c00045f9:	c9                   	leave  
c00045fa:	c3                   	ret    

c00045fb <process_execute>:

// 创建用户进程
void process_execute(void *filename, char *name) { // filename：用户进程地址
c00045fb:	55                   	push   %ebp
c00045fc:	89 e5                	mov    %esp,%ebp
c00045fe:	83 ec 18             	sub    $0x18,%esp
  struct task_struct *thread = get_kernel_pages(1);
c0004601:	83 ec 0c             	sub    $0xc,%esp
c0004604:	6a 01                	push   $0x1
c0004606:	e8 da e6 ff ff       	call   c0002ce5 <get_kernel_pages>
c000460b:	83 c4 10             	add    $0x10,%esp
c000460e:	89 45 f4             	mov    %eax,-0xc(%ebp)
  init_thread(thread, name, default_prio);
c0004611:	83 ec 04             	sub    $0x4,%esp
c0004614:	6a 14                	push   $0x14
c0004616:	ff 75 0c             	push   0xc(%ebp)
c0004619:	ff 75 f4             	push   -0xc(%ebp)
c000461c:	e8 c9 eb ff ff       	call   c00031ea <init_thread>
c0004621:	83 c4 10             	add    $0x10,%esp
  create_user_vaddr_bitmap(thread);
c0004624:	83 ec 0c             	sub    $0xc,%esp
c0004627:	ff 75 f4             	push   -0xc(%ebp)
c000462a:	e8 82 ff ff ff       	call   c00045b1 <create_user_vaddr_bitmap>
c000462f:	83 c4 10             	add    $0x10,%esp
  thread_create(thread, start_process, filename);
c0004632:	83 ec 04             	sub    $0x4,%esp
c0004635:	ff 75 08             	push   0x8(%ebp)
c0004638:	68 c1 43 00 c0       	push   $0xc00043c1
c000463d:	ff 75 f4             	push   -0xc(%ebp)
c0004640:	e8 2e eb ff ff       	call   c0003173 <thread_create>
c0004645:	83 c4 10             	add    $0x10,%esp
  thread->pgdir = create_page_dir();
c0004648:	e8 ec fe ff ff       	call   c0004539 <create_page_dir>
c000464d:	8b 55 f4             	mov    -0xc(%ebp),%edx
c0004650:	89 42 30             	mov    %eax,0x30(%edx)

  enum intr_status old_status = intr_disable();
c0004653:	e8 35 d3 ff ff       	call   c000198d <intr_disable>
c0004658:	89 45 f0             	mov    %eax,-0x10(%ebp)
  ASSERT(!elem_find(&thread_ready_list, &thread->general_tag));
c000465b:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000465e:	83 c0 20             	add    $0x20,%eax
c0004661:	83 ec 08             	sub    $0x8,%esp
c0004664:	50                   	push   %eax
c0004665:	68 1c 85 00 c0       	push   $0xc000851c
c000466a:	e8 36 f1 ff ff       	call   c00037a5 <elem_find>
c000466f:	83 c4 10             	add    $0x10,%esp
c0004672:	85 c0                	test   %eax,%eax
c0004674:	74 19                	je     c000468f <process_execute+0x94>
c0004676:	68 2c 5c 00 c0       	push   $0xc0005c2c
c000467b:	68 ac 5c 00 c0       	push   $0xc0005cac
c0004680:	6a 75                	push   $0x75
c0004682:	68 ed 5b 00 c0       	push   $0xc0005bed
c0004687:	e8 e4 db ff ff       	call   c0002270 <panic_spin>
c000468c:	83 c4 10             	add    $0x10,%esp
  list_append(&thread_ready_list, &thread->general_tag);
c000468f:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0004692:	83 c0 20             	add    $0x20,%eax
c0004695:	83 ec 08             	sub    $0x8,%esp
c0004698:	50                   	push   %eax
c0004699:	68 1c 85 00 c0       	push   $0xc000851c
c000469e:	e8 88 f0 ff ff       	call   c000372b <list_append>
c00046a3:	83 c4 10             	add    $0x10,%esp

  ASSERT(!elem_find(&thread_ready_list, &thread->all_list_tag));
c00046a6:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00046a9:	83 c0 28             	add    $0x28,%eax
c00046ac:	83 ec 08             	sub    $0x8,%esp
c00046af:	50                   	push   %eax
c00046b0:	68 1c 85 00 c0       	push   $0xc000851c
c00046b5:	e8 eb f0 ff ff       	call   c00037a5 <elem_find>
c00046ba:	83 c4 10             	add    $0x10,%esp
c00046bd:	85 c0                	test   %eax,%eax
c00046bf:	74 19                	je     c00046da <process_execute+0xdf>
c00046c1:	68 64 5c 00 c0       	push   $0xc0005c64
c00046c6:	68 ac 5c 00 c0       	push   $0xc0005cac
c00046cb:	6a 78                	push   $0x78
c00046cd:	68 ed 5b 00 c0       	push   $0xc0005bed
c00046d2:	e8 99 db ff ff       	call   c0002270 <panic_spin>
c00046d7:	83 c4 10             	add    $0x10,%esp
  list_append(&thread_ready_list, &thread->all_list_tag);
c00046da:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00046dd:	83 c0 28             	add    $0x28,%eax
c00046e0:	83 ec 08             	sub    $0x8,%esp
c00046e3:	50                   	push   %eax
c00046e4:	68 1c 85 00 c0       	push   $0xc000851c
c00046e9:	e8 3d f0 ff ff       	call   c000372b <list_append>
c00046ee:	83 c4 10             	add    $0x10,%esp
  intr_set_status(old_status);
c00046f1:	83 ec 0c             	sub    $0xc,%esp
c00046f4:	ff 75 f0             	push   -0x10(%ebp)
c00046f7:	e8 d7 d2 ff ff       	call   c00019d3 <intr_set_status>
c00046fc:	83 c4 10             	add    $0x10,%esp
c00046ff:	90                   	nop
c0004700:	c9                   	leave  
c0004701:	c3                   	ret    
