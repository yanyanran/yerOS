
kernel.bin：     文件格式 elf32-i386


Disassembly of section .text:

c0001500 <main>:
void u_prog_a(void);
void u_prog_b(void);
int prog_a_pid = 0;
int prog_b_pid = 0;

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
c0001519:	e8 f2 05 00 00       	call   c0001b10 <put_str>
c000151e:	83 c4 10             	add    $0x10,%esp
  init_all();
c0001521:	e8 39 01 00 00       	call   c000165f <init_all>

  process_execute(u_prog_a, "user_prog_a");
c0001526:	83 ec 08             	sub    $0x8,%esp
c0001529:	68 0d 50 00 c0       	push   $0xc000500d
c000152e:	68 23 16 00 c0       	push   $0xc0001623
c0001533:	e8 db 31 00 00       	call   c0004713 <process_execute>
c0001538:	83 c4 10             	add    $0x10,%esp
  process_execute(u_prog_b, "user_prog_b");
c000153b:	83 ec 08             	sub    $0x8,%esp
c000153e:	68 19 50 00 c0       	push   $0xc0005019
c0001543:	68 41 16 00 c0       	push   $0xc0001641
c0001548:	e8 c6 31 00 00       	call   c0004713 <process_execute>
c000154d:	83 c4 10             	add    $0x10,%esp

  intr_enable(); // 开中断
c0001550:	e8 9f 04 00 00       	call   c00019f4 <intr_enable>
  console_put_str("main_pid:0x");
c0001555:	83 ec 0c             	sub    $0xc,%esp
c0001558:	68 25 50 00 c0       	push   $0xc0005025
c000155d:	e8 bf 27 00 00       	call   c0003d21 <console_put_str>
c0001562:	83 c4 10             	add    $0x10,%esp
  console_put_int(sys_getpid());
c0001565:	e8 e3 32 00 00       	call   c000484d <sys_getpid>
c000156a:	83 ec 0c             	sub    $0xc,%esp
c000156d:	50                   	push   %eax
c000156e:	e8 f8 27 00 00       	call   c0003d6b <console_put_int>
c0001573:	83 c4 10             	add    $0x10,%esp
  console_put_char('\n');
c0001576:	83 ec 0c             	sub    $0xc,%esp
c0001579:	6a 0a                	push   $0xa
c000157b:	e8 c2 27 00 00       	call   c0003d42 <console_put_char>
c0001580:	83 c4 10             	add    $0x10,%esp

  thread_start("k_thread_a", 31, k_thread_a, "argA ");
c0001583:	68 31 50 00 c0       	push   $0xc0005031
c0001588:	68 b7 15 00 c0       	push   $0xc00015b7
c000158d:	6a 1f                	push   $0x1f
c000158f:	68 37 50 00 c0       	push   $0xc0005037
c0001594:	e8 f3 1d 00 00       	call   c000338c <thread_start>
c0001599:	83 c4 10             	add    $0x10,%esp
  thread_start("k_thread_b", 31, k_thread_b, "argB ");
c000159c:	68 42 50 00 c0       	push   $0xc0005042
c00015a1:	68 ed 15 00 c0       	push   $0xc00015ed
c00015a6:	6a 1f                	push   $0x1f
c00015a8:	68 48 50 00 c0       	push   $0xc0005048
c00015ad:	e8 da 1d 00 00       	call   c000338c <thread_start>
c00015b2:	83 c4 10             	add    $0x10,%esp

  while (1) {
c00015b5:	eb fe                	jmp    c00015b5 <main+0xb5>

c00015b7 <k_thread_a>:
  };
  return 0;
}

// 线程中运行的函数
void k_thread_a(void *arg) {
c00015b7:	55                   	push   %ebp
c00015b8:	89 e5                	mov    %esp,%ebp
c00015ba:	83 ec 08             	sub    $0x8,%esp
  //char *para = arg;
  console_put_str(" thread_a_pid:0x");
c00015bd:	83 ec 0c             	sub    $0xc,%esp
c00015c0:	68 53 50 00 c0       	push   $0xc0005053
c00015c5:	e8 57 27 00 00       	call   c0003d21 <console_put_str>
c00015ca:	83 c4 10             	add    $0x10,%esp
  console_put_int(sys_getpid());
c00015cd:	e8 7b 32 00 00       	call   c000484d <sys_getpid>
c00015d2:	83 ec 0c             	sub    $0xc,%esp
c00015d5:	50                   	push   %eax
c00015d6:	e8 90 27 00 00       	call   c0003d6b <console_put_int>
c00015db:	83 c4 10             	add    $0x10,%esp
  console_put_char('\n');
c00015de:	83 ec 0c             	sub    $0xc,%esp
c00015e1:	6a 0a                	push   $0xa
c00015e3:	e8 5a 27 00 00       	call   c0003d42 <console_put_char>
c00015e8:	83 c4 10             	add    $0x10,%esp
  while (1)
c00015eb:	eb fe                	jmp    c00015eb <k_thread_a+0x34>

c00015ed <k_thread_b>:
    ;
}

void k_thread_b(void *arg) {
c00015ed:	55                   	push   %ebp
c00015ee:	89 e5                	mov    %esp,%ebp
c00015f0:	83 ec 08             	sub    $0x8,%esp
  //char *para = arg;
  console_put_str(" thread_b_pid:0x");
c00015f3:	83 ec 0c             	sub    $0xc,%esp
c00015f6:	68 64 50 00 c0       	push   $0xc0005064
c00015fb:	e8 21 27 00 00       	call   c0003d21 <console_put_str>
c0001600:	83 c4 10             	add    $0x10,%esp
  console_put_int(sys_getpid());
c0001603:	e8 45 32 00 00       	call   c000484d <sys_getpid>
c0001608:	83 ec 0c             	sub    $0xc,%esp
c000160b:	50                   	push   %eax
c000160c:	e8 5a 27 00 00       	call   c0003d6b <console_put_int>
c0001611:	83 c4 10             	add    $0x10,%esp
  console_put_char('\n');
c0001614:	83 ec 0c             	sub    $0xc,%esp
c0001617:	6a 0a                	push   $0xa
c0001619:	e8 24 27 00 00       	call   c0003d42 <console_put_char>
c000161e:	83 c4 10             	add    $0x10,%esp
  while (1)
c0001621:	eb fe                	jmp    c0001621 <k_thread_b+0x34>

c0001623 <u_prog_a>:
    ;
}

void u_prog_a(void) {
c0001623:	55                   	push   %ebp
c0001624:	89 e5                	mov    %esp,%ebp
c0001626:	83 ec 08             	sub    $0x8,%esp
  printf(" prog_a_pid:0x%x\n", getpid());
c0001629:	e8 ec 31 00 00       	call   c000481a <getpid>
c000162e:	83 ec 08             	sub    $0x8,%esp
c0001631:	50                   	push   %eax
c0001632:	68 75 50 00 c0       	push   $0xc0005075
c0001637:	e8 a7 33 00 00       	call   c00049e3 <printf>
c000163c:	83 c4 10             	add    $0x10,%esp
  while (1)
c000163f:	eb fe                	jmp    c000163f <u_prog_a+0x1c>

c0001641 <u_prog_b>:
    ;
}

void u_prog_b(void) {
c0001641:	55                   	push   %ebp
c0001642:	89 e5                	mov    %esp,%ebp
c0001644:	83 ec 08             	sub    $0x8,%esp
  printf(" prog_b_pid:0x%x\n", getpid());
c0001647:	e8 ce 31 00 00       	call   c000481a <getpid>
c000164c:	83 ec 08             	sub    $0x8,%esp
c000164f:	50                   	push   %eax
c0001650:	68 87 50 00 c0       	push   $0xc0005087
c0001655:	e8 89 33 00 00       	call   c00049e3 <printf>
c000165a:	83 c4 10             	add    $0x10,%esp
  while (1)
c000165d:	eb fe                	jmp    c000165d <u_prog_b+0x1c>

c000165f <init_all>:
#include "thread.h"
#include "timer.h"
#include "tss.h"

// 负责初始化所有模块
void init_all() {
c000165f:	55                   	push   %ebp
c0001660:	89 e5                	mov    %esp,%ebp
c0001662:	83 ec 08             	sub    $0x8,%esp
  put_str("init_all\n");
c0001665:	83 ec 0c             	sub    $0xc,%esp
c0001668:	68 99 50 00 c0       	push   $0xc0005099
c000166d:	e8 9e 04 00 00       	call   c0001b10 <put_str>
c0001672:	83 c4 10             	add    $0x10,%esp
  idt_init();      // 初始化中断
c0001675:	e8 24 04 00 00       	call   c0001a9e <idt_init>
  timer_init();    // 初始化PIT
c000167a:	e8 62 0c 00 00       	call   c00022e1 <timer_init>
  mem_init();      // 初始化内存池
c000167f:	e8 41 1b 00 00       	call   c00031c5 <mem_init>
  thread_init();   // 初始化线程环境
c0001684:	e8 75 1f 00 00       	call   c00035fe <thread_init>
  console_init();  // 初始化终端
c0001689:	e8 48 26 00 00       	call   c0003cd6 <console_init>
  keyboard_init(); // 初始化键盘
c000168e:	e8 96 29 00 00       	call   c0004029 <keyboard_init>
  tss_init();      // 初始化任务状态表
c0001693:	e8 37 2d 00 00       	call   c00043cf <tss_init>
  syscall_init();  // 初始化系统调用
c0001698:	e8 e6 31 00 00       	call   c0004883 <syscall_init>
c000169d:	90                   	nop
c000169e:	c9                   	leave  
c000169f:	c3                   	ret    

c00016a0 <outb>:
#ifndef __LIB_IO_H
#define __LIB_IO_H
#include "stdint.h"

// 向端口写入1字节
static inline void outb(uint16_t port, uint8_t data) {
c00016a0:	55                   	push   %ebp
c00016a1:	89 e5                	mov    %esp,%ebp
c00016a3:	83 ec 08             	sub    $0x8,%esp
c00016a6:	8b 45 08             	mov    0x8(%ebp),%eax
c00016a9:	8b 55 0c             	mov    0xc(%ebp),%edx
c00016ac:	66 89 45 fc          	mov    %ax,-0x4(%ebp)
c00016b0:	89 d0                	mov    %edx,%eax
c00016b2:	88 45 f8             	mov    %al,-0x8(%ebp)
  asm volatile("outb %b0, %w1" ::"a"(data), "Nd"(port));
c00016b5:	0f b6 45 f8          	movzbl -0x8(%ebp),%eax
c00016b9:	0f b7 55 fc          	movzwl -0x4(%ebp),%edx
c00016bd:	ee                   	out    %al,(%dx)
}
c00016be:	90                   	nop
c00016bf:	c9                   	leave  
c00016c0:	c3                   	ret    

c00016c1 <pic_init>:
char *intr_name[IDT_DESC_CNT];             // 中断异常名数组
extern intr_handler intr_entry_table[IDT_DESC_CNT]; // 中断入口数组(asm)
intr_handler idt_table[IDT_DESC_CNT]; // 最终中断处理程序数组(c)

// 初始化8259A
static void pic_init() {
c00016c1:	55                   	push   %ebp
c00016c2:	89 e5                	mov    %esp,%ebp
c00016c4:	83 ec 08             	sub    $0x8,%esp
  // 初始化主片
  outb(PIC_M_CTRL, 0x11); // ICW1: 边沿触发,级联8259, 需要ICW4
c00016c7:	6a 11                	push   $0x11
c00016c9:	6a 20                	push   $0x20
c00016cb:	e8 d0 ff ff ff       	call   c00016a0 <outb>
c00016d0:	83 c4 08             	add    $0x8,%esp
  outb(PIC_M_DATA, 0x20); // ICW2: 起始中断向量号0x20,也就是IR[0-7]为0x20～0x27
c00016d3:	6a 20                	push   $0x20
c00016d5:	6a 21                	push   $0x21
c00016d7:	e8 c4 ff ff ff       	call   c00016a0 <outb>
c00016dc:	83 c4 08             	add    $0x8,%esp
  outb(PIC_M_DATA, 0x04); // ICW3: IR2接从片
c00016df:	6a 04                	push   $0x4
c00016e1:	6a 21                	push   $0x21
c00016e3:	e8 b8 ff ff ff       	call   c00016a0 <outb>
c00016e8:	83 c4 08             	add    $0x8,%esp
  outb(PIC_M_DATA, 0x01); // ICW4: 8086模式正常EOI
c00016eb:	6a 01                	push   $0x1
c00016ed:	6a 21                	push   $0x21
c00016ef:	e8 ac ff ff ff       	call   c00016a0 <outb>
c00016f4:	83 c4 08             	add    $0x8,%esp

  // 初始化从片
  outb(PIC_S_CTRL, 0x11);
c00016f7:	6a 11                	push   $0x11
c00016f9:	68 a0 00 00 00       	push   $0xa0
c00016fe:	e8 9d ff ff ff       	call   c00016a0 <outb>
c0001703:	83 c4 08             	add    $0x8,%esp
  outb(PIC_S_DATA, 0x28); // ICW2: 起始中断向量号0x28,也就是IR[8-15]为0x28～0x2F
c0001706:	6a 28                	push   $0x28
c0001708:	68 a1 00 00 00       	push   $0xa1
c000170d:	e8 8e ff ff ff       	call   c00016a0 <outb>
c0001712:	83 c4 08             	add    $0x8,%esp
  outb(PIC_S_DATA, 0x02); // ICW3: 设置从片连接到主片的IR2引脚
c0001715:	6a 02                	push   $0x2
c0001717:	68 a1 00 00 00       	push   $0xa1
c000171c:	e8 7f ff ff ff       	call   c00016a0 <outb>
c0001721:	83 c4 08             	add    $0x8,%esp
  outb(PIC_S_DATA, 0x01);
c0001724:	6a 01                	push   $0x1
c0001726:	68 a1 00 00 00       	push   $0xa1
c000172b:	e8 70 ff ff ff       	call   c00016a0 <outb>
c0001730:	83 c4 08             	add    $0x8,%esp

  // 打开键盘、时钟中断
  outb(PIC_M_DATA, 0xfc);
c0001733:	68 fc 00 00 00       	push   $0xfc
c0001738:	6a 21                	push   $0x21
c000173a:	e8 61 ff ff ff       	call   c00016a0 <outb>
c000173f:	83 c4 08             	add    $0x8,%esp
  outb(PIC_S_DATA, 0xff);
c0001742:	68 ff 00 00 00       	push   $0xff
c0001747:	68 a1 00 00 00       	push   $0xa1
c000174c:	e8 4f ff ff ff       	call   c00016a0 <outb>
c0001751:	83 c4 08             	add    $0x8,%esp

  put_str("   pic_init done\n");
c0001754:	83 ec 0c             	sub    $0xc,%esp
c0001757:	68 a4 50 00 c0       	push   $0xc00050a4
c000175c:	e8 af 03 00 00       	call   c0001b10 <put_str>
c0001761:	83 c4 10             	add    $0x10,%esp
}
c0001764:	90                   	nop
c0001765:	c9                   	leave  
c0001766:	c3                   	ret    

c0001767 <make_idt_desc>:

// 创建中断门描述符
static void make_idt_desc(struct gate_desc *p_gdesc, uint8_t attr,
                          intr_handler function) {
c0001767:	55                   	push   %ebp
c0001768:	89 e5                	mov    %esp,%ebp
c000176a:	83 ec 04             	sub    $0x4,%esp
c000176d:	8b 45 0c             	mov    0xc(%ebp),%eax
c0001770:	88 45 fc             	mov    %al,-0x4(%ebp)
  p_gdesc->func_offset_low_word = (uint32_t)function & 0x0000FFFF;
c0001773:	8b 45 10             	mov    0x10(%ebp),%eax
c0001776:	89 c2                	mov    %eax,%edx
c0001778:	8b 45 08             	mov    0x8(%ebp),%eax
c000177b:	66 89 10             	mov    %dx,(%eax)
  p_gdesc->selector = SELECTOR_K_CODE;
c000177e:	8b 45 08             	mov    0x8(%ebp),%eax
c0001781:	66 c7 40 02 08 00    	movw   $0x8,0x2(%eax)
  p_gdesc->dcount = 0;
c0001787:	8b 45 08             	mov    0x8(%ebp),%eax
c000178a:	c6 40 04 00          	movb   $0x0,0x4(%eax)
  p_gdesc->attribute = attr;
c000178e:	8b 45 08             	mov    0x8(%ebp),%eax
c0001791:	0f b6 55 fc          	movzbl -0x4(%ebp),%edx
c0001795:	88 50 05             	mov    %dl,0x5(%eax)
  p_gdesc->func_offset_high_word = ((uint32_t)function & 0xFFFF0000) >> 16;
c0001798:	8b 45 10             	mov    0x10(%ebp),%eax
c000179b:	c1 e8 10             	shr    $0x10,%eax
c000179e:	89 c2                	mov    %eax,%edx
c00017a0:	8b 45 08             	mov    0x8(%ebp),%eax
c00017a3:	66 89 50 06          	mov    %dx,0x6(%eax)
}
c00017a7:	90                   	nop
c00017a8:	c9                   	leave  
c00017a9:	c3                   	ret    

c00017aa <idt_desc_init>:

// 初始化填充IDT
static void idt_desc_init(void) {
c00017aa:	55                   	push   %ebp
c00017ab:	89 e5                	mov    %esp,%ebp
c00017ad:	83 ec 18             	sub    $0x18,%esp
  int i;
  int lastindex = IDT_DESC_CNT - 1;
c00017b0:	c7 45 f0 80 00 00 00 	movl   $0x80,-0x10(%ebp)
  for (i = 0; i < IDT_DESC_CNT; i++) {
c00017b7:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
c00017be:	eb 29                	jmp    c00017e9 <idt_desc_init+0x3f>
    make_idt_desc(&idt[i], IDT_DESC_ATTR_DPL0, intr_entry_table[i]);
c00017c0:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00017c3:	8b 04 85 08 80 00 c0 	mov    -0x3fff7ff8(,%eax,4),%eax
c00017ca:	8b 55 f4             	mov    -0xc(%ebp),%edx
c00017cd:	c1 e2 03             	shl    $0x3,%edx
c00017d0:	81 c2 c0 85 00 c0    	add    $0xc00085c0,%edx
c00017d6:	50                   	push   %eax
c00017d7:	68 8e 00 00 00       	push   $0x8e
c00017dc:	52                   	push   %edx
c00017dd:	e8 85 ff ff ff       	call   c0001767 <make_idt_desc>
c00017e2:	83 c4 0c             	add    $0xc,%esp
  for (i = 0; i < IDT_DESC_CNT; i++) {
c00017e5:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
c00017e9:	81 7d f4 80 00 00 00 	cmpl   $0x80,-0xc(%ebp)
c00017f0:	7e ce                	jle    c00017c0 <idt_desc_init+0x16>
  }
  /* 系统调用单独处理，对应中断门dpl为3，中断处理程序为syscall_handler */
  make_idt_desc(&idt[lastindex], IDT_DESC_ATTR_DPL3, syscall_handler);
c00017f2:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00017f5:	c1 e0 03             	shl    $0x3,%eax
c00017f8:	05 c0 85 00 c0       	add    $0xc00085c0,%eax
c00017fd:	68 9a 21 00 c0       	push   $0xc000219a
c0001802:	68 ee 00 00 00       	push   $0xee
c0001807:	50                   	push   %eax
c0001808:	e8 5a ff ff ff       	call   c0001767 <make_idt_desc>
c000180d:	83 c4 0c             	add    $0xc,%esp
  put_str("   idt_desc_init done\n");
c0001810:	83 ec 0c             	sub    $0xc,%esp
c0001813:	68 b6 50 00 c0       	push   $0xc00050b6
c0001818:	e8 f3 02 00 00       	call   c0001b10 <put_str>
c000181d:	83 c4 10             	add    $0x10,%esp
}
c0001820:	90                   	nop
c0001821:	c9                   	leave  
c0001822:	c3                   	ret    

c0001823 <general_intr_handler>:

// 通用中断处理函数（异常处理）
static void general_intr_handler(uint8_t vec_nr) {
c0001823:	55                   	push   %ebp
c0001824:	89 e5                	mov    %esp,%ebp
c0001826:	83 ec 28             	sub    $0x28,%esp
c0001829:	8b 45 08             	mov    0x8(%ebp),%eax
c000182c:	88 45 e4             	mov    %al,-0x1c(%ebp)
  // 伪中断无需处理，0x2f是从片8259A上最后一个IRQ引脚，作保留项
  if (vec_nr == 0x27 || vec_nr == 0x2f) {
c000182f:	80 7d e4 27          	cmpb   $0x27,-0x1c(%ebp)
c0001833:	0f 84 bf 00 00 00    	je     c00018f8 <general_intr_handler+0xd5>
c0001839:	80 7d e4 2f          	cmpb   $0x2f,-0x1c(%ebp)
c000183d:	0f 84 b5 00 00 00    	je     c00018f8 <general_intr_handler+0xd5>
    return;
  }
  set_cursor(0); // 光标置0
c0001843:	83 ec 0c             	sub    $0xc,%esp
c0001846:	6a 00                	push   $0x0
c0001848:	e8 91 03 00 00       	call   c0001bde <set_cursor>
c000184d:	83 c4 10             	add    $0x10,%esp
  int cursor_pos = 0;
c0001850:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  while (cursor_pos < 320) { // 4行空格
c0001857:	eb 11                	jmp    c000186a <general_intr_handler+0x47>
    put_char(' ');
c0001859:	83 ec 0c             	sub    $0xc,%esp
c000185c:	6a 20                	push   $0x20
c000185e:	e8 cb 02 00 00       	call   c0001b2e <put_char>
c0001863:	83 c4 10             	add    $0x10,%esp
    cursor_pos++;
c0001866:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
  while (cursor_pos < 320) { // 4行空格
c000186a:	81 7d f4 3f 01 00 00 	cmpl   $0x13f,-0xc(%ebp)
c0001871:	7e e6                	jle    c0001859 <general_intr_handler+0x36>
  }

  set_cursor(0);
c0001873:	83 ec 0c             	sub    $0xc,%esp
c0001876:	6a 00                	push   $0x0
c0001878:	e8 61 03 00 00       	call   c0001bde <set_cursor>
c000187d:	83 c4 10             	add    $0x10,%esp
  put_str("!!!       excetion messge begin          !!!\n");
c0001880:	83 ec 0c             	sub    $0xc,%esp
c0001883:	68 d0 50 00 c0       	push   $0xc00050d0
c0001888:	e8 83 02 00 00       	call   c0001b10 <put_str>
c000188d:	83 c4 10             	add    $0x10,%esp
  set_cursor(88); // 第2行第8个地方开始打印
c0001890:	83 ec 0c             	sub    $0xc,%esp
c0001893:	6a 58                	push   $0x58
c0001895:	e8 44 03 00 00       	call   c0001bde <set_cursor>
c000189a:	83 c4 10             	add    $0x10,%esp
  put_str(intr_name[vec_nr]);
c000189d:	0f b6 45 e4          	movzbl -0x1c(%ebp),%eax
c00018a1:	8b 04 85 80 81 00 c0 	mov    -0x3fff7e80(,%eax,4),%eax
c00018a8:	83 ec 0c             	sub    $0xc,%esp
c00018ab:	50                   	push   %eax
c00018ac:	e8 5f 02 00 00       	call   c0001b10 <put_str>
c00018b1:	83 c4 10             	add    $0x10,%esp
  if (vec_nr == 14) { // pagefault缺页异常，将缺失地址打印出来并悬停
c00018b4:	80 7d e4 0e          	cmpb   $0xe,-0x1c(%ebp)
c00018b8:	75 2c                	jne    c00018e6 <general_intr_handler+0xc3>
    int page_fault_vaddr = 0;
c00018ba:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
    asm("movl %%cr2, %0" : "=r"(page_fault_vaddr)); // cr2存放造成pagefault地址
c00018c1:	0f 20 d0             	mov    %cr2,%eax
c00018c4:	89 45 f0             	mov    %eax,-0x10(%ebp)

    put_str("\npage fault addr is ");
c00018c7:	83 ec 0c             	sub    $0xc,%esp
c00018ca:	68 fe 50 00 c0       	push   $0xc00050fe
c00018cf:	e8 3c 02 00 00       	call   c0001b10 <put_str>
c00018d4:	83 c4 10             	add    $0x10,%esp
    put_int(page_fault_vaddr);
c00018d7:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00018da:	83 ec 0c             	sub    $0xc,%esp
c00018dd:	50                   	push   %eax
c00018de:	e8 19 03 00 00       	call   c0001bfc <put_int>
c00018e3:	83 c4 10             	add    $0x10,%esp
  }

  put_str("\n!!!       excetion messge end          !!!\n");
c00018e6:	83 ec 0c             	sub    $0xc,%esp
c00018e9:	68 14 51 00 c0       	push   $0xc0005114
c00018ee:	e8 1d 02 00 00       	call   c0001b10 <put_str>
c00018f3:	83 c4 10             	add    $0x10,%esp
  while (1)
c00018f6:	eb fe                	jmp    c00018f6 <general_intr_handler+0xd3>
    return;
c00018f8:	90                   	nop
    ; // 到这不再会被中断
}
c00018f9:	c9                   	leave  
c00018fa:	c3                   	ret    

c00018fb <exception_init>:

// 完成一般中断处理函数的注册、异常名的注册
static void exception_init(void) {
c00018fb:	55                   	push   %ebp
c00018fc:	89 e5                	mov    %esp,%ebp
c00018fe:	83 ec 10             	sub    $0x10,%esp
  int i;
  // idt_table中的函数在进入中断后根据中断向量号调用
  for (i = 0; i < IDT_DESC_CNT; i++) {
c0001901:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%ebp)
c0001908:	eb 20                	jmp    c000192a <exception_init+0x2f>
    idt_table[i] = general_intr_handler; // 默认，以后注册具体处理函数
c000190a:	8b 45 fc             	mov    -0x4(%ebp),%eax
c000190d:	c7 04 85 a0 83 00 c0 	movl   $0xc0001823,-0x3fff7c60(,%eax,4)
c0001914:	23 18 00 c0 
    intr_name[i] = "unknown";
c0001918:	8b 45 fc             	mov    -0x4(%ebp),%eax
c000191b:	c7 04 85 80 81 00 c0 	movl   $0xc0005141,-0x3fff7e80(,%eax,4)
c0001922:	41 51 00 c0 
  for (i = 0; i < IDT_DESC_CNT; i++) {
c0001926:	83 45 fc 01          	addl   $0x1,-0x4(%ebp)
c000192a:	81 7d fc 80 00 00 00 	cmpl   $0x80,-0x4(%ebp)
c0001931:	7e d7                	jle    c000190a <exception_init+0xf>
  }

  // 20个异常（0x00-0x13）
  intr_name[0] = "#DE Divide Error";
c0001933:	c7 05 80 81 00 c0 49 	movl   $0xc0005149,0xc0008180
c000193a:	51 00 c0 
  intr_name[1] = "#DB Debug Exception";
c000193d:	c7 05 84 81 00 c0 5a 	movl   $0xc000515a,0xc0008184
c0001944:	51 00 c0 
  intr_name[2] = "NMI Interrupt";
c0001947:	c7 05 88 81 00 c0 6e 	movl   $0xc000516e,0xc0008188
c000194e:	51 00 c0 
  intr_name[3] = "#BP Breakpoint Exception";
c0001951:	c7 05 8c 81 00 c0 7c 	movl   $0xc000517c,0xc000818c
c0001958:	51 00 c0 
  intr_name[4] = "#OF Overflow Exception";
c000195b:	c7 05 90 81 00 c0 95 	movl   $0xc0005195,0xc0008190
c0001962:	51 00 c0 
  intr_name[5] = "#BR BOUND Range Exceeded Exception";
c0001965:	c7 05 94 81 00 c0 ac 	movl   $0xc00051ac,0xc0008194
c000196c:	51 00 c0 
  intr_name[6] = "#UD Invalid Opcode Exception";
c000196f:	c7 05 98 81 00 c0 cf 	movl   $0xc00051cf,0xc0008198
c0001976:	51 00 c0 
  intr_name[7] = "#NM Device Not Available Exception";
c0001979:	c7 05 9c 81 00 c0 ec 	movl   $0xc00051ec,0xc000819c
c0001980:	51 00 c0 
  intr_name[8] = "#DF Double Fault Exception";
c0001983:	c7 05 a0 81 00 c0 0f 	movl   $0xc000520f,0xc00081a0
c000198a:	52 00 c0 
  intr_name[9] = "Coprocessor Segment Overrun";
c000198d:	c7 05 a4 81 00 c0 2a 	movl   $0xc000522a,0xc00081a4
c0001994:	52 00 c0 
  intr_name[10] = "#TS Invalid TSS Exception";
c0001997:	c7 05 a8 81 00 c0 46 	movl   $0xc0005246,0xc00081a8
c000199e:	52 00 c0 
  intr_name[11] = "#NP Segment Not Present";
c00019a1:	c7 05 ac 81 00 c0 60 	movl   $0xc0005260,0xc00081ac
c00019a8:	52 00 c0 
  intr_name[12] = "#SS Stack Fault Exception";
c00019ab:	c7 05 b0 81 00 c0 78 	movl   $0xc0005278,0xc00081b0
c00019b2:	52 00 c0 
  intr_name[13] = "#GP General Protection Exception";
c00019b5:	c7 05 b4 81 00 c0 94 	movl   $0xc0005294,0xc00081b4
c00019bc:	52 00 c0 
  intr_name[14] = "#PF Page-Fault Exception";
c00019bf:	c7 05 b8 81 00 c0 b5 	movl   $0xc00052b5,0xc00081b8
c00019c6:	52 00 c0 
  // intr_name[15] 第15项是intel保留项，未使用
  intr_name[16] = "#MF x87 FPU Floating-Point Error";
c00019c9:	c7 05 c0 81 00 c0 d0 	movl   $0xc00052d0,0xc00081c0
c00019d0:	52 00 c0 
  intr_name[17] = "#AC Alignment Check Exception";
c00019d3:	c7 05 c4 81 00 c0 f1 	movl   $0xc00052f1,0xc00081c4
c00019da:	52 00 c0 
  intr_name[18] = "#MC Machine-Check Exception";
c00019dd:	c7 05 c8 81 00 c0 0f 	movl   $0xc000530f,0xc00081c8
c00019e4:	53 00 c0 
  intr_name[19] = "#XF SIMD Floating-Point Exception";
c00019e7:	c7 05 cc 81 00 c0 2c 	movl   $0xc000532c,0xc00081cc
c00019ee:	53 00 c0 
}
c00019f1:	90                   	nop
c00019f2:	c9                   	leave  
c00019f3:	c3                   	ret    

c00019f4 <intr_enable>:

// 开中断，并返回开中断前的状态
enum intr_status intr_enable() {
c00019f4:	55                   	push   %ebp
c00019f5:	89 e5                	mov    %esp,%ebp
c00019f7:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status;
  if (INTR_ON == intr_get_status()) {
c00019fa:	e8 82 00 00 00       	call   c0001a81 <intr_get_status>
c00019ff:	83 f8 01             	cmp    $0x1,%eax
c0001a02:	75 0c                	jne    c0001a10 <intr_enable+0x1c>
    old_status = INTR_ON;
c0001a04:	c7 45 f4 01 00 00 00 	movl   $0x1,-0xc(%ebp)
    return old_status;
c0001a0b:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0001a0e:	eb 0b                	jmp    c0001a1b <intr_enable+0x27>
  } else {
    old_status = INTR_OFF;
c0001a10:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
    asm volatile("sti"); // 开中断，sti指令将IF位置1
c0001a17:	fb                   	sti    
    return old_status;
c0001a18:	8b 45 f4             	mov    -0xc(%ebp),%eax
  }
}
c0001a1b:	c9                   	leave  
c0001a1c:	c3                   	ret    

c0001a1d <intr_disable>:

// 关中断，并返回关中断前的状态
enum intr_status intr_disable() {
c0001a1d:	55                   	push   %ebp
c0001a1e:	89 e5                	mov    %esp,%ebp
c0001a20:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status;
  if (INTR_ON == intr_get_status()) {
c0001a23:	e8 59 00 00 00       	call   c0001a81 <intr_get_status>
c0001a28:	83 f8 01             	cmp    $0x1,%eax
c0001a2b:	75 0d                	jne    c0001a3a <intr_disable+0x1d>
    old_status = INTR_ON;
c0001a2d:	c7 45 f4 01 00 00 00 	movl   $0x1,-0xc(%ebp)
    asm volatile("cli" ::: "memory"); // 关中断，cli指令将IF位置0
c0001a34:	fa                   	cli    
    return old_status;
c0001a35:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0001a38:	eb 0a                	jmp    c0001a44 <intr_disable+0x27>
  } else {
    old_status = INTR_OFF;
c0001a3a:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
    return old_status;
c0001a41:	8b 45 f4             	mov    -0xc(%ebp),%eax
  }
}
c0001a44:	c9                   	leave  
c0001a45:	c3                   	ret    

c0001a46 <register_handler>:

// 注册中断处理函数
void register_handler(uint8_t vector_no, intr_handler func) {
c0001a46:	55                   	push   %ebp
c0001a47:	89 e5                	mov    %esp,%ebp
c0001a49:	83 ec 04             	sub    $0x4,%esp
c0001a4c:	8b 45 08             	mov    0x8(%ebp),%eax
c0001a4f:	88 45 fc             	mov    %al,-0x4(%ebp)
  idt_table[vector_no] = func;
c0001a52:	0f b6 45 fc          	movzbl -0x4(%ebp),%eax
c0001a56:	8b 55 0c             	mov    0xc(%ebp),%edx
c0001a59:	89 14 85 a0 83 00 c0 	mov    %edx,-0x3fff7c60(,%eax,4)
}
c0001a60:	90                   	nop
c0001a61:	c9                   	leave  
c0001a62:	c3                   	ret    

c0001a63 <intr_set_status>:

// 将中断状态设置为status
enum intr_status intr_set_status(enum intr_status status) {
c0001a63:	55                   	push   %ebp
c0001a64:	89 e5                	mov    %esp,%ebp
c0001a66:	83 ec 08             	sub    $0x8,%esp
  return status & INTR_ON ? intr_enable() : intr_disable();
c0001a69:	8b 45 08             	mov    0x8(%ebp),%eax
c0001a6c:	83 e0 01             	and    $0x1,%eax
c0001a6f:	85 c0                	test   %eax,%eax
c0001a71:	74 07                	je     c0001a7a <intr_set_status+0x17>
c0001a73:	e8 7c ff ff ff       	call   c00019f4 <intr_enable>
c0001a78:	eb 05                	jmp    c0001a7f <intr_set_status+0x1c>
c0001a7a:	e8 9e ff ff ff       	call   c0001a1d <intr_disable>
}
c0001a7f:	c9                   	leave  
c0001a80:	c3                   	ret    

c0001a81 <intr_get_status>:

// 获取当前中断状态
enum intr_status intr_get_status() {
c0001a81:	55                   	push   %ebp
c0001a82:	89 e5                	mov    %esp,%ebp
c0001a84:	83 ec 10             	sub    $0x10,%esp
  uint32_t eflags = 0;
c0001a87:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%ebp)
  GET_EFLAGS(eflags);
c0001a8e:	9c                   	pushf  
c0001a8f:	58                   	pop    %eax
c0001a90:	89 45 fc             	mov    %eax,-0x4(%ebp)
  return (EFLAGS_IF & eflags) ? INTR_ON : INTR_OFF; // 判断eflags中的IF位
c0001a93:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0001a96:	c1 e8 09             	shr    $0x9,%eax
c0001a99:	83 e0 01             	and    $0x1,%eax
}
c0001a9c:	c9                   	leave  
c0001a9d:	c3                   	ret    

c0001a9e <idt_init>:

// 完成有关中断的所有初始化工作
void idt_init() {
c0001a9e:	55                   	push   %ebp
c0001a9f:	89 e5                	mov    %esp,%ebp
c0001aa1:	57                   	push   %edi
c0001aa2:	56                   	push   %esi
c0001aa3:	83 ec 10             	sub    $0x10,%esp
  put_str("idt_init start\n");
c0001aa6:	83 ec 0c             	sub    $0xc,%esp
c0001aa9:	68 4e 53 00 c0       	push   $0xc000534e
c0001aae:	e8 5d 00 00 00       	call   c0001b10 <put_str>
c0001ab3:	83 c4 10             	add    $0x10,%esp
  idt_desc_init();  // 初始化IDT
c0001ab6:	e8 ef fc ff ff       	call   c00017aa <idt_desc_init>
  exception_init(); // 异常名初始化并注册通常的中断处理函数
c0001abb:	e8 3b fe ff ff       	call   c00018fb <exception_init>
  pic_init();       // 初始化8259A
c0001ac0:	e8 fc fb ff ff       	call   c00016c1 <pic_init>

  // 加载IDT
  uint64_t idt_operand =
      ((sizeof(idt) - 1) | (((uint64_t)(uint32_t)idt << 16)));
c0001ac5:	b8 c0 85 00 c0       	mov    $0xc00085c0,%eax
c0001aca:	ba 00 00 00 00       	mov    $0x0,%edx
c0001acf:	0f a4 c2 10          	shld   $0x10,%eax,%edx
c0001ad3:	c1 e0 10             	shl    $0x10,%eax
c0001ad6:	89 c1                	mov    %eax,%ecx
c0001ad8:	81 c9 07 04 00 00    	or     $0x407,%ecx
c0001ade:	89 ce                	mov    %ecx,%esi
c0001ae0:	89 d0                	mov    %edx,%eax
c0001ae2:	80 cc 00             	or     $0x0,%ah
c0001ae5:	89 c7                	mov    %eax,%edi
  uint64_t idt_operand =
c0001ae7:	89 75 f0             	mov    %esi,-0x10(%ebp)
c0001aea:	89 7d f4             	mov    %edi,-0xc(%ebp)
  asm volatile("lidt %0" ::"m"(idt_operand));
c0001aed:	0f 01 5d f0          	lidtl  -0x10(%ebp)
  put_str("idt_init done\n");
c0001af1:	83 ec 0c             	sub    $0xc,%esp
c0001af4:	68 5e 53 00 c0       	push   $0xc000535e
c0001af9:	e8 12 00 00 00       	call   c0001b10 <put_str>
c0001afe:	83 c4 10             	add    $0x10,%esp
c0001b01:	90                   	nop
c0001b02:	8d 65 f8             	lea    -0x8(%ebp),%esp
c0001b05:	5e                   	pop    %esi
c0001b06:	5f                   	pop    %edi
c0001b07:	5d                   	pop    %ebp
c0001b08:	c3                   	ret    
c0001b09:	66 90                	xchg   %ax,%ax
c0001b0b:	66 90                	xchg   %ax,%ax
c0001b0d:	66 90                	xchg   %ax,%ax
c0001b0f:	90                   	nop

c0001b10 <put_str>:
c0001b10:	53                   	push   %ebx
c0001b11:	51                   	push   %ecx
c0001b12:	31 c9                	xor    %ecx,%ecx
c0001b14:	8b 5c 24 0c          	mov    0xc(%esp),%ebx

c0001b18 <put_str.goon>:
c0001b18:	8a 0b                	mov    (%ebx),%cl
c0001b1a:	80 f9 00             	cmp    $0x0,%cl
c0001b1d:	74 0c                	je     c0001b2b <put_str.str_over>
c0001b1f:	51                   	push   %ecx
c0001b20:	e8 09 00 00 00       	call   c0001b2e <put_char>
c0001b25:	83 c4 04             	add    $0x4,%esp
c0001b28:	43                   	inc    %ebx
c0001b29:	eb ed                	jmp    c0001b18 <put_str.goon>

c0001b2b <put_str.str_over>:
c0001b2b:	59                   	pop    %ecx
c0001b2c:	5b                   	pop    %ebx
c0001b2d:	c3                   	ret    

c0001b2e <put_char>:
c0001b2e:	60                   	pusha  
c0001b2f:	66 b8 18 00          	mov    $0x18,%ax
c0001b33:	8e e8                	mov    %eax,%gs
c0001b35:	66 ba d4 03          	mov    $0x3d4,%dx
c0001b39:	b0 0e                	mov    $0xe,%al
c0001b3b:	ee                   	out    %al,(%dx)
c0001b3c:	66 ba d5 03          	mov    $0x3d5,%dx
c0001b40:	ec                   	in     (%dx),%al
c0001b41:	88 c4                	mov    %al,%ah
c0001b43:	66 ba d4 03          	mov    $0x3d4,%dx
c0001b47:	b0 0f                	mov    $0xf,%al
c0001b49:	ee                   	out    %al,(%dx)
c0001b4a:	66 ba d5 03          	mov    $0x3d5,%dx
c0001b4e:	ec                   	in     (%dx),%al
c0001b4f:	66 89 c3             	mov    %ax,%bx
c0001b52:	8b 4c 24 24          	mov    0x24(%esp),%ecx
c0001b56:	80 f9 0d             	cmp    $0xd,%cl
c0001b59:	74 3c                	je     c0001b97 <put_char.is_carriage_return>
c0001b5b:	80 f9 0a             	cmp    $0xa,%cl
c0001b5e:	74 37                	je     c0001b97 <put_char.is_carriage_return>
c0001b60:	80 f9 08             	cmp    $0x8,%cl
c0001b63:	74 02                	je     c0001b67 <put_char.back_space>
c0001b65:	eb 16                	jmp    c0001b7d <put_char.put_other>

c0001b67 <put_char.back_space>:
c0001b67:	66 4b                	dec    %bx
c0001b69:	66 d1 e3             	shl    %bx
c0001b6c:	65 67 c6 07 20       	movb   $0x20,%gs:(%bx)
c0001b71:	66 43                	inc    %bx
c0001b73:	65 67 c6 07 07       	movb   $0x7,%gs:(%bx)
c0001b78:	66 d1 eb             	shr    %bx
c0001b7b:	eb 61                	jmp    c0001bde <set_cursor>

c0001b7d <put_char.put_other>:
c0001b7d:	66 d1 e3             	shl    %bx
c0001b80:	65 67 88 0f          	mov    %cl,%gs:(%bx)
c0001b84:	66 43                	inc    %bx
c0001b86:	65 67 c6 07 07       	movb   $0x7,%gs:(%bx)
c0001b8b:	66 d1 eb             	shr    %bx
c0001b8e:	66 43                	inc    %bx
c0001b90:	66 81 fb d0 07       	cmp    $0x7d0,%bx
c0001b95:	7c 47                	jl     c0001bde <set_cursor>

c0001b97 <put_char.is_carriage_return>:
c0001b97:	66 31 d2             	xor    %dx,%dx
c0001b9a:	66 89 d8             	mov    %bx,%ax
c0001b9d:	66 be 50 00          	mov    $0x50,%si
c0001ba1:	66 f7 f6             	div    %si
c0001ba4:	66 29 d3             	sub    %dx,%bx

c0001ba7 <put_char.is_carriage_return_end>:
c0001ba7:	66 83 c3 50          	add    $0x50,%bx
c0001bab:	66 81 fb d0 07       	cmp    $0x7d0,%bx

c0001bb0 <put_char.is_line_feed_end>:
c0001bb0:	7c 2c                	jl     c0001bde <set_cursor>

c0001bb2 <put_char.roll_screen>:
c0001bb2:	fc                   	cld    
c0001bb3:	b9 c0 03 00 00       	mov    $0x3c0,%ecx
c0001bb8:	be a0 80 0b c0       	mov    $0xc00b80a0,%esi
c0001bbd:	bf 00 80 0b c0       	mov    $0xc00b8000,%edi
c0001bc2:	f3 a5                	rep movsl %ds:(%esi),%es:(%edi)
c0001bc4:	bb 00 0f 00 00       	mov    $0xf00,%ebx
c0001bc9:	b9 50 00 00 00       	mov    $0x50,%ecx

c0001bce <put_char.cls>:
c0001bce:	65 c7 03 20 07 00 00 	movl   $0x720,%gs:(%ebx)
c0001bd5:	83 c3 02             	add    $0x2,%ebx
c0001bd8:	e2 f4                	loop   c0001bce <put_char.cls>
c0001bda:	66 bb 80 07          	mov    $0x780,%bx

c0001bde <set_cursor>:
c0001bde:	66 ba d4 03          	mov    $0x3d4,%dx
c0001be2:	b0 0e                	mov    $0xe,%al
c0001be4:	ee                   	out    %al,(%dx)
c0001be5:	66 ba d5 03          	mov    $0x3d5,%dx
c0001be9:	88 f8                	mov    %bh,%al
c0001beb:	ee                   	out    %al,(%dx)
c0001bec:	66 ba d4 03          	mov    $0x3d4,%dx
c0001bf0:	b0 0f                	mov    $0xf,%al
c0001bf2:	ee                   	out    %al,(%dx)
c0001bf3:	66 ba d5 03          	mov    $0x3d5,%dx
c0001bf7:	88 d8                	mov    %bl,%al
c0001bf9:	ee                   	out    %al,(%dx)

c0001bfa <set_cursor.put_char_done>:
c0001bfa:	61                   	popa   
c0001bfb:	c3                   	ret    

c0001bfc <put_int>:
c0001bfc:	60                   	pusha  
c0001bfd:	89 e5                	mov    %esp,%ebp
c0001bff:	8b 45 24             	mov    0x24(%ebp),%eax
c0001c02:	89 c2                	mov    %eax,%edx
c0001c04:	bf 07 00 00 00       	mov    $0x7,%edi
c0001c09:	b9 08 00 00 00       	mov    $0x8,%ecx
c0001c0e:	bb 00 80 00 c0       	mov    $0xc0008000,%ebx

c0001c13 <put_int.16based_4bits>:
c0001c13:	83 e2 0f             	and    $0xf,%edx
c0001c16:	83 fa 09             	cmp    $0x9,%edx
c0001c19:	7f 05                	jg     c0001c20 <put_int.is_A2F>
c0001c1b:	83 c2 30             	add    $0x30,%edx
c0001c1e:	eb 06                	jmp    c0001c26 <put_int.store>

c0001c20 <put_int.is_A2F>:
c0001c20:	83 ea 0a             	sub    $0xa,%edx
c0001c23:	83 c2 41             	add    $0x41,%edx

c0001c26 <put_int.store>:
c0001c26:	88 14 3b             	mov    %dl,(%ebx,%edi,1)
c0001c29:	4f                   	dec    %edi
c0001c2a:	c1 e8 04             	shr    $0x4,%eax
c0001c2d:	89 c2                	mov    %eax,%edx
c0001c2f:	e2 e2                	loop   c0001c13 <put_int.16based_4bits>

c0001c31 <put_int.ready_to_print>:
c0001c31:	47                   	inc    %edi

c0001c32 <put_int.skip_prefix_0>:
c0001c32:	83 ff 08             	cmp    $0x8,%edi
c0001c35:	74 0f                	je     c0001c46 <put_int.full0>

c0001c37 <put_int.go_on_skip>:
c0001c37:	8a 8f 00 80 00 c0    	mov    -0x3fff8000(%edi),%cl
c0001c3d:	47                   	inc    %edi
c0001c3e:	80 f9 30             	cmp    $0x30,%cl
c0001c41:	74 ef                	je     c0001c32 <put_int.skip_prefix_0>
c0001c43:	4f                   	dec    %edi
c0001c44:	eb 02                	jmp    c0001c48 <put_int.put_each_num>

c0001c46 <put_int.full0>:
c0001c46:	b1 30                	mov    $0x30,%cl

c0001c48 <put_int.put_each_num>:
c0001c48:	51                   	push   %ecx
c0001c49:	e8 e0 fe ff ff       	call   c0001b2e <put_char>
c0001c4e:	83 c4 04             	add    $0x4,%esp
c0001c51:	47                   	inc    %edi
c0001c52:	8a 8f 00 80 00 c0    	mov    -0x3fff8000(%edi),%cl
c0001c58:	83 ff 08             	cmp    $0x8,%edi
c0001c5b:	7c eb                	jl     c0001c48 <put_int.put_each_num>
c0001c5d:	61                   	popa   
c0001c5e:	c3                   	ret    
c0001c5f:	90                   	nop

c0001c60 <intr_exit>:
c0001c60:	83 c4 04             	add    $0x4,%esp
c0001c63:	61                   	popa   
c0001c64:	0f a9                	pop    %gs
c0001c66:	0f a1                	pop    %fs
c0001c68:	07                   	pop    %es
c0001c69:	1f                   	pop    %ds
c0001c6a:	83 c4 04             	add    $0x4,%esp
c0001c6d:	cf                   	iret   

c0001c6e <intr0x00entry>:
c0001c6e:	6a 00                	push   $0x0
c0001c70:	1e                   	push   %ds
c0001c71:	06                   	push   %es
c0001c72:	0f a0                	push   %fs
c0001c74:	0f a8                	push   %gs
c0001c76:	60                   	pusha  
c0001c77:	b0 20                	mov    $0x20,%al
c0001c79:	e6 a0                	out    %al,$0xa0
c0001c7b:	e6 20                	out    %al,$0x20
c0001c7d:	6a 00                	push   $0x0
c0001c7f:	ff 15 a0 83 00 c0    	call   *0xc00083a0
c0001c85:	eb d9                	jmp    c0001c60 <intr_exit>

c0001c87 <intr0x01entry>:
c0001c87:	6a 00                	push   $0x0
c0001c89:	1e                   	push   %ds
c0001c8a:	06                   	push   %es
c0001c8b:	0f a0                	push   %fs
c0001c8d:	0f a8                	push   %gs
c0001c8f:	60                   	pusha  
c0001c90:	b0 20                	mov    $0x20,%al
c0001c92:	e6 a0                	out    %al,$0xa0
c0001c94:	e6 20                	out    %al,$0x20
c0001c96:	6a 01                	push   $0x1
c0001c98:	ff 15 a4 83 00 c0    	call   *0xc00083a4
c0001c9e:	eb c0                	jmp    c0001c60 <intr_exit>

c0001ca0 <intr0x02entry>:
c0001ca0:	6a 00                	push   $0x0
c0001ca2:	1e                   	push   %ds
c0001ca3:	06                   	push   %es
c0001ca4:	0f a0                	push   %fs
c0001ca6:	0f a8                	push   %gs
c0001ca8:	60                   	pusha  
c0001ca9:	b0 20                	mov    $0x20,%al
c0001cab:	e6 a0                	out    %al,$0xa0
c0001cad:	e6 20                	out    %al,$0x20
c0001caf:	6a 02                	push   $0x2
c0001cb1:	ff 15 a8 83 00 c0    	call   *0xc00083a8
c0001cb7:	eb a7                	jmp    c0001c60 <intr_exit>

c0001cb9 <intr0x03entry>:
c0001cb9:	6a 00                	push   $0x0
c0001cbb:	1e                   	push   %ds
c0001cbc:	06                   	push   %es
c0001cbd:	0f a0                	push   %fs
c0001cbf:	0f a8                	push   %gs
c0001cc1:	60                   	pusha  
c0001cc2:	b0 20                	mov    $0x20,%al
c0001cc4:	e6 a0                	out    %al,$0xa0
c0001cc6:	e6 20                	out    %al,$0x20
c0001cc8:	6a 03                	push   $0x3
c0001cca:	ff 15 ac 83 00 c0    	call   *0xc00083ac
c0001cd0:	eb 8e                	jmp    c0001c60 <intr_exit>

c0001cd2 <intr0x04entry>:
c0001cd2:	6a 00                	push   $0x0
c0001cd4:	1e                   	push   %ds
c0001cd5:	06                   	push   %es
c0001cd6:	0f a0                	push   %fs
c0001cd8:	0f a8                	push   %gs
c0001cda:	60                   	pusha  
c0001cdb:	b0 20                	mov    $0x20,%al
c0001cdd:	e6 a0                	out    %al,$0xa0
c0001cdf:	e6 20                	out    %al,$0x20
c0001ce1:	6a 04                	push   $0x4
c0001ce3:	ff 15 b0 83 00 c0    	call   *0xc00083b0
c0001ce9:	e9 72 ff ff ff       	jmp    c0001c60 <intr_exit>

c0001cee <intr0x05entry>:
c0001cee:	6a 00                	push   $0x0
c0001cf0:	1e                   	push   %ds
c0001cf1:	06                   	push   %es
c0001cf2:	0f a0                	push   %fs
c0001cf4:	0f a8                	push   %gs
c0001cf6:	60                   	pusha  
c0001cf7:	b0 20                	mov    $0x20,%al
c0001cf9:	e6 a0                	out    %al,$0xa0
c0001cfb:	e6 20                	out    %al,$0x20
c0001cfd:	6a 05                	push   $0x5
c0001cff:	ff 15 b4 83 00 c0    	call   *0xc00083b4
c0001d05:	e9 56 ff ff ff       	jmp    c0001c60 <intr_exit>

c0001d0a <intr0x06entry>:
c0001d0a:	6a 00                	push   $0x0
c0001d0c:	1e                   	push   %ds
c0001d0d:	06                   	push   %es
c0001d0e:	0f a0                	push   %fs
c0001d10:	0f a8                	push   %gs
c0001d12:	60                   	pusha  
c0001d13:	b0 20                	mov    $0x20,%al
c0001d15:	e6 a0                	out    %al,$0xa0
c0001d17:	e6 20                	out    %al,$0x20
c0001d19:	6a 06                	push   $0x6
c0001d1b:	ff 15 b8 83 00 c0    	call   *0xc00083b8
c0001d21:	e9 3a ff ff ff       	jmp    c0001c60 <intr_exit>

c0001d26 <intr0x07entry>:
c0001d26:	6a 00                	push   $0x0
c0001d28:	1e                   	push   %ds
c0001d29:	06                   	push   %es
c0001d2a:	0f a0                	push   %fs
c0001d2c:	0f a8                	push   %gs
c0001d2e:	60                   	pusha  
c0001d2f:	b0 20                	mov    $0x20,%al
c0001d31:	e6 a0                	out    %al,$0xa0
c0001d33:	e6 20                	out    %al,$0x20
c0001d35:	6a 07                	push   $0x7
c0001d37:	ff 15 bc 83 00 c0    	call   *0xc00083bc
c0001d3d:	e9 1e ff ff ff       	jmp    c0001c60 <intr_exit>

c0001d42 <intr0x08entry>:
c0001d42:	90                   	nop
c0001d43:	1e                   	push   %ds
c0001d44:	06                   	push   %es
c0001d45:	0f a0                	push   %fs
c0001d47:	0f a8                	push   %gs
c0001d49:	60                   	pusha  
c0001d4a:	b0 20                	mov    $0x20,%al
c0001d4c:	e6 a0                	out    %al,$0xa0
c0001d4e:	e6 20                	out    %al,$0x20
c0001d50:	6a 08                	push   $0x8
c0001d52:	ff 15 c0 83 00 c0    	call   *0xc00083c0
c0001d58:	e9 03 ff ff ff       	jmp    c0001c60 <intr_exit>

c0001d5d <intr0x09entry>:
c0001d5d:	6a 00                	push   $0x0
c0001d5f:	1e                   	push   %ds
c0001d60:	06                   	push   %es
c0001d61:	0f a0                	push   %fs
c0001d63:	0f a8                	push   %gs
c0001d65:	60                   	pusha  
c0001d66:	b0 20                	mov    $0x20,%al
c0001d68:	e6 a0                	out    %al,$0xa0
c0001d6a:	e6 20                	out    %al,$0x20
c0001d6c:	6a 09                	push   $0x9
c0001d6e:	ff 15 c4 83 00 c0    	call   *0xc00083c4
c0001d74:	e9 e7 fe ff ff       	jmp    c0001c60 <intr_exit>

c0001d79 <intr0x0aentry>:
c0001d79:	90                   	nop
c0001d7a:	1e                   	push   %ds
c0001d7b:	06                   	push   %es
c0001d7c:	0f a0                	push   %fs
c0001d7e:	0f a8                	push   %gs
c0001d80:	60                   	pusha  
c0001d81:	b0 20                	mov    $0x20,%al
c0001d83:	e6 a0                	out    %al,$0xa0
c0001d85:	e6 20                	out    %al,$0x20
c0001d87:	6a 0a                	push   $0xa
c0001d89:	ff 15 c8 83 00 c0    	call   *0xc00083c8
c0001d8f:	e9 cc fe ff ff       	jmp    c0001c60 <intr_exit>

c0001d94 <intr0x0bentry>:
c0001d94:	90                   	nop
c0001d95:	1e                   	push   %ds
c0001d96:	06                   	push   %es
c0001d97:	0f a0                	push   %fs
c0001d99:	0f a8                	push   %gs
c0001d9b:	60                   	pusha  
c0001d9c:	b0 20                	mov    $0x20,%al
c0001d9e:	e6 a0                	out    %al,$0xa0
c0001da0:	e6 20                	out    %al,$0x20
c0001da2:	6a 0b                	push   $0xb
c0001da4:	ff 15 cc 83 00 c0    	call   *0xc00083cc
c0001daa:	e9 b1 fe ff ff       	jmp    c0001c60 <intr_exit>

c0001daf <intr0x0centry>:
c0001daf:	90                   	nop
c0001db0:	1e                   	push   %ds
c0001db1:	06                   	push   %es
c0001db2:	0f a0                	push   %fs
c0001db4:	0f a8                	push   %gs
c0001db6:	60                   	pusha  
c0001db7:	b0 20                	mov    $0x20,%al
c0001db9:	e6 a0                	out    %al,$0xa0
c0001dbb:	e6 20                	out    %al,$0x20
c0001dbd:	6a 0c                	push   $0xc
c0001dbf:	ff 15 d0 83 00 c0    	call   *0xc00083d0
c0001dc5:	e9 96 fe ff ff       	jmp    c0001c60 <intr_exit>

c0001dca <intr0x0dentry>:
c0001dca:	90                   	nop
c0001dcb:	1e                   	push   %ds
c0001dcc:	06                   	push   %es
c0001dcd:	0f a0                	push   %fs
c0001dcf:	0f a8                	push   %gs
c0001dd1:	60                   	pusha  
c0001dd2:	b0 20                	mov    $0x20,%al
c0001dd4:	e6 a0                	out    %al,$0xa0
c0001dd6:	e6 20                	out    %al,$0x20
c0001dd8:	6a 0d                	push   $0xd
c0001dda:	ff 15 d4 83 00 c0    	call   *0xc00083d4
c0001de0:	e9 7b fe ff ff       	jmp    c0001c60 <intr_exit>

c0001de5 <intr0x0eentry>:
c0001de5:	90                   	nop
c0001de6:	1e                   	push   %ds
c0001de7:	06                   	push   %es
c0001de8:	0f a0                	push   %fs
c0001dea:	0f a8                	push   %gs
c0001dec:	60                   	pusha  
c0001ded:	b0 20                	mov    $0x20,%al
c0001def:	e6 a0                	out    %al,$0xa0
c0001df1:	e6 20                	out    %al,$0x20
c0001df3:	6a 0e                	push   $0xe
c0001df5:	ff 15 d8 83 00 c0    	call   *0xc00083d8
c0001dfb:	e9 60 fe ff ff       	jmp    c0001c60 <intr_exit>

c0001e00 <intr0x0fentry>:
c0001e00:	6a 00                	push   $0x0
c0001e02:	1e                   	push   %ds
c0001e03:	06                   	push   %es
c0001e04:	0f a0                	push   %fs
c0001e06:	0f a8                	push   %gs
c0001e08:	60                   	pusha  
c0001e09:	b0 20                	mov    $0x20,%al
c0001e0b:	e6 a0                	out    %al,$0xa0
c0001e0d:	e6 20                	out    %al,$0x20
c0001e0f:	6a 0f                	push   $0xf
c0001e11:	ff 15 dc 83 00 c0    	call   *0xc00083dc
c0001e17:	e9 44 fe ff ff       	jmp    c0001c60 <intr_exit>

c0001e1c <intr0x10entry>:
c0001e1c:	6a 00                	push   $0x0
c0001e1e:	1e                   	push   %ds
c0001e1f:	06                   	push   %es
c0001e20:	0f a0                	push   %fs
c0001e22:	0f a8                	push   %gs
c0001e24:	60                   	pusha  
c0001e25:	b0 20                	mov    $0x20,%al
c0001e27:	e6 a0                	out    %al,$0xa0
c0001e29:	e6 20                	out    %al,$0x20
c0001e2b:	6a 10                	push   $0x10
c0001e2d:	ff 15 e0 83 00 c0    	call   *0xc00083e0
c0001e33:	e9 28 fe ff ff       	jmp    c0001c60 <intr_exit>

c0001e38 <intr0x11entry>:
c0001e38:	90                   	nop
c0001e39:	1e                   	push   %ds
c0001e3a:	06                   	push   %es
c0001e3b:	0f a0                	push   %fs
c0001e3d:	0f a8                	push   %gs
c0001e3f:	60                   	pusha  
c0001e40:	b0 20                	mov    $0x20,%al
c0001e42:	e6 a0                	out    %al,$0xa0
c0001e44:	e6 20                	out    %al,$0x20
c0001e46:	6a 11                	push   $0x11
c0001e48:	ff 15 e4 83 00 c0    	call   *0xc00083e4
c0001e4e:	e9 0d fe ff ff       	jmp    c0001c60 <intr_exit>

c0001e53 <intr0x12entry>:
c0001e53:	6a 00                	push   $0x0
c0001e55:	1e                   	push   %ds
c0001e56:	06                   	push   %es
c0001e57:	0f a0                	push   %fs
c0001e59:	0f a8                	push   %gs
c0001e5b:	60                   	pusha  
c0001e5c:	b0 20                	mov    $0x20,%al
c0001e5e:	e6 a0                	out    %al,$0xa0
c0001e60:	e6 20                	out    %al,$0x20
c0001e62:	6a 12                	push   $0x12
c0001e64:	ff 15 e8 83 00 c0    	call   *0xc00083e8
c0001e6a:	e9 f1 fd ff ff       	jmp    c0001c60 <intr_exit>

c0001e6f <intr0x13entry>:
c0001e6f:	6a 00                	push   $0x0
c0001e71:	1e                   	push   %ds
c0001e72:	06                   	push   %es
c0001e73:	0f a0                	push   %fs
c0001e75:	0f a8                	push   %gs
c0001e77:	60                   	pusha  
c0001e78:	b0 20                	mov    $0x20,%al
c0001e7a:	e6 a0                	out    %al,$0xa0
c0001e7c:	e6 20                	out    %al,$0x20
c0001e7e:	6a 13                	push   $0x13
c0001e80:	ff 15 ec 83 00 c0    	call   *0xc00083ec
c0001e86:	e9 d5 fd ff ff       	jmp    c0001c60 <intr_exit>

c0001e8b <intr0x14entry>:
c0001e8b:	6a 00                	push   $0x0
c0001e8d:	1e                   	push   %ds
c0001e8e:	06                   	push   %es
c0001e8f:	0f a0                	push   %fs
c0001e91:	0f a8                	push   %gs
c0001e93:	60                   	pusha  
c0001e94:	b0 20                	mov    $0x20,%al
c0001e96:	e6 a0                	out    %al,$0xa0
c0001e98:	e6 20                	out    %al,$0x20
c0001e9a:	6a 14                	push   $0x14
c0001e9c:	ff 15 f0 83 00 c0    	call   *0xc00083f0
c0001ea2:	e9 b9 fd ff ff       	jmp    c0001c60 <intr_exit>

c0001ea7 <intr0x15entry>:
c0001ea7:	6a 00                	push   $0x0
c0001ea9:	1e                   	push   %ds
c0001eaa:	06                   	push   %es
c0001eab:	0f a0                	push   %fs
c0001ead:	0f a8                	push   %gs
c0001eaf:	60                   	pusha  
c0001eb0:	b0 20                	mov    $0x20,%al
c0001eb2:	e6 a0                	out    %al,$0xa0
c0001eb4:	e6 20                	out    %al,$0x20
c0001eb6:	6a 15                	push   $0x15
c0001eb8:	ff 15 f4 83 00 c0    	call   *0xc00083f4
c0001ebe:	e9 9d fd ff ff       	jmp    c0001c60 <intr_exit>

c0001ec3 <intr0x16entry>:
c0001ec3:	6a 00                	push   $0x0
c0001ec5:	1e                   	push   %ds
c0001ec6:	06                   	push   %es
c0001ec7:	0f a0                	push   %fs
c0001ec9:	0f a8                	push   %gs
c0001ecb:	60                   	pusha  
c0001ecc:	b0 20                	mov    $0x20,%al
c0001ece:	e6 a0                	out    %al,$0xa0
c0001ed0:	e6 20                	out    %al,$0x20
c0001ed2:	6a 16                	push   $0x16
c0001ed4:	ff 15 f8 83 00 c0    	call   *0xc00083f8
c0001eda:	e9 81 fd ff ff       	jmp    c0001c60 <intr_exit>

c0001edf <intr0x17entry>:
c0001edf:	6a 00                	push   $0x0
c0001ee1:	1e                   	push   %ds
c0001ee2:	06                   	push   %es
c0001ee3:	0f a0                	push   %fs
c0001ee5:	0f a8                	push   %gs
c0001ee7:	60                   	pusha  
c0001ee8:	b0 20                	mov    $0x20,%al
c0001eea:	e6 a0                	out    %al,$0xa0
c0001eec:	e6 20                	out    %al,$0x20
c0001eee:	6a 17                	push   $0x17
c0001ef0:	ff 15 fc 83 00 c0    	call   *0xc00083fc
c0001ef6:	e9 65 fd ff ff       	jmp    c0001c60 <intr_exit>

c0001efb <intr0x18entry>:
c0001efb:	6a 00                	push   $0x0
c0001efd:	1e                   	push   %ds
c0001efe:	06                   	push   %es
c0001eff:	0f a0                	push   %fs
c0001f01:	0f a8                	push   %gs
c0001f03:	60                   	pusha  
c0001f04:	b0 20                	mov    $0x20,%al
c0001f06:	e6 a0                	out    %al,$0xa0
c0001f08:	e6 20                	out    %al,$0x20
c0001f0a:	6a 18                	push   $0x18
c0001f0c:	ff 15 00 84 00 c0    	call   *0xc0008400
c0001f12:	e9 49 fd ff ff       	jmp    c0001c60 <intr_exit>

c0001f17 <intr0x19entry>:
c0001f17:	6a 00                	push   $0x0
c0001f19:	1e                   	push   %ds
c0001f1a:	06                   	push   %es
c0001f1b:	0f a0                	push   %fs
c0001f1d:	0f a8                	push   %gs
c0001f1f:	60                   	pusha  
c0001f20:	b0 20                	mov    $0x20,%al
c0001f22:	e6 a0                	out    %al,$0xa0
c0001f24:	e6 20                	out    %al,$0x20
c0001f26:	6a 19                	push   $0x19
c0001f28:	ff 15 04 84 00 c0    	call   *0xc0008404
c0001f2e:	e9 2d fd ff ff       	jmp    c0001c60 <intr_exit>

c0001f33 <intr0x1aentry>:
c0001f33:	6a 00                	push   $0x0
c0001f35:	1e                   	push   %ds
c0001f36:	06                   	push   %es
c0001f37:	0f a0                	push   %fs
c0001f39:	0f a8                	push   %gs
c0001f3b:	60                   	pusha  
c0001f3c:	b0 20                	mov    $0x20,%al
c0001f3e:	e6 a0                	out    %al,$0xa0
c0001f40:	e6 20                	out    %al,$0x20
c0001f42:	6a 1a                	push   $0x1a
c0001f44:	ff 15 08 84 00 c0    	call   *0xc0008408
c0001f4a:	e9 11 fd ff ff       	jmp    c0001c60 <intr_exit>

c0001f4f <intr0x1bentry>:
c0001f4f:	6a 00                	push   $0x0
c0001f51:	1e                   	push   %ds
c0001f52:	06                   	push   %es
c0001f53:	0f a0                	push   %fs
c0001f55:	0f a8                	push   %gs
c0001f57:	60                   	pusha  
c0001f58:	b0 20                	mov    $0x20,%al
c0001f5a:	e6 a0                	out    %al,$0xa0
c0001f5c:	e6 20                	out    %al,$0x20
c0001f5e:	6a 1b                	push   $0x1b
c0001f60:	ff 15 0c 84 00 c0    	call   *0xc000840c
c0001f66:	e9 f5 fc ff ff       	jmp    c0001c60 <intr_exit>

c0001f6b <intr0x1centry>:
c0001f6b:	6a 00                	push   $0x0
c0001f6d:	1e                   	push   %ds
c0001f6e:	06                   	push   %es
c0001f6f:	0f a0                	push   %fs
c0001f71:	0f a8                	push   %gs
c0001f73:	60                   	pusha  
c0001f74:	b0 20                	mov    $0x20,%al
c0001f76:	e6 a0                	out    %al,$0xa0
c0001f78:	e6 20                	out    %al,$0x20
c0001f7a:	6a 1c                	push   $0x1c
c0001f7c:	ff 15 10 84 00 c0    	call   *0xc0008410
c0001f82:	e9 d9 fc ff ff       	jmp    c0001c60 <intr_exit>

c0001f87 <intr0x1dentry>:
c0001f87:	6a 00                	push   $0x0
c0001f89:	1e                   	push   %ds
c0001f8a:	06                   	push   %es
c0001f8b:	0f a0                	push   %fs
c0001f8d:	0f a8                	push   %gs
c0001f8f:	60                   	pusha  
c0001f90:	b0 20                	mov    $0x20,%al
c0001f92:	e6 a0                	out    %al,$0xa0
c0001f94:	e6 20                	out    %al,$0x20
c0001f96:	6a 1d                	push   $0x1d
c0001f98:	ff 15 14 84 00 c0    	call   *0xc0008414
c0001f9e:	e9 bd fc ff ff       	jmp    c0001c60 <intr_exit>

c0001fa3 <intr0x1eentry>:
c0001fa3:	90                   	nop
c0001fa4:	1e                   	push   %ds
c0001fa5:	06                   	push   %es
c0001fa6:	0f a0                	push   %fs
c0001fa8:	0f a8                	push   %gs
c0001faa:	60                   	pusha  
c0001fab:	b0 20                	mov    $0x20,%al
c0001fad:	e6 a0                	out    %al,$0xa0
c0001faf:	e6 20                	out    %al,$0x20
c0001fb1:	6a 1e                	push   $0x1e
c0001fb3:	ff 15 18 84 00 c0    	call   *0xc0008418
c0001fb9:	e9 a2 fc ff ff       	jmp    c0001c60 <intr_exit>

c0001fbe <intr0x1fentry>:
c0001fbe:	6a 00                	push   $0x0
c0001fc0:	1e                   	push   %ds
c0001fc1:	06                   	push   %es
c0001fc2:	0f a0                	push   %fs
c0001fc4:	0f a8                	push   %gs
c0001fc6:	60                   	pusha  
c0001fc7:	b0 20                	mov    $0x20,%al
c0001fc9:	e6 a0                	out    %al,$0xa0
c0001fcb:	e6 20                	out    %al,$0x20
c0001fcd:	6a 1f                	push   $0x1f
c0001fcf:	ff 15 1c 84 00 c0    	call   *0xc000841c
c0001fd5:	e9 86 fc ff ff       	jmp    c0001c60 <intr_exit>

c0001fda <intr0x20entry>:
c0001fda:	6a 00                	push   $0x0
c0001fdc:	1e                   	push   %ds
c0001fdd:	06                   	push   %es
c0001fde:	0f a0                	push   %fs
c0001fe0:	0f a8                	push   %gs
c0001fe2:	60                   	pusha  
c0001fe3:	b0 20                	mov    $0x20,%al
c0001fe5:	e6 a0                	out    %al,$0xa0
c0001fe7:	e6 20                	out    %al,$0x20
c0001fe9:	6a 20                	push   $0x20
c0001feb:	ff 15 20 84 00 c0    	call   *0xc0008420
c0001ff1:	e9 6a fc ff ff       	jmp    c0001c60 <intr_exit>

c0001ff6 <intr0x21entry>:
c0001ff6:	6a 00                	push   $0x0
c0001ff8:	1e                   	push   %ds
c0001ff9:	06                   	push   %es
c0001ffa:	0f a0                	push   %fs
c0001ffc:	0f a8                	push   %gs
c0001ffe:	60                   	pusha  
c0001fff:	b0 20                	mov    $0x20,%al
c0002001:	e6 a0                	out    %al,$0xa0
c0002003:	e6 20                	out    %al,$0x20
c0002005:	6a 21                	push   $0x21
c0002007:	ff 15 24 84 00 c0    	call   *0xc0008424
c000200d:	e9 4e fc ff ff       	jmp    c0001c60 <intr_exit>

c0002012 <intr0x22entry>:
c0002012:	6a 00                	push   $0x0
c0002014:	1e                   	push   %ds
c0002015:	06                   	push   %es
c0002016:	0f a0                	push   %fs
c0002018:	0f a8                	push   %gs
c000201a:	60                   	pusha  
c000201b:	b0 20                	mov    $0x20,%al
c000201d:	e6 a0                	out    %al,$0xa0
c000201f:	e6 20                	out    %al,$0x20
c0002021:	6a 22                	push   $0x22
c0002023:	ff 15 28 84 00 c0    	call   *0xc0008428
c0002029:	e9 32 fc ff ff       	jmp    c0001c60 <intr_exit>

c000202e <intr0x23entry>:
c000202e:	6a 00                	push   $0x0
c0002030:	1e                   	push   %ds
c0002031:	06                   	push   %es
c0002032:	0f a0                	push   %fs
c0002034:	0f a8                	push   %gs
c0002036:	60                   	pusha  
c0002037:	b0 20                	mov    $0x20,%al
c0002039:	e6 a0                	out    %al,$0xa0
c000203b:	e6 20                	out    %al,$0x20
c000203d:	6a 23                	push   $0x23
c000203f:	ff 15 2c 84 00 c0    	call   *0xc000842c
c0002045:	e9 16 fc ff ff       	jmp    c0001c60 <intr_exit>

c000204a <intr0x24entry>:
c000204a:	6a 00                	push   $0x0
c000204c:	1e                   	push   %ds
c000204d:	06                   	push   %es
c000204e:	0f a0                	push   %fs
c0002050:	0f a8                	push   %gs
c0002052:	60                   	pusha  
c0002053:	b0 20                	mov    $0x20,%al
c0002055:	e6 a0                	out    %al,$0xa0
c0002057:	e6 20                	out    %al,$0x20
c0002059:	6a 24                	push   $0x24
c000205b:	ff 15 30 84 00 c0    	call   *0xc0008430
c0002061:	e9 fa fb ff ff       	jmp    c0001c60 <intr_exit>

c0002066 <intr0x25entry>:
c0002066:	6a 00                	push   $0x0
c0002068:	1e                   	push   %ds
c0002069:	06                   	push   %es
c000206a:	0f a0                	push   %fs
c000206c:	0f a8                	push   %gs
c000206e:	60                   	pusha  
c000206f:	b0 20                	mov    $0x20,%al
c0002071:	e6 a0                	out    %al,$0xa0
c0002073:	e6 20                	out    %al,$0x20
c0002075:	6a 25                	push   $0x25
c0002077:	ff 15 34 84 00 c0    	call   *0xc0008434
c000207d:	e9 de fb ff ff       	jmp    c0001c60 <intr_exit>

c0002082 <intr0x26entry>:
c0002082:	6a 00                	push   $0x0
c0002084:	1e                   	push   %ds
c0002085:	06                   	push   %es
c0002086:	0f a0                	push   %fs
c0002088:	0f a8                	push   %gs
c000208a:	60                   	pusha  
c000208b:	b0 20                	mov    $0x20,%al
c000208d:	e6 a0                	out    %al,$0xa0
c000208f:	e6 20                	out    %al,$0x20
c0002091:	6a 26                	push   $0x26
c0002093:	ff 15 38 84 00 c0    	call   *0xc0008438
c0002099:	e9 c2 fb ff ff       	jmp    c0001c60 <intr_exit>

c000209e <intr0x27entry>:
c000209e:	6a 00                	push   $0x0
c00020a0:	1e                   	push   %ds
c00020a1:	06                   	push   %es
c00020a2:	0f a0                	push   %fs
c00020a4:	0f a8                	push   %gs
c00020a6:	60                   	pusha  
c00020a7:	b0 20                	mov    $0x20,%al
c00020a9:	e6 a0                	out    %al,$0xa0
c00020ab:	e6 20                	out    %al,$0x20
c00020ad:	6a 27                	push   $0x27
c00020af:	ff 15 3c 84 00 c0    	call   *0xc000843c
c00020b5:	e9 a6 fb ff ff       	jmp    c0001c60 <intr_exit>

c00020ba <intr0x28entry>:
c00020ba:	6a 00                	push   $0x0
c00020bc:	1e                   	push   %ds
c00020bd:	06                   	push   %es
c00020be:	0f a0                	push   %fs
c00020c0:	0f a8                	push   %gs
c00020c2:	60                   	pusha  
c00020c3:	b0 20                	mov    $0x20,%al
c00020c5:	e6 a0                	out    %al,$0xa0
c00020c7:	e6 20                	out    %al,$0x20
c00020c9:	6a 28                	push   $0x28
c00020cb:	ff 15 40 84 00 c0    	call   *0xc0008440
c00020d1:	e9 8a fb ff ff       	jmp    c0001c60 <intr_exit>

c00020d6 <intr0x29entry>:
c00020d6:	6a 00                	push   $0x0
c00020d8:	1e                   	push   %ds
c00020d9:	06                   	push   %es
c00020da:	0f a0                	push   %fs
c00020dc:	0f a8                	push   %gs
c00020de:	60                   	pusha  
c00020df:	b0 20                	mov    $0x20,%al
c00020e1:	e6 a0                	out    %al,$0xa0
c00020e3:	e6 20                	out    %al,$0x20
c00020e5:	6a 29                	push   $0x29
c00020e7:	ff 15 44 84 00 c0    	call   *0xc0008444
c00020ed:	e9 6e fb ff ff       	jmp    c0001c60 <intr_exit>

c00020f2 <intr0x2aentry>:
c00020f2:	6a 00                	push   $0x0
c00020f4:	1e                   	push   %ds
c00020f5:	06                   	push   %es
c00020f6:	0f a0                	push   %fs
c00020f8:	0f a8                	push   %gs
c00020fa:	60                   	pusha  
c00020fb:	b0 20                	mov    $0x20,%al
c00020fd:	e6 a0                	out    %al,$0xa0
c00020ff:	e6 20                	out    %al,$0x20
c0002101:	6a 2a                	push   $0x2a
c0002103:	ff 15 48 84 00 c0    	call   *0xc0008448
c0002109:	e9 52 fb ff ff       	jmp    c0001c60 <intr_exit>

c000210e <intr0x2bentry>:
c000210e:	6a 00                	push   $0x0
c0002110:	1e                   	push   %ds
c0002111:	06                   	push   %es
c0002112:	0f a0                	push   %fs
c0002114:	0f a8                	push   %gs
c0002116:	60                   	pusha  
c0002117:	b0 20                	mov    $0x20,%al
c0002119:	e6 a0                	out    %al,$0xa0
c000211b:	e6 20                	out    %al,$0x20
c000211d:	6a 2b                	push   $0x2b
c000211f:	ff 15 4c 84 00 c0    	call   *0xc000844c
c0002125:	e9 36 fb ff ff       	jmp    c0001c60 <intr_exit>

c000212a <intr0x2centry>:
c000212a:	6a 00                	push   $0x0
c000212c:	1e                   	push   %ds
c000212d:	06                   	push   %es
c000212e:	0f a0                	push   %fs
c0002130:	0f a8                	push   %gs
c0002132:	60                   	pusha  
c0002133:	b0 20                	mov    $0x20,%al
c0002135:	e6 a0                	out    %al,$0xa0
c0002137:	e6 20                	out    %al,$0x20
c0002139:	6a 2c                	push   $0x2c
c000213b:	ff 15 50 84 00 c0    	call   *0xc0008450
c0002141:	e9 1a fb ff ff       	jmp    c0001c60 <intr_exit>

c0002146 <intr0x2dentry>:
c0002146:	6a 00                	push   $0x0
c0002148:	1e                   	push   %ds
c0002149:	06                   	push   %es
c000214a:	0f a0                	push   %fs
c000214c:	0f a8                	push   %gs
c000214e:	60                   	pusha  
c000214f:	b0 20                	mov    $0x20,%al
c0002151:	e6 a0                	out    %al,$0xa0
c0002153:	e6 20                	out    %al,$0x20
c0002155:	6a 2d                	push   $0x2d
c0002157:	ff 15 54 84 00 c0    	call   *0xc0008454
c000215d:	e9 fe fa ff ff       	jmp    c0001c60 <intr_exit>

c0002162 <intr0x2eentry>:
c0002162:	6a 00                	push   $0x0
c0002164:	1e                   	push   %ds
c0002165:	06                   	push   %es
c0002166:	0f a0                	push   %fs
c0002168:	0f a8                	push   %gs
c000216a:	60                   	pusha  
c000216b:	b0 20                	mov    $0x20,%al
c000216d:	e6 a0                	out    %al,$0xa0
c000216f:	e6 20                	out    %al,$0x20
c0002171:	6a 2e                	push   $0x2e
c0002173:	ff 15 58 84 00 c0    	call   *0xc0008458
c0002179:	e9 e2 fa ff ff       	jmp    c0001c60 <intr_exit>

c000217e <intr0x2fentry>:
c000217e:	6a 00                	push   $0x0
c0002180:	1e                   	push   %ds
c0002181:	06                   	push   %es
c0002182:	0f a0                	push   %fs
c0002184:	0f a8                	push   %gs
c0002186:	60                   	pusha  
c0002187:	b0 20                	mov    $0x20,%al
c0002189:	e6 a0                	out    %al,$0xa0
c000218b:	e6 20                	out    %al,$0x20
c000218d:	6a 2f                	push   $0x2f
c000218f:	ff 15 5c 84 00 c0    	call   *0xc000845c
c0002195:	e9 c6 fa ff ff       	jmp    c0001c60 <intr_exit>

c000219a <syscall_handler>:
c000219a:	6a 00                	push   $0x0
c000219c:	1e                   	push   %ds
c000219d:	06                   	push   %es
c000219e:	0f a0                	push   %fs
c00021a0:	0f a8                	push   %gs
c00021a2:	60                   	pusha  
c00021a3:	68 80 00 00 00       	push   $0x80
c00021a8:	52                   	push   %edx
c00021a9:	51                   	push   %ecx
c00021aa:	52                   	push   %edx
c00021ab:	ff 14 85 c0 8b 00 c0 	call   *-0x3fff7440(,%eax,4)
c00021b2:	83 c4 0c             	add    $0xc,%esp
c00021b5:	89 44 24 20          	mov    %eax,0x20(%esp)
c00021b9:	e9 a2 fa ff ff       	jmp    c0001c60 <intr_exit>

c00021be <outb>:
static inline void outb(uint16_t port, uint8_t data) {
c00021be:	55                   	push   %ebp
c00021bf:	89 e5                	mov    %esp,%ebp
c00021c1:	83 ec 08             	sub    $0x8,%esp
c00021c4:	8b 45 08             	mov    0x8(%ebp),%eax
c00021c7:	8b 55 0c             	mov    0xc(%ebp),%edx
c00021ca:	66 89 45 fc          	mov    %ax,-0x4(%ebp)
c00021ce:	89 d0                	mov    %edx,%eax
c00021d0:	88 45 f8             	mov    %al,-0x8(%ebp)
  asm volatile("outb %b0, %w1" ::"a"(data), "Nd"(port));
c00021d3:	0f b6 45 f8          	movzbl -0x8(%ebp),%eax
c00021d7:	0f b7 55 fc          	movzwl -0x4(%ebp),%edx
c00021db:	ee                   	out    %al,(%dx)
}
c00021dc:	90                   	nop
c00021dd:	c9                   	leave  
c00021de:	c3                   	ret    

c00021df <frequency_set>:
#define PIT_CONTROL_PORT 0x43

uint32_t ticks; // 内核发生的总中断次数（系统运行时长）

static void frequency_set(uint8_t counter_port, uint8_t counter_no, uint8_t rwl,
                          uint8_t counter_mode, uint16_t counter_value) {
c00021df:	55                   	push   %ebp
c00021e0:	89 e5                	mov    %esp,%ebp
c00021e2:	57                   	push   %edi
c00021e3:	56                   	push   %esi
c00021e4:	53                   	push   %ebx
c00021e5:	83 ec 14             	sub    $0x14,%esp
c00021e8:	8b 75 08             	mov    0x8(%ebp),%esi
c00021eb:	8b 5d 0c             	mov    0xc(%ebp),%ebx
c00021ee:	8b 4d 10             	mov    0x10(%ebp),%ecx
c00021f1:	8b 55 14             	mov    0x14(%ebp),%edx
c00021f4:	8b 7d 18             	mov    0x18(%ebp),%edi
c00021f7:	89 f0                	mov    %esi,%eax
c00021f9:	88 45 f0             	mov    %al,-0x10(%ebp)
c00021fc:	88 5d ec             	mov    %bl,-0x14(%ebp)
c00021ff:	88 4d e8             	mov    %cl,-0x18(%ebp)
c0002202:	88 55 e4             	mov    %dl,-0x1c(%ebp)
c0002205:	89 f8                	mov    %edi,%eax
c0002207:	66 89 45 e0          	mov    %ax,-0x20(%ebp)
  // 往控制字寄存器端口0x43中写入控制字
  outb(PIT_CONTROL_PORT,
       (uint8_t)(counter_no << 6 | rwl << 4 | counter_mode << 1));
c000220b:	0f b6 45 ec          	movzbl -0x14(%ebp),%eax
c000220f:	c1 e0 06             	shl    $0x6,%eax
c0002212:	89 c2                	mov    %eax,%edx
c0002214:	0f b6 45 e8          	movzbl -0x18(%ebp),%eax
c0002218:	c1 e0 04             	shl    $0x4,%eax
c000221b:	09 c2                	or     %eax,%edx
c000221d:	0f b6 45 e4          	movzbl -0x1c(%ebp),%eax
c0002221:	01 c0                	add    %eax,%eax
c0002223:	09 d0                	or     %edx,%eax
  outb(PIT_CONTROL_PORT,
c0002225:	0f b6 c0             	movzbl %al,%eax
c0002228:	50                   	push   %eax
c0002229:	6a 43                	push   $0x43
c000222b:	e8 8e ff ff ff       	call   c00021be <outb>
c0002230:	83 c4 08             	add    $0x8,%esp
  // 先写入counter_value低8位，再写高8位
  outb(counter_port, (uint8_t)counter_value);
c0002233:	0f b7 45 e0          	movzwl -0x20(%ebp),%eax
c0002237:	0f b6 d0             	movzbl %al,%edx
c000223a:	0f b6 45 f0          	movzbl -0x10(%ebp),%eax
c000223e:	52                   	push   %edx
c000223f:	50                   	push   %eax
c0002240:	e8 79 ff ff ff       	call   c00021be <outb>
c0002245:	83 c4 08             	add    $0x8,%esp
  outb(counter_port, (uint8_t)counter_value >> 8);
c0002248:	0f b7 45 e0          	movzwl -0x20(%ebp),%eax
c000224c:	0f b6 c0             	movzbl %al,%eax
c000224f:	c1 f8 08             	sar    $0x8,%eax
c0002252:	0f b6 d0             	movzbl %al,%edx
c0002255:	0f b6 45 f0          	movzbl -0x10(%ebp),%eax
c0002259:	52                   	push   %edx
c000225a:	50                   	push   %eax
c000225b:	e8 5e ff ff ff       	call   c00021be <outb>
c0002260:	83 c4 08             	add    $0x8,%esp
}
c0002263:	90                   	nop
c0002264:	8d 65 f4             	lea    -0xc(%ebp),%esp
c0002267:	5b                   	pop    %ebx
c0002268:	5e                   	pop    %esi
c0002269:	5f                   	pop    %edi
c000226a:	5d                   	pop    %ebp
c000226b:	c3                   	ret    

c000226c <intr_timer_handler>:

// 时钟中断处理函数
static void intr_timer_handler(void) {
c000226c:	55                   	push   %ebp
c000226d:	89 e5                	mov    %esp,%ebp
c000226f:	83 ec 18             	sub    $0x18,%esp
  struct task_struct *cur_thread = running_thread();
c0002272:	e8 8f 0f 00 00       	call   c0003206 <running_thread>
c0002277:	89 45 f4             	mov    %eax,-0xc(%ebp)
  ASSERT(cur_thread->stack_magic == 0x20021112);
c000227a:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000227d:	8b 40 44             	mov    0x44(%eax),%eax
c0002280:	3d 12 11 02 20       	cmp    $0x20021112,%eax
c0002285:	74 19                	je     c00022a0 <intr_timer_handler+0x34>
c0002287:	68 70 53 00 c0       	push   $0xc0005370
c000228c:	68 c8 53 00 c0       	push   $0xc00053c8
c0002291:	6a 20                	push   $0x20
c0002293:	68 96 53 00 c0       	push   $0xc0005396
c0002298:	e8 97 00 00 00       	call   c0002334 <panic_spin>
c000229d:	83 c4 10             	add    $0x10,%esp
  cur_thread->elapsed_ticks++; // 记录此线程占用cpu时间
c00022a0:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00022a3:	8b 40 20             	mov    0x20(%eax),%eax
c00022a6:	8d 50 01             	lea    0x1(%eax),%edx
c00022a9:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00022ac:	89 50 20             	mov    %edx,0x20(%eax)
  ticks++;
c00022af:	a1 c8 89 00 c0       	mov    0xc00089c8,%eax
c00022b4:	83 c0 01             	add    $0x1,%eax
c00022b7:	a3 c8 89 00 c0       	mov    %eax,0xc00089c8

  if (cur_thread->ticks == 0) { // 时间片用完，调度新进程上cpu
c00022bc:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00022bf:	0f b6 40 1d          	movzbl 0x1d(%eax),%eax
c00022c3:	84 c0                	test   %al,%al
c00022c5:	75 07                	jne    c00022ce <intr_timer_handler+0x62>
    schedule();
c00022c7:	e8 13 12 00 00       	call   c00034df <schedule>
  } else {
    cur_thread->ticks--;
  }
}
c00022cc:	eb 10                	jmp    c00022de <intr_timer_handler+0x72>
    cur_thread->ticks--;
c00022ce:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00022d1:	0f b6 40 1d          	movzbl 0x1d(%eax),%eax
c00022d5:	8d 50 ff             	lea    -0x1(%eax),%edx
c00022d8:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00022db:	88 50 1d             	mov    %dl,0x1d(%eax)
}
c00022de:	90                   	nop
c00022df:	c9                   	leave  
c00022e0:	c3                   	ret    

c00022e1 <timer_init>:

// 初始化PIT8253
void timer_init() {
c00022e1:	55                   	push   %ebp
c00022e2:	89 e5                	mov    %esp,%ebp
c00022e4:	83 ec 08             	sub    $0x8,%esp
  put_str("timer_init start\n");
c00022e7:	83 ec 0c             	sub    $0xc,%esp
c00022ea:	68 a5 53 00 c0       	push   $0xc00053a5
c00022ef:	e8 1c f8 ff ff       	call   c0001b10 <put_str>
c00022f4:	83 c4 10             	add    $0x10,%esp
  // 设置8253定时周期-> 发中断周期
  frequency_set(CONTRER0_PORT, COUNTER0_NO, READ_WRITE_LATCH, COUNTER_MODE,
c00022f7:	83 ec 0c             	sub    $0xc,%esp
c00022fa:	68 9b 2e 00 00       	push   $0x2e9b
c00022ff:	6a 02                	push   $0x2
c0002301:	6a 03                	push   $0x3
c0002303:	6a 00                	push   $0x0
c0002305:	6a 40                	push   $0x40
c0002307:	e8 d3 fe ff ff       	call   c00021df <frequency_set>
c000230c:	83 c4 20             	add    $0x20,%esp
                COUNTER0_VALUE);
  register_handler(0x20, intr_timer_handler); // 注册时钟中断处理函数
c000230f:	83 ec 08             	sub    $0x8,%esp
c0002312:	68 6c 22 00 c0       	push   $0xc000226c
c0002317:	6a 20                	push   $0x20
c0002319:	e8 28 f7 ff ff       	call   c0001a46 <register_handler>
c000231e:	83 c4 10             	add    $0x10,%esp
  put_str("timer_init done\n");
c0002321:	83 ec 0c             	sub    $0xc,%esp
c0002324:	68 b7 53 00 c0       	push   $0xc00053b7
c0002329:	e8 e2 f7 ff ff       	call   c0001b10 <put_str>
c000232e:	83 c4 10             	add    $0x10,%esp
c0002331:	90                   	nop
c0002332:	c9                   	leave  
c0002333:	c3                   	ret    

c0002334 <panic_spin>:
#include "interrupt.h"
#include "print.h"

// 打印文件名、行号、函数名、条件并使程序悬停
void panic_spin(char *filename, int line, const char *func,
                const char *condition) {
c0002334:	55                   	push   %ebp
c0002335:	89 e5                	mov    %esp,%ebp
c0002337:	83 ec 08             	sub    $0x8,%esp
  intr_disable(); // 因为有时候会单独调用 panic_spin，所以在此处关中断
c000233a:	e8 de f6 ff ff       	call   c0001a1d <intr_disable>
  put_str("\n\n\n!!!!! error !!!!!\n");
c000233f:	83 ec 0c             	sub    $0xc,%esp
c0002342:	68 db 53 00 c0       	push   $0xc00053db
c0002347:	e8 c4 f7 ff ff       	call   c0001b10 <put_str>
c000234c:	83 c4 10             	add    $0x10,%esp
  put_str("filename:");
c000234f:	83 ec 0c             	sub    $0xc,%esp
c0002352:	68 f1 53 00 c0       	push   $0xc00053f1
c0002357:	e8 b4 f7 ff ff       	call   c0001b10 <put_str>
c000235c:	83 c4 10             	add    $0x10,%esp
  put_str(filename);
c000235f:	83 ec 0c             	sub    $0xc,%esp
c0002362:	ff 75 08             	push   0x8(%ebp)
c0002365:	e8 a6 f7 ff ff       	call   c0001b10 <put_str>
c000236a:	83 c4 10             	add    $0x10,%esp
  put_str("\n");
c000236d:	83 ec 0c             	sub    $0xc,%esp
c0002370:	68 fb 53 00 c0       	push   $0xc00053fb
c0002375:	e8 96 f7 ff ff       	call   c0001b10 <put_str>
c000237a:	83 c4 10             	add    $0x10,%esp

  put_str("line:0x");
c000237d:	83 ec 0c             	sub    $0xc,%esp
c0002380:	68 fd 53 00 c0       	push   $0xc00053fd
c0002385:	e8 86 f7 ff ff       	call   c0001b10 <put_str>
c000238a:	83 c4 10             	add    $0x10,%esp
  put_int(line);
c000238d:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002390:	83 ec 0c             	sub    $0xc,%esp
c0002393:	50                   	push   %eax
c0002394:	e8 63 f8 ff ff       	call   c0001bfc <put_int>
c0002399:	83 c4 10             	add    $0x10,%esp
  put_str("\n");
c000239c:	83 ec 0c             	sub    $0xc,%esp
c000239f:	68 fb 53 00 c0       	push   $0xc00053fb
c00023a4:	e8 67 f7 ff ff       	call   c0001b10 <put_str>
c00023a9:	83 c4 10             	add    $0x10,%esp

  put_str("function:");
c00023ac:	83 ec 0c             	sub    $0xc,%esp
c00023af:	68 05 54 00 c0       	push   $0xc0005405
c00023b4:	e8 57 f7 ff ff       	call   c0001b10 <put_str>
c00023b9:	83 c4 10             	add    $0x10,%esp
  put_str((char *)func);
c00023bc:	83 ec 0c             	sub    $0xc,%esp
c00023bf:	ff 75 10             	push   0x10(%ebp)
c00023c2:	e8 49 f7 ff ff       	call   c0001b10 <put_str>
c00023c7:	83 c4 10             	add    $0x10,%esp
  put_str("\n");
c00023ca:	83 ec 0c             	sub    $0xc,%esp
c00023cd:	68 fb 53 00 c0       	push   $0xc00053fb
c00023d2:	e8 39 f7 ff ff       	call   c0001b10 <put_str>
c00023d7:	83 c4 10             	add    $0x10,%esp

  put_str("condition:");
c00023da:	83 ec 0c             	sub    $0xc,%esp
c00023dd:	68 0f 54 00 c0       	push   $0xc000540f
c00023e2:	e8 29 f7 ff ff       	call   c0001b10 <put_str>
c00023e7:	83 c4 10             	add    $0x10,%esp
  put_str((char *)condition);
c00023ea:	83 ec 0c             	sub    $0xc,%esp
c00023ed:	ff 75 14             	push   0x14(%ebp)
c00023f0:	e8 1b f7 ff ff       	call   c0001b10 <put_str>
c00023f5:	83 c4 10             	add    $0x10,%esp
  put_str("\n");
c00023f8:	83 ec 0c             	sub    $0xc,%esp
c00023fb:	68 fb 53 00 c0       	push   $0xc00053fb
c0002400:	e8 0b f7 ff ff       	call   c0001b10 <put_str>
c0002405:	83 c4 10             	add    $0x10,%esp
  while (1) {
c0002408:	eb fe                	jmp    c0002408 <panic_spin+0xd4>

c000240a <memset>:
#include "debug.h"
#include "global.h"

// 内存区域的数据初始化（内存分配时的数据清零）=>
// 将dst_起始的size个字节置为value
void memset(void *dst_, uint8_t value, uint32_t size) {
c000240a:	55                   	push   %ebp
c000240b:	89 e5                	mov    %esp,%ebp
c000240d:	83 ec 28             	sub    $0x28,%esp
c0002410:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002413:	88 45 e4             	mov    %al,-0x1c(%ebp)
  ASSERT(dst_ != NULL);
c0002416:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c000241a:	75 19                	jne    c0002435 <memset+0x2b>
c000241c:	68 1c 54 00 c0       	push   $0xc000541c
c0002421:	68 78 54 00 c0       	push   $0xc0005478
c0002426:	6a 08                	push   $0x8
c0002428:	68 29 54 00 c0       	push   $0xc0005429
c000242d:	e8 02 ff ff ff       	call   c0002334 <panic_spin>
c0002432:	83 c4 10             	add    $0x10,%esp
  uint8_t *dst = (uint8_t *)dst_;
c0002435:	8b 45 08             	mov    0x8(%ebp),%eax
c0002438:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while (size-- > 0) {
c000243b:	eb 0f                	jmp    c000244c <memset+0x42>
    *dst++ = value;
c000243d:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002440:	8d 50 01             	lea    0x1(%eax),%edx
c0002443:	89 55 f4             	mov    %edx,-0xc(%ebp)
c0002446:	0f b6 55 e4          	movzbl -0x1c(%ebp),%edx
c000244a:	88 10                	mov    %dl,(%eax)
  while (size-- > 0) {
c000244c:	8b 45 10             	mov    0x10(%ebp),%eax
c000244f:	8d 50 ff             	lea    -0x1(%eax),%edx
c0002452:	89 55 10             	mov    %edx,0x10(%ebp)
c0002455:	85 c0                	test   %eax,%eax
c0002457:	75 e4                	jne    c000243d <memset+0x33>
  }
}
c0002459:	90                   	nop
c000245a:	90                   	nop
c000245b:	c9                   	leave  
c000245c:	c3                   	ret    

c000245d <memcpy>:

// 内存数据拷贝=> 终止条件：size
// 将src_起始的size个字节复制到dst_
void memcpy(void *dst_, const void *src_, uint32_t size) {
c000245d:	55                   	push   %ebp
c000245e:	89 e5                	mov    %esp,%ebp
c0002460:	83 ec 18             	sub    $0x18,%esp
  ASSERT(dst_ != NULL && src_ != NULL);
c0002463:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c0002467:	74 06                	je     c000246f <memcpy+0x12>
c0002469:	83 7d 0c 00          	cmpl   $0x0,0xc(%ebp)
c000246d:	75 19                	jne    c0002488 <memcpy+0x2b>
c000246f:	68 36 54 00 c0       	push   $0xc0005436
c0002474:	68 80 54 00 c0       	push   $0xc0005480
c0002479:	6a 12                	push   $0x12
c000247b:	68 29 54 00 c0       	push   $0xc0005429
c0002480:	e8 af fe ff ff       	call   c0002334 <panic_spin>
c0002485:	83 c4 10             	add    $0x10,%esp
  uint8_t *dst = dst_;
c0002488:	8b 45 08             	mov    0x8(%ebp),%eax
c000248b:	89 45 f4             	mov    %eax,-0xc(%ebp)
  const uint8_t *src = src_;
c000248e:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002491:	89 45 f0             	mov    %eax,-0x10(%ebp)
  while (size-- > 0) {
c0002494:	eb 17                	jmp    c00024ad <memcpy+0x50>
    *dst++ = *src++;
c0002496:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0002499:	8d 42 01             	lea    0x1(%edx),%eax
c000249c:	89 45 f0             	mov    %eax,-0x10(%ebp)
c000249f:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00024a2:	8d 48 01             	lea    0x1(%eax),%ecx
c00024a5:	89 4d f4             	mov    %ecx,-0xc(%ebp)
c00024a8:	0f b6 12             	movzbl (%edx),%edx
c00024ab:	88 10                	mov    %dl,(%eax)
  while (size-- > 0) {
c00024ad:	8b 45 10             	mov    0x10(%ebp),%eax
c00024b0:	8d 50 ff             	lea    -0x1(%eax),%edx
c00024b3:	89 55 10             	mov    %edx,0x10(%ebp)
c00024b6:	85 c0                	test   %eax,%eax
c00024b8:	75 dc                	jne    c0002496 <memcpy+0x39>
  }
}
c00024ba:	90                   	nop
c00024bb:	90                   	nop
c00024bc:	c9                   	leave  
c00024bd:	c3                   	ret    

c00024be <memcmp>:

// 用于一段内存数据比较=>
// 连续比较以地址a_和b_开头的size个字节，相等返回0，a_>b_返回+1，否则返回−1
int memcmp(const void *a_, const void *b_, uint32_t size) {
c00024be:	55                   	push   %ebp
c00024bf:	89 e5                	mov    %esp,%ebp
c00024c1:	83 ec 18             	sub    $0x18,%esp
  const char *a = a_;
c00024c4:	8b 45 08             	mov    0x8(%ebp),%eax
c00024c7:	89 45 f4             	mov    %eax,-0xc(%ebp)
  const char *b = b_;
c00024ca:	8b 45 0c             	mov    0xc(%ebp),%eax
c00024cd:	89 45 f0             	mov    %eax,-0x10(%ebp)
  ASSERT(a != NULL && b != NULL);
c00024d0:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
c00024d4:	74 06                	je     c00024dc <memcmp+0x1e>
c00024d6:	83 7d f0 00          	cmpl   $0x0,-0x10(%ebp)
c00024da:	75 19                	jne    c00024f5 <memcmp+0x37>
c00024dc:	68 53 54 00 c0       	push   $0xc0005453
c00024e1:	68 88 54 00 c0       	push   $0xc0005488
c00024e6:	6a 1f                	push   $0x1f
c00024e8:	68 29 54 00 c0       	push   $0xc0005429
c00024ed:	e8 42 fe ff ff       	call   c0002334 <panic_spin>
c00024f2:	83 c4 10             	add    $0x10,%esp
  while (size-- > 0) {
c00024f5:	eb 36                	jmp    c000252d <memcmp+0x6f>
    if (*a != *b) {
c00024f7:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00024fa:	0f b6 10             	movzbl (%eax),%edx
c00024fd:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002500:	0f b6 00             	movzbl (%eax),%eax
c0002503:	38 c2                	cmp    %al,%dl
c0002505:	74 1e                	je     c0002525 <memcmp+0x67>
      return *a > *b ? 1 : -1;
c0002507:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000250a:	0f b6 10             	movzbl (%eax),%edx
c000250d:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002510:	0f b6 00             	movzbl (%eax),%eax
c0002513:	38 c2                	cmp    %al,%dl
c0002515:	7e 07                	jle    c000251e <memcmp+0x60>
c0002517:	b8 01 00 00 00       	mov    $0x1,%eax
c000251c:	eb 21                	jmp    c000253f <memcmp+0x81>
c000251e:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c0002523:	eb 1a                	jmp    c000253f <memcmp+0x81>
    }
    a++;
c0002525:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
    b++;
c0002529:	83 45 f0 01          	addl   $0x1,-0x10(%ebp)
  while (size-- > 0) {
c000252d:	8b 45 10             	mov    0x10(%ebp),%eax
c0002530:	8d 50 ff             	lea    -0x1(%eax),%edx
c0002533:	89 55 10             	mov    %edx,0x10(%ebp)
c0002536:	85 c0                	test   %eax,%eax
c0002538:	75 bd                	jne    c00024f7 <memcmp+0x39>
  }
  return 0;
c000253a:	b8 00 00 00 00       	mov    $0x0,%eax
}
c000253f:	c9                   	leave  
c0002540:	c3                   	ret    

c0002541 <strcpy>:

// 字符串拷贝=> 终止条件：src_处的字符‘0’
// 将字符串从src_复制到dst_
char *strcpy(char *dst_, const char *src_) {
c0002541:	55                   	push   %ebp
c0002542:	89 e5                	mov    %esp,%ebp
c0002544:	83 ec 18             	sub    $0x18,%esp
  ASSERT(dst_ != NULL && src_ != NULL);
c0002547:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c000254b:	74 06                	je     c0002553 <strcpy+0x12>
c000254d:	83 7d 0c 00          	cmpl   $0x0,0xc(%ebp)
c0002551:	75 19                	jne    c000256c <strcpy+0x2b>
c0002553:	68 36 54 00 c0       	push   $0xc0005436
c0002558:	68 90 54 00 c0       	push   $0xc0005490
c000255d:	6a 2d                	push   $0x2d
c000255f:	68 29 54 00 c0       	push   $0xc0005429
c0002564:	e8 cb fd ff ff       	call   c0002334 <panic_spin>
c0002569:	83 c4 10             	add    $0x10,%esp
  char *r = dst_; // 用来返回目的字符串dst_起始地址
c000256c:	8b 45 08             	mov    0x8(%ebp),%eax
c000256f:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while ((*dst_++ = *src_++))
c0002572:	90                   	nop
c0002573:	8b 55 0c             	mov    0xc(%ebp),%edx
c0002576:	8d 42 01             	lea    0x1(%edx),%eax
c0002579:	89 45 0c             	mov    %eax,0xc(%ebp)
c000257c:	8b 45 08             	mov    0x8(%ebp),%eax
c000257f:	8d 48 01             	lea    0x1(%eax),%ecx
c0002582:	89 4d 08             	mov    %ecx,0x8(%ebp)
c0002585:	0f b6 12             	movzbl (%edx),%edx
c0002588:	88 10                	mov    %dl,(%eax)
c000258a:	0f b6 00             	movzbl (%eax),%eax
c000258d:	84 c0                	test   %al,%al
c000258f:	75 e2                	jne    c0002573 <strcpy+0x32>
    ;
  return r;
c0002591:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0002594:	c9                   	leave  
c0002595:	c3                   	ret    

c0002596 <strlen>:

// 返回字符串长度
uint32_t strlen(const char *str) {
c0002596:	55                   	push   %ebp
c0002597:	89 e5                	mov    %esp,%ebp
c0002599:	83 ec 18             	sub    $0x18,%esp
  ASSERT(str != NULL);
c000259c:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c00025a0:	75 19                	jne    c00025bb <strlen+0x25>
c00025a2:	68 6a 54 00 c0       	push   $0xc000546a
c00025a7:	68 98 54 00 c0       	push   $0xc0005498
c00025ac:	6a 36                	push   $0x36
c00025ae:	68 29 54 00 c0       	push   $0xc0005429
c00025b3:	e8 7c fd ff ff       	call   c0002334 <panic_spin>
c00025b8:	83 c4 10             	add    $0x10,%esp
  const char *p = str;
c00025bb:	8b 45 08             	mov    0x8(%ebp),%eax
c00025be:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while (*p++)
c00025c1:	90                   	nop
c00025c2:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00025c5:	8d 50 01             	lea    0x1(%eax),%edx
c00025c8:	89 55 f4             	mov    %edx,-0xc(%ebp)
c00025cb:	0f b6 00             	movzbl (%eax),%eax
c00025ce:	84 c0                	test   %al,%al
c00025d0:	75 f0                	jne    c00025c2 <strlen+0x2c>
    ;
  return (p - str - 1);
c00025d2:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00025d5:	2b 45 08             	sub    0x8(%ebp),%eax
c00025d8:	83 e8 01             	sub    $0x1,%eax
}
c00025db:	c9                   	leave  
c00025dc:	c3                   	ret    

c00025dd <strcmp>:

// 比较两个字符串，若a_中字符大于b_返回1，相等返回0，否则返回−1
uint8_t strcmp(const char *a, const char *b) {
c00025dd:	55                   	push   %ebp
c00025de:	89 e5                	mov    %esp,%ebp
c00025e0:	83 ec 08             	sub    $0x8,%esp
  ASSERT(a != NULL && b != NULL);
c00025e3:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c00025e7:	74 06                	je     c00025ef <strcmp+0x12>
c00025e9:	83 7d 0c 00          	cmpl   $0x0,0xc(%ebp)
c00025ed:	75 19                	jne    c0002608 <strcmp+0x2b>
c00025ef:	68 53 54 00 c0       	push   $0xc0005453
c00025f4:	68 a0 54 00 c0       	push   $0xc00054a0
c00025f9:	6a 3f                	push   $0x3f
c00025fb:	68 29 54 00 c0       	push   $0xc0005429
c0002600:	e8 2f fd ff ff       	call   c0002334 <panic_spin>
c0002605:	83 c4 10             	add    $0x10,%esp
  while (*a != 0 && *a == *b) {
c0002608:	eb 08                	jmp    c0002612 <strcmp+0x35>
    a++;
c000260a:	83 45 08 01          	addl   $0x1,0x8(%ebp)
    b++;
c000260e:	83 45 0c 01          	addl   $0x1,0xc(%ebp)
  while (*a != 0 && *a == *b) {
c0002612:	8b 45 08             	mov    0x8(%ebp),%eax
c0002615:	0f b6 00             	movzbl (%eax),%eax
c0002618:	84 c0                	test   %al,%al
c000261a:	74 10                	je     c000262c <strcmp+0x4f>
c000261c:	8b 45 08             	mov    0x8(%ebp),%eax
c000261f:	0f b6 10             	movzbl (%eax),%edx
c0002622:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002625:	0f b6 00             	movzbl (%eax),%eax
c0002628:	38 c2                	cmp    %al,%dl
c000262a:	74 de                	je     c000260a <strcmp+0x2d>
  }
  return *a < *b ? -1 : *a > *b;
c000262c:	8b 45 08             	mov    0x8(%ebp),%eax
c000262f:	0f b6 10             	movzbl (%eax),%edx
c0002632:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002635:	0f b6 00             	movzbl (%eax),%eax
c0002638:	38 c2                	cmp    %al,%dl
c000263a:	7c 13                	jl     c000264f <strcmp+0x72>
c000263c:	8b 45 08             	mov    0x8(%ebp),%eax
c000263f:	0f b6 10             	movzbl (%eax),%edx
c0002642:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002645:	0f b6 00             	movzbl (%eax),%eax
c0002648:	38 c2                	cmp    %al,%dl
c000264a:	0f 9f c0             	setg   %al
c000264d:	eb 05                	jmp    c0002654 <strcmp+0x77>
c000264f:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
}
c0002654:	c9                   	leave  
c0002655:	c3                   	ret    

c0002656 <strchr>:

// 从左到右 查找字符串str中首次出现字符ch的地址
char *strchr(const char *str, const uint8_t ch) {
c0002656:	55                   	push   %ebp
c0002657:	89 e5                	mov    %esp,%ebp
c0002659:	83 ec 18             	sub    $0x18,%esp
c000265c:	8b 45 0c             	mov    0xc(%ebp),%eax
c000265f:	88 45 f4             	mov    %al,-0xc(%ebp)
  ASSERT(str != NULL);
c0002662:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c0002666:	75 35                	jne    c000269d <strchr+0x47>
c0002668:	68 6a 54 00 c0       	push   $0xc000546a
c000266d:	68 a8 54 00 c0       	push   $0xc00054a8
c0002672:	6a 49                	push   $0x49
c0002674:	68 29 54 00 c0       	push   $0xc0005429
c0002679:	e8 b6 fc ff ff       	call   c0002334 <panic_spin>
c000267e:	83 c4 10             	add    $0x10,%esp
  while (*str != 0) {
c0002681:	eb 1a                	jmp    c000269d <strchr+0x47>
    if (*str == ch) {
c0002683:	8b 45 08             	mov    0x8(%ebp),%eax
c0002686:	0f b6 00             	movzbl (%eax),%eax
c0002689:	0f be d0             	movsbl %al,%edx
c000268c:	0f b6 45 f4          	movzbl -0xc(%ebp),%eax
c0002690:	39 c2                	cmp    %eax,%edx
c0002692:	75 05                	jne    c0002699 <strchr+0x43>
      return (char *)str;
c0002694:	8b 45 08             	mov    0x8(%ebp),%eax
c0002697:	eb 13                	jmp    c00026ac <strchr+0x56>
    }
    str++;
c0002699:	83 45 08 01          	addl   $0x1,0x8(%ebp)
  while (*str != 0) {
c000269d:	8b 45 08             	mov    0x8(%ebp),%eax
c00026a0:	0f b6 00             	movzbl (%eax),%eax
c00026a3:	84 c0                	test   %al,%al
c00026a5:	75 dc                	jne    c0002683 <strchr+0x2d>
  }
  return NULL;
c00026a7:	b8 00 00 00 00       	mov    $0x0,%eax
}
c00026ac:	c9                   	leave  
c00026ad:	c3                   	ret    

c00026ae <strrchr>:

// 从后往前 查找字符串str中最后一次出现字符ch的地址
char *strrchr(const char *str, const uint8_t ch) {
c00026ae:	55                   	push   %ebp
c00026af:	89 e5                	mov    %esp,%ebp
c00026b1:	83 ec 28             	sub    $0x28,%esp
c00026b4:	8b 45 0c             	mov    0xc(%ebp),%eax
c00026b7:	88 45 e4             	mov    %al,-0x1c(%ebp)
  ASSERT(str != NULL);
c00026ba:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c00026be:	75 19                	jne    c00026d9 <strrchr+0x2b>
c00026c0:	68 6a 54 00 c0       	push   $0xc000546a
c00026c5:	68 b0 54 00 c0       	push   $0xc00054b0
c00026ca:	6a 55                	push   $0x55
c00026cc:	68 29 54 00 c0       	push   $0xc0005429
c00026d1:	e8 5e fc ff ff       	call   c0002334 <panic_spin>
c00026d6:	83 c4 10             	add    $0x10,%esp
  const char *last_char = NULL;
c00026d9:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  while (*str != 0) {
c00026e0:	eb 1b                	jmp    c00026fd <strrchr+0x4f>
    if (*str == ch) {
c00026e2:	8b 45 08             	mov    0x8(%ebp),%eax
c00026e5:	0f b6 00             	movzbl (%eax),%eax
c00026e8:	0f be d0             	movsbl %al,%edx
c00026eb:	0f b6 45 e4          	movzbl -0x1c(%ebp),%eax
c00026ef:	39 c2                	cmp    %eax,%edx
c00026f1:	75 06                	jne    c00026f9 <strrchr+0x4b>
      last_char = str;
c00026f3:	8b 45 08             	mov    0x8(%ebp),%eax
c00026f6:	89 45 f4             	mov    %eax,-0xc(%ebp)
    }
    str++;
c00026f9:	83 45 08 01          	addl   $0x1,0x8(%ebp)
  while (*str != 0) {
c00026fd:	8b 45 08             	mov    0x8(%ebp),%eax
c0002700:	0f b6 00             	movzbl (%eax),%eax
c0002703:	84 c0                	test   %al,%al
c0002705:	75 db                	jne    c00026e2 <strrchr+0x34>
  }
  return (char *)last_char;
c0002707:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c000270a:	c9                   	leave  
c000270b:	c3                   	ret    

c000270c <strcat>:

// 字符串拼接=>
// 将字符串src_拼接到dst_后，返回dst_地址
char *strcat(char *dst_, const char *src_) {
c000270c:	55                   	push   %ebp
c000270d:	89 e5                	mov    %esp,%ebp
c000270f:	83 ec 18             	sub    $0x18,%esp
  ASSERT(dst_ != NULL && src_ != NULL);
c0002712:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c0002716:	74 06                	je     c000271e <strcat+0x12>
c0002718:	83 7d 0c 00          	cmpl   $0x0,0xc(%ebp)
c000271c:	75 19                	jne    c0002737 <strcat+0x2b>
c000271e:	68 36 54 00 c0       	push   $0xc0005436
c0002723:	68 b8 54 00 c0       	push   $0xc00054b8
c0002728:	6a 63                	push   $0x63
c000272a:	68 29 54 00 c0       	push   $0xc0005429
c000272f:	e8 00 fc ff ff       	call   c0002334 <panic_spin>
c0002734:	83 c4 10             	add    $0x10,%esp
  char *str = dst_;
c0002737:	8b 45 08             	mov    0x8(%ebp),%eax
c000273a:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while (*str++)
c000273d:	90                   	nop
c000273e:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002741:	8d 50 01             	lea    0x1(%eax),%edx
c0002744:	89 55 f4             	mov    %edx,-0xc(%ebp)
c0002747:	0f b6 00             	movzbl (%eax),%eax
c000274a:	84 c0                	test   %al,%al
c000274c:	75 f0                	jne    c000273e <strcat+0x32>
    ;
  --str;
c000274e:	83 6d f4 01          	subl   $0x1,-0xc(%ebp)
  while ((*str++ = *src_++)) // 当*str被赋值0时
c0002752:	90                   	nop
c0002753:	8b 55 0c             	mov    0xc(%ebp),%edx
c0002756:	8d 42 01             	lea    0x1(%edx),%eax
c0002759:	89 45 0c             	mov    %eax,0xc(%ebp)
c000275c:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000275f:	8d 48 01             	lea    0x1(%eax),%ecx
c0002762:	89 4d f4             	mov    %ecx,-0xc(%ebp)
c0002765:	0f b6 12             	movzbl (%edx),%edx
c0002768:	88 10                	mov    %dl,(%eax)
c000276a:	0f b6 00             	movzbl (%eax),%eax
c000276d:	84 c0                	test   %al,%al
c000276f:	75 e2                	jne    c0002753 <strcat+0x47>
    ; //也就是表达式不成立，正好添加了字符串结尾的0
  return dst_;
c0002771:	8b 45 08             	mov    0x8(%ebp),%eax
}
c0002774:	c9                   	leave  
c0002775:	c3                   	ret    

c0002776 <strchrs>:

// 在字符串str中查找字符ch出现的次数
uint32_t strchrs(const char *str, uint8_t ch) {
c0002776:	55                   	push   %ebp
c0002777:	89 e5                	mov    %esp,%ebp
c0002779:	83 ec 28             	sub    $0x28,%esp
c000277c:	8b 45 0c             	mov    0xc(%ebp),%eax
c000277f:	88 45 e4             	mov    %al,-0x1c(%ebp)
  ASSERT(str != NULL);
c0002782:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c0002786:	75 19                	jne    c00027a1 <strchrs+0x2b>
c0002788:	68 6a 54 00 c0       	push   $0xc000546a
c000278d:	68 c0 54 00 c0       	push   $0xc00054c0
c0002792:	6a 6f                	push   $0x6f
c0002794:	68 29 54 00 c0       	push   $0xc0005429
c0002799:	e8 96 fb ff ff       	call   c0002334 <panic_spin>
c000279e:	83 c4 10             	add    $0x10,%esp
  uint32_t ch_cnt = 0;
c00027a1:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  const char *p = str;
c00027a8:	8b 45 08             	mov    0x8(%ebp),%eax
c00027ab:	89 45 f0             	mov    %eax,-0x10(%ebp)
  while (*p != 0) {
c00027ae:	eb 19                	jmp    c00027c9 <strchrs+0x53>
    if (*p == ch) {
c00027b0:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00027b3:	0f b6 00             	movzbl (%eax),%eax
c00027b6:	0f be d0             	movsbl %al,%edx
c00027b9:	0f b6 45 e4          	movzbl -0x1c(%ebp),%eax
c00027bd:	39 c2                	cmp    %eax,%edx
c00027bf:	75 04                	jne    c00027c5 <strchrs+0x4f>
      ch_cnt++;
c00027c1:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
    }
    p++;
c00027c5:	83 45 f0 01          	addl   $0x1,-0x10(%ebp)
  while (*p != 0) {
c00027c9:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00027cc:	0f b6 00             	movzbl (%eax),%eax
c00027cf:	84 c0                	test   %al,%al
c00027d1:	75 dd                	jne    c00027b0 <strchrs+0x3a>
  }
  return ch_cnt;
c00027d3:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c00027d6:	c9                   	leave  
c00027d7:	c3                   	ret    

c00027d8 <bitmap_init>:
#include "print.h"
#include "stdint.h"
#include "string.h"

// 初始化位图btmp
void bitmap_init(struct bitmap *btmp) {
c00027d8:	55                   	push   %ebp
c00027d9:	89 e5                	mov    %esp,%ebp
c00027db:	83 ec 08             	sub    $0x8,%esp
  memset(btmp->bits, 0, btmp->btmp_bytes_len);
c00027de:	8b 45 08             	mov    0x8(%ebp),%eax
c00027e1:	8b 10                	mov    (%eax),%edx
c00027e3:	8b 45 08             	mov    0x8(%ebp),%eax
c00027e6:	8b 40 04             	mov    0x4(%eax),%eax
c00027e9:	83 ec 04             	sub    $0x4,%esp
c00027ec:	52                   	push   %edx
c00027ed:	6a 00                	push   $0x0
c00027ef:	50                   	push   %eax
c00027f0:	e8 15 fc ff ff       	call   c000240a <memset>
c00027f5:	83 c4 10             	add    $0x10,%esp
}
c00027f8:	90                   	nop
c00027f9:	c9                   	leave  
c00027fa:	c3                   	ret    

c00027fb <bitmap_scan_test>:

// 判断bit_idx位是否为1，为1返回true，否则返回false
bool bitmap_scan_test(struct bitmap *btmp, uint32_t bit_idx) {
c00027fb:	55                   	push   %ebp
c00027fc:	89 e5                	mov    %esp,%ebp
c00027fe:	53                   	push   %ebx
c00027ff:	83 ec 10             	sub    $0x10,%esp
  uint32_t byte_idx = bit_idx / 8; // 向下取整用于索引数组下标
c0002802:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002805:	c1 e8 03             	shr    $0x3,%eax
c0002808:	89 45 f8             	mov    %eax,-0x8(%ebp)
  uint32_t bit_odd = bit_idx % 8;  //取余用于索引数组内的位
c000280b:	8b 45 0c             	mov    0xc(%ebp),%eax
c000280e:	83 e0 07             	and    $0x7,%eax
c0002811:	89 45 f4             	mov    %eax,-0xc(%ebp)
  return (btmp->bits[byte_idx] & (BITMAP_MASK << bit_odd));
c0002814:	8b 45 08             	mov    0x8(%ebp),%eax
c0002817:	8b 50 04             	mov    0x4(%eax),%edx
c000281a:	8b 45 f8             	mov    -0x8(%ebp),%eax
c000281d:	01 d0                	add    %edx,%eax
c000281f:	0f b6 00             	movzbl (%eax),%eax
c0002822:	0f b6 d0             	movzbl %al,%edx
c0002825:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002828:	bb 01 00 00 00       	mov    $0x1,%ebx
c000282d:	89 c1                	mov    %eax,%ecx
c000282f:	d3 e3                	shl    %cl,%ebx
c0002831:	89 d8                	mov    %ebx,%eax
c0002833:	21 d0                	and    %edx,%eax
}
c0002835:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c0002838:	c9                   	leave  
c0002839:	c3                   	ret    

c000283a <bitmap_scan>:

// 在位图中申请cnt个位，成功返回其起始下标地址，失败返回-1
int bitmap_scan(struct bitmap *btmp, uint32_t cnt) {
c000283a:	55                   	push   %ebp
c000283b:	89 e5                	mov    %esp,%ebp
c000283d:	83 ec 28             	sub    $0x28,%esp
  uint32_t idx_byte = 0; //用于记录空闲位所在字节索引
c0002840:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  //逐个字节比较
  while ((0xff == btmp->bits[idx_byte]) && (idx_byte < btmp->btmp_bytes_len)) {
c0002847:	eb 04                	jmp    c000284d <bitmap_scan+0x13>
    // 0xff表示该字节内已无空闲位，继续下一个字节
    idx_byte++;
c0002849:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
  while ((0xff == btmp->bits[idx_byte]) && (idx_byte < btmp->btmp_bytes_len)) {
c000284d:	8b 45 08             	mov    0x8(%ebp),%eax
c0002850:	8b 50 04             	mov    0x4(%eax),%edx
c0002853:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002856:	01 d0                	add    %edx,%eax
c0002858:	0f b6 00             	movzbl (%eax),%eax
c000285b:	3c ff                	cmp    $0xff,%al
c000285d:	75 0a                	jne    c0002869 <bitmap_scan+0x2f>
c000285f:	8b 45 08             	mov    0x8(%ebp),%eax
c0002862:	8b 00                	mov    (%eax),%eax
c0002864:	39 45 f4             	cmp    %eax,-0xc(%ebp)
c0002867:	72 e0                	jb     c0002849 <bitmap_scan+0xf>
  }

  ASSERT(idx_byte < btmp->btmp_bytes_len);
c0002869:	8b 45 08             	mov    0x8(%ebp),%eax
c000286c:	8b 00                	mov    (%eax),%eax
c000286e:	39 45 f4             	cmp    %eax,-0xc(%ebp)
c0002871:	72 19                	jb     c000288c <bitmap_scan+0x52>
c0002873:	68 c8 54 00 c0       	push   $0xc00054c8
c0002878:	68 1c 55 00 c0       	push   $0xc000551c
c000287d:	6a 1d                	push   $0x1d
c000287f:	68 e8 54 00 c0       	push   $0xc00054e8
c0002884:	e8 ab fa ff ff       	call   c0002334 <panic_spin>
c0002889:	83 c4 10             	add    $0x10,%esp
  if (idx_byte == btmp->btmp_bytes_len) { //该内存池已找不到空间
c000288c:	8b 45 08             	mov    0x8(%ebp),%eax
c000288f:	8b 00                	mov    (%eax),%eax
c0002891:	39 45 f4             	cmp    %eax,-0xc(%ebp)
c0002894:	75 0a                	jne    c00028a0 <bitmap_scan+0x66>
    return -1;
c0002896:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
c000289b:	e9 c3 00 00 00       	jmp    c0002963 <bitmap_scan+0x129>
  }

  //在位图数组范围内的某字节内找到了空闲位，在该字节内逐位比对，返回空闲位的索引
  int idx_bit = 0; // 字节内的索引(范围0-7)
c00028a0:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
  while ((uint8_t)(BITMAP_MASK << idx_bit) & btmp->bits[idx_byte]) {
c00028a7:	eb 04                	jmp    c00028ad <bitmap_scan+0x73>
    idx_bit++;
c00028a9:	83 45 f0 01          	addl   $0x1,-0x10(%ebp)
  while ((uint8_t)(BITMAP_MASK << idx_bit) & btmp->bits[idx_byte]) {
c00028ad:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00028b0:	ba 01 00 00 00       	mov    $0x1,%edx
c00028b5:	89 c1                	mov    %eax,%ecx
c00028b7:	d3 e2                	shl    %cl,%edx
c00028b9:	89 d0                	mov    %edx,%eax
c00028bb:	89 c1                	mov    %eax,%ecx
c00028bd:	8b 45 08             	mov    0x8(%ebp),%eax
c00028c0:	8b 50 04             	mov    0x4(%eax),%edx
c00028c3:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00028c6:	01 d0                	add    %edx,%eax
c00028c8:	0f b6 00             	movzbl (%eax),%eax
c00028cb:	21 c8                	and    %ecx,%eax
c00028cd:	84 c0                	test   %al,%al
c00028cf:	75 d8                	jne    c00028a9 <bitmap_scan+0x6f>
  }

  int bit_idx_start = idx_byte * 8 + idx_bit; // 空闲位在位图内的下标
c00028d1:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00028d4:	8d 14 c5 00 00 00 00 	lea    0x0(,%eax,8),%edx
c00028db:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00028de:	01 d0                	add    %edx,%eax
c00028e0:	89 45 ec             	mov    %eax,-0x14(%ebp)
  if (cnt == 1) {
c00028e3:	83 7d 0c 01          	cmpl   $0x1,0xc(%ebp)
c00028e7:	75 05                	jne    c00028ee <bitmap_scan+0xb4>
    return bit_idx_start;
c00028e9:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00028ec:	eb 75                	jmp    c0002963 <bitmap_scan+0x129>
  }

  uint32_t bit_left = (btmp->btmp_bytes_len * 8 - bit_idx_start);
c00028ee:	8b 45 08             	mov    0x8(%ebp),%eax
c00028f1:	8b 00                	mov    (%eax),%eax
c00028f3:	c1 e0 03             	shl    $0x3,%eax
c00028f6:	8b 55 ec             	mov    -0x14(%ebp),%edx
c00028f9:	29 d0                	sub    %edx,%eax
c00028fb:	89 45 e8             	mov    %eax,-0x18(%ebp)
  // 记录还有多少位可以判断
  uint32_t next_bit = bit_idx_start + 1;
c00028fe:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002901:	83 c0 01             	add    $0x1,%eax
c0002904:	89 45 e4             	mov    %eax,-0x1c(%ebp)
  uint32_t count = 1; //用于记录找到的空闲位数
c0002907:	c7 45 e0 01 00 00 00 	movl   $0x1,-0x20(%ebp)

  bit_idx_start = -1; // 先将其置为-1，若找不到连续的位置就直接返回
c000290e:	c7 45 ec ff ff ff ff 	movl   $0xffffffff,-0x14(%ebp)
  while (bit_left-- > 0) {
c0002915:	eb 3c                	jmp    c0002953 <bitmap_scan+0x119>
    if (!(bitmap_scan_test(btmp, next_bit))) { //如果next_bit为0
c0002917:	83 ec 08             	sub    $0x8,%esp
c000291a:	ff 75 e4             	push   -0x1c(%ebp)
c000291d:	ff 75 08             	push   0x8(%ebp)
c0002920:	e8 d6 fe ff ff       	call   c00027fb <bitmap_scan_test>
c0002925:	83 c4 10             	add    $0x10,%esp
c0002928:	85 c0                	test   %eax,%eax
c000292a:	75 06                	jne    c0002932 <bitmap_scan+0xf8>
      count++;
c000292c:	83 45 e0 01          	addl   $0x1,-0x20(%ebp)
c0002930:	eb 07                	jmp    c0002939 <bitmap_scan+0xff>
    } else {
      count = 0;
c0002932:	c7 45 e0 00 00 00 00 	movl   $0x0,-0x20(%ebp)
    }
    if (count == cnt) { // 若找到连续的cnt个空位
c0002939:	8b 45 e0             	mov    -0x20(%ebp),%eax
c000293c:	3b 45 0c             	cmp    0xc(%ebp),%eax
c000293f:	75 0e                	jne    c000294f <bitmap_scan+0x115>
      bit_idx_start = next_bit - cnt + 1;
c0002941:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0002944:	2b 45 0c             	sub    0xc(%ebp),%eax
c0002947:	83 c0 01             	add    $0x1,%eax
c000294a:	89 45 ec             	mov    %eax,-0x14(%ebp)
      break;
c000294d:	eb 11                	jmp    c0002960 <bitmap_scan+0x126>
    }
    next_bit++;
c000294f:	83 45 e4 01          	addl   $0x1,-0x1c(%ebp)
  while (bit_left-- > 0) {
c0002953:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002956:	8d 50 ff             	lea    -0x1(%eax),%edx
c0002959:	89 55 e8             	mov    %edx,-0x18(%ebp)
c000295c:	85 c0                	test   %eax,%eax
c000295e:	75 b7                	jne    c0002917 <bitmap_scan+0xdd>
  }
  return bit_idx_start;
c0002960:	8b 45 ec             	mov    -0x14(%ebp),%eax
}
c0002963:	c9                   	leave  
c0002964:	c3                   	ret    

c0002965 <bitmap_set>:

// 将位图的btmp的bit_idx位设置为value
void bitmap_set(struct bitmap *btmp, uint32_t bit_idx, int8_t value) {
c0002965:	55                   	push   %ebp
c0002966:	89 e5                	mov    %esp,%ebp
c0002968:	53                   	push   %ebx
c0002969:	83 ec 24             	sub    $0x24,%esp
c000296c:	8b 45 10             	mov    0x10(%ebp),%eax
c000296f:	88 45 e4             	mov    %al,-0x1c(%ebp)
  ASSERT((value == 0) || (value == 1));
c0002972:	80 7d e4 00          	cmpb   $0x0,-0x1c(%ebp)
c0002976:	74 1f                	je     c0002997 <bitmap_set+0x32>
c0002978:	80 7d e4 01          	cmpb   $0x1,-0x1c(%ebp)
c000297c:	74 19                	je     c0002997 <bitmap_set+0x32>
c000297e:	68 fc 54 00 c0       	push   $0xc00054fc
c0002983:	68 28 55 00 c0       	push   $0xc0005528
c0002988:	6a 44                	push   $0x44
c000298a:	68 e8 54 00 c0       	push   $0xc00054e8
c000298f:	e8 a0 f9 ff ff       	call   c0002334 <panic_spin>
c0002994:	83 c4 10             	add    $0x10,%esp
  uint32_t byte_idx = bit_idx / 8; //向下取整用于索引数组下标
c0002997:	8b 45 0c             	mov    0xc(%ebp),%eax
c000299a:	c1 e8 03             	shr    $0x3,%eax
c000299d:	89 45 f4             	mov    %eax,-0xc(%ebp)
  uint32_t bit_odd = bit_idx % 8;  // 取余用于索引数组内的位
c00029a0:	8b 45 0c             	mov    0xc(%ebp),%eax
c00029a3:	83 e0 07             	and    $0x7,%eax
c00029a6:	89 45 f0             	mov    %eax,-0x10(%ebp)

  // 一般用0x1这样的数对字节中的位操作，将1任意移动后再取反，或者先取反再移位，可用来对位置0操作
  if (value) { // value==1
c00029a9:	80 7d e4 00          	cmpb   $0x0,-0x1c(%ebp)
c00029ad:	74 33                	je     c00029e2 <bitmap_set+0x7d>
    btmp->bits[byte_idx] |= (BITMAP_MASK << bit_odd);
c00029af:	8b 45 08             	mov    0x8(%ebp),%eax
c00029b2:	8b 50 04             	mov    0x4(%eax),%edx
c00029b5:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00029b8:	01 d0                	add    %edx,%eax
c00029ba:	0f b6 00             	movzbl (%eax),%eax
c00029bd:	89 c3                	mov    %eax,%ebx
c00029bf:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00029c2:	ba 01 00 00 00       	mov    $0x1,%edx
c00029c7:	89 c1                	mov    %eax,%ecx
c00029c9:	d3 e2                	shl    %cl,%edx
c00029cb:	89 d0                	mov    %edx,%eax
c00029cd:	09 c3                	or     %eax,%ebx
c00029cf:	89 d9                	mov    %ebx,%ecx
c00029d1:	8b 45 08             	mov    0x8(%ebp),%eax
c00029d4:	8b 50 04             	mov    0x4(%eax),%edx
c00029d7:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00029da:	01 d0                	add    %edx,%eax
c00029dc:	89 ca                	mov    %ecx,%edx
c00029de:	88 10                	mov    %dl,(%eax)
  } else {
    btmp->bits[byte_idx] &= ~(BITMAP_MASK << bit_odd);
  }
c00029e0:	eb 33                	jmp    c0002a15 <bitmap_set+0xb0>
    btmp->bits[byte_idx] &= ~(BITMAP_MASK << bit_odd);
c00029e2:	8b 45 08             	mov    0x8(%ebp),%eax
c00029e5:	8b 50 04             	mov    0x4(%eax),%edx
c00029e8:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00029eb:	01 d0                	add    %edx,%eax
c00029ed:	0f b6 00             	movzbl (%eax),%eax
c00029f0:	89 c3                	mov    %eax,%ebx
c00029f2:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00029f5:	ba 01 00 00 00       	mov    $0x1,%edx
c00029fa:	89 c1                	mov    %eax,%ecx
c00029fc:	d3 e2                	shl    %cl,%edx
c00029fe:	89 d0                	mov    %edx,%eax
c0002a00:	f7 d0                	not    %eax
c0002a02:	21 c3                	and    %eax,%ebx
c0002a04:	89 d9                	mov    %ebx,%ecx
c0002a06:	8b 45 08             	mov    0x8(%ebp),%eax
c0002a09:	8b 50 04             	mov    0x4(%eax),%edx
c0002a0c:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002a0f:	01 d0                	add    %edx,%eax
c0002a11:	89 ca                	mov    %ecx,%edx
c0002a13:	88 10                	mov    %dl,(%eax)
c0002a15:	90                   	nop
c0002a16:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c0002a19:	c9                   	leave  
c0002a1a:	c3                   	ret    

c0002a1b <vaddr_get>:
};
struct pool kernel_pool, user_pool;
struct virtual_addr kernel_vaddr; // 用来给内核分配虚拟地址

// 在虚拟内存池（pf指定类型）中申请pg_cnt个虚拟页
static void *vaddr_get(enum pool_flags pf, uint32_t pg_cnt) {
c0002a1b:	55                   	push   %ebp
c0002a1c:	89 e5                	mov    %esp,%ebp
c0002a1e:	83 ec 18             	sub    $0x18,%esp
  int vaddr_start = 0, bit_idx_start = -1;
c0002a21:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
c0002a28:	c7 45 ec ff ff ff ff 	movl   $0xffffffff,-0x14(%ebp)
  uint32_t cnt = 0;
c0002a2f:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)

  if (pf == PF_KERNEL) {
c0002a36:	83 7d 08 01          	cmpl   $0x1,0x8(%ebp)
c0002a3a:	75 65                	jne    c0002aa1 <vaddr_get+0x86>
    bit_idx_start = bitmap_scan(&kernel_vaddr.vaddr_bitmap, pg_cnt);
c0002a3c:	83 ec 08             	sub    $0x8,%esp
c0002a3f:	ff 75 0c             	push   0xc(%ebp)
c0002a42:	68 4c 8a 00 c0       	push   $0xc0008a4c
c0002a47:	e8 ee fd ff ff       	call   c000283a <bitmap_scan>
c0002a4c:	83 c4 10             	add    $0x10,%esp
c0002a4f:	89 45 ec             	mov    %eax,-0x14(%ebp)
    if (bit_idx_start == -1) {
c0002a52:	83 7d ec ff          	cmpl   $0xffffffff,-0x14(%ebp)
c0002a56:	75 2b                	jne    c0002a83 <vaddr_get+0x68>
      return NULL; // 失败
c0002a58:	b8 00 00 00 00       	mov    $0x0,%eax
c0002a5d:	e9 ce 00 00 00       	jmp    c0002b30 <vaddr_get+0x115>
    }
    while (cnt < pg_cnt) {
      bitmap_set(&kernel_vaddr.vaddr_bitmap, bit_idx_start + cnt++, 1);
c0002a62:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002a65:	8d 50 01             	lea    0x1(%eax),%edx
c0002a68:	89 55 f0             	mov    %edx,-0x10(%ebp)
c0002a6b:	8b 55 ec             	mov    -0x14(%ebp),%edx
c0002a6e:	01 d0                	add    %edx,%eax
c0002a70:	83 ec 04             	sub    $0x4,%esp
c0002a73:	6a 01                	push   $0x1
c0002a75:	50                   	push   %eax
c0002a76:	68 4c 8a 00 c0       	push   $0xc0008a4c
c0002a7b:	e8 e5 fe ff ff       	call   c0002965 <bitmap_set>
c0002a80:	83 c4 10             	add    $0x10,%esp
    while (cnt < pg_cnt) {
c0002a83:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002a86:	3b 45 0c             	cmp    0xc(%ebp),%eax
c0002a89:	72 d7                	jb     c0002a62 <vaddr_get+0x47>
    }
    // 将bit_idx_start转为虚拟地址
    vaddr_start = kernel_vaddr.vaddr_start + bit_idx_start * PG_SIZE;
c0002a8b:	8b 15 54 8a 00 c0    	mov    0xc0008a54,%edx
c0002a91:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002a94:	c1 e0 0c             	shl    $0xc,%eax
c0002a97:	01 d0                	add    %edx,%eax
c0002a99:	89 45 f4             	mov    %eax,-0xc(%ebp)
c0002a9c:	e9 8c 00 00 00       	jmp    c0002b2d <vaddr_get+0x112>
  } else {
    struct task_struct *cur = running_thread();
c0002aa1:	e8 60 07 00 00       	call   c0003206 <running_thread>
c0002aa6:	89 45 e8             	mov    %eax,-0x18(%ebp)
    bit_idx_start = bitmap_scan(&cur->userprog_vaddr.vaddr_bitmap, pg_cnt);
c0002aa9:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002aac:	83 c0 38             	add    $0x38,%eax
c0002aaf:	83 ec 08             	sub    $0x8,%esp
c0002ab2:	ff 75 0c             	push   0xc(%ebp)
c0002ab5:	50                   	push   %eax
c0002ab6:	e8 7f fd ff ff       	call   c000283a <bitmap_scan>
c0002abb:	83 c4 10             	add    $0x10,%esp
c0002abe:	89 45 ec             	mov    %eax,-0x14(%ebp)
    if (bit_idx_start == -1) {
c0002ac1:	83 7d ec ff          	cmpl   $0xffffffff,-0x14(%ebp)
c0002ac5:	75 2a                	jne    c0002af1 <vaddr_get+0xd6>
      return NULL;
c0002ac7:	b8 00 00 00 00       	mov    $0x0,%eax
c0002acc:	eb 62                	jmp    c0002b30 <vaddr_get+0x115>
    }

    while (cnt < pg_cnt) {
      bitmap_set(&cur->userprog_vaddr.vaddr_bitmap, bit_idx_start + cnt++, 1);
c0002ace:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002ad1:	8d 50 01             	lea    0x1(%eax),%edx
c0002ad4:	89 55 f0             	mov    %edx,-0x10(%ebp)
c0002ad7:	8b 55 ec             	mov    -0x14(%ebp),%edx
c0002ada:	01 c2                	add    %eax,%edx
c0002adc:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002adf:	83 c0 38             	add    $0x38,%eax
c0002ae2:	83 ec 04             	sub    $0x4,%esp
c0002ae5:	6a 01                	push   $0x1
c0002ae7:	52                   	push   %edx
c0002ae8:	50                   	push   %eax
c0002ae9:	e8 77 fe ff ff       	call   c0002965 <bitmap_set>
c0002aee:	83 c4 10             	add    $0x10,%esp
    while (cnt < pg_cnt) {
c0002af1:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002af4:	3b 45 0c             	cmp    0xc(%ebp),%eax
c0002af7:	72 d5                	jb     c0002ace <vaddr_get+0xb3>
    }
    vaddr_start = cur->userprog_vaddr.vaddr_start + bit_idx_start * PG_SIZE;
c0002af9:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002afc:	8b 50 40             	mov    0x40(%eax),%edx
c0002aff:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002b02:	c1 e0 0c             	shl    $0xc,%eax
c0002b05:	01 d0                	add    %edx,%eax
c0002b07:	89 45 f4             	mov    %eax,-0xc(%ebp)

    // (0xc0000000-PG_SIZE)-> 用户3级栈
    ASSERT((uint32_t)vaddr_start < (0xc0000000 - PG_SIZE));
c0002b0a:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002b0d:	3d ff ef ff bf       	cmp    $0xbfffefff,%eax
c0002b12:	76 19                	jbe    c0002b2d <vaddr_get+0x112>
c0002b14:	68 34 55 00 c0       	push   $0xc0005534
c0002b19:	68 dc 56 00 c0       	push   $0xc00056dc
c0002b1e:	6a 3c                	push   $0x3c
c0002b20:	68 63 55 00 c0       	push   $0xc0005563
c0002b25:	e8 0a f8 ff ff       	call   c0002334 <panic_spin>
c0002b2a:	83 c4 10             	add    $0x10,%esp
  }
  return (void *)vaddr_start;
c0002b2d:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0002b30:	c9                   	leave  
c0002b31:	c3                   	ret    

c0002b32 <pte_ptr>:

// 得到虚拟地址对应的pte指针
uint32_t *pte_ptr(uint32_t vaddr) {
c0002b32:	55                   	push   %ebp
c0002b33:	89 e5                	mov    %esp,%ebp
c0002b35:	83 ec 10             	sub    $0x10,%esp
  /* 先访问到页表自己
   * 再用页目录项 pde（页目录内页表的索引）作为 pte 的索引访问到页表
   * 再用 pte 的索引作为页内偏移
   */
  uint32_t *pte = (uint32_t *)(0xffc00000 + ((vaddr & 0xffc00000) >> 10) +
c0002b38:	8b 45 08             	mov    0x8(%ebp),%eax
c0002b3b:	c1 e8 0a             	shr    $0xa,%eax
c0002b3e:	25 00 f0 3f 00       	and    $0x3ff000,%eax
c0002b43:	89 c2                	mov    %eax,%edx
                               PTE_IDX(vaddr) * 4);
c0002b45:	8b 45 08             	mov    0x8(%ebp),%eax
c0002b48:	c1 e8 0c             	shr    $0xc,%eax
c0002b4b:	25 ff 03 00 00       	and    $0x3ff,%eax
c0002b50:	c1 e0 02             	shl    $0x2,%eax
  uint32_t *pte = (uint32_t *)(0xffc00000 + ((vaddr & 0xffc00000) >> 10) +
c0002b53:	01 d0                	add    %edx,%eax
c0002b55:	2d 00 00 40 00       	sub    $0x400000,%eax
c0002b5a:	89 45 fc             	mov    %eax,-0x4(%ebp)
  return pte;
c0002b5d:	8b 45 fc             	mov    -0x4(%ebp),%eax
}
c0002b60:	c9                   	leave  
c0002b61:	c3                   	ret    

c0002b62 <pde_ptr>:

// 得到虚拟地址对应的pde指针
uint32_t *pde_ptr(uint32_t vaddr) {
c0002b62:	55                   	push   %ebp
c0002b63:	89 e5                	mov    %esp,%ebp
c0002b65:	83 ec 10             	sub    $0x10,%esp
  // 0xfffff用来访问到页表本身所在的地址
  uint32_t *pde = (uint32_t *)((0xfffff000) + PDE_IDX(vaddr) * 4);
c0002b68:	8b 45 08             	mov    0x8(%ebp),%eax
c0002b6b:	c1 e8 16             	shr    $0x16,%eax
c0002b6e:	05 00 fc ff 3f       	add    $0x3ffffc00,%eax
c0002b73:	c1 e0 02             	shl    $0x2,%eax
c0002b76:	89 45 fc             	mov    %eax,-0x4(%ebp)
  return pde;
c0002b79:	8b 45 fc             	mov    -0x4(%ebp),%eax
}
c0002b7c:	c9                   	leave  
c0002b7d:	c3                   	ret    

c0002b7e <palloc>:

// 在m_pool指向的物理内存池中分配1个物理页
static void *palloc(struct pool *m_pool) {
c0002b7e:	55                   	push   %ebp
c0002b7f:	89 e5                	mov    %esp,%ebp
c0002b81:	83 ec 18             	sub    $0x18,%esp
  /* 扫描或设置位图要保证原子操作 */
  int bit_idx = bitmap_scan(&m_pool->pool_bitmap, 1); // 找一个物理页面
c0002b84:	8b 45 08             	mov    0x8(%ebp),%eax
c0002b87:	83 ec 08             	sub    $0x8,%esp
c0002b8a:	6a 01                	push   $0x1
c0002b8c:	50                   	push   %eax
c0002b8d:	e8 a8 fc ff ff       	call   c000283a <bitmap_scan>
c0002b92:	83 c4 10             	add    $0x10,%esp
c0002b95:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (bit_idx == -1) {
c0002b98:	83 7d f4 ff          	cmpl   $0xffffffff,-0xc(%ebp)
c0002b9c:	75 07                	jne    c0002ba5 <palloc+0x27>
    return NULL; // 失败
c0002b9e:	b8 00 00 00 00       	mov    $0x0,%eax
c0002ba3:	eb 2b                	jmp    c0002bd0 <palloc+0x52>
  }
  bitmap_set(&m_pool->pool_bitmap, bit_idx, 1);
c0002ba5:	8b 55 f4             	mov    -0xc(%ebp),%edx
c0002ba8:	8b 45 08             	mov    0x8(%ebp),%eax
c0002bab:	83 ec 04             	sub    $0x4,%esp
c0002bae:	6a 01                	push   $0x1
c0002bb0:	52                   	push   %edx
c0002bb1:	50                   	push   %eax
c0002bb2:	e8 ae fd ff ff       	call   c0002965 <bitmap_set>
c0002bb7:	83 c4 10             	add    $0x10,%esp
  uint32_t page_phyaddr = // 分配的物理页地址
      ((bit_idx * PG_SIZE) + m_pool->phy_addr_start);
c0002bba:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002bbd:	c1 e0 0c             	shl    $0xc,%eax
c0002bc0:	89 c2                	mov    %eax,%edx
c0002bc2:	8b 45 08             	mov    0x8(%ebp),%eax
c0002bc5:	8b 40 08             	mov    0x8(%eax),%eax
  uint32_t page_phyaddr = // 分配的物理页地址
c0002bc8:	01 d0                	add    %edx,%eax
c0002bca:	89 45 f0             	mov    %eax,-0x10(%ebp)
  return (void *)page_phyaddr;
c0002bcd:	8b 45 f0             	mov    -0x10(%ebp),%eax
}
c0002bd0:	c9                   	leave  
c0002bd1:	c3                   	ret    

c0002bd2 <page_table_add>:

// 页表中添加虚拟地址与物理地址的映射
static void page_table_add(void *_vaddr, void *_page_phyaddr) {
c0002bd2:	55                   	push   %ebp
c0002bd3:	89 e5                	mov    %esp,%ebp
c0002bd5:	83 ec 28             	sub    $0x28,%esp
  uint32_t vaddr = (uint32_t)_vaddr, page_phyaddr = (uint32_t)_page_phyaddr;
c0002bd8:	8b 45 08             	mov    0x8(%ebp),%eax
c0002bdb:	89 45 f4             	mov    %eax,-0xc(%ebp)
c0002bde:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002be1:	89 45 f0             	mov    %eax,-0x10(%ebp)
  uint32_t *pde = pde_ptr(vaddr);
c0002be4:	ff 75 f4             	push   -0xc(%ebp)
c0002be7:	e8 76 ff ff ff       	call   c0002b62 <pde_ptr>
c0002bec:	83 c4 04             	add    $0x4,%esp
c0002bef:	89 45 ec             	mov    %eax,-0x14(%ebp)
  uint32_t *pte = pte_ptr(vaddr);
c0002bf2:	ff 75 f4             	push   -0xc(%ebp)
c0002bf5:	e8 38 ff ff ff       	call   c0002b32 <pte_ptr>
c0002bfa:	83 c4 04             	add    $0x4,%esp
c0002bfd:	89 45 e8             	mov    %eax,-0x18(%ebp)

  // 在页目录表内判断目录项的P位，为1表示该表已存在
  if (*pde & 0x00000001) {
c0002c00:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002c03:	8b 00                	mov    (%eax),%eax
c0002c05:	83 e0 01             	and    $0x1,%eax
c0002c08:	85 c0                	test   %eax,%eax
c0002c0a:	74 6b                	je     c0002c77 <page_table_add+0xa5>
    ASSERT(!(*pte & 0x00000001));
c0002c0c:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002c0f:	8b 00                	mov    (%eax),%eax
c0002c11:	83 e0 01             	and    $0x1,%eax
c0002c14:	85 c0                	test   %eax,%eax
c0002c16:	74 19                	je     c0002c31 <page_table_add+0x5f>
c0002c18:	68 73 55 00 c0       	push   $0xc0005573
c0002c1d:	68 e8 56 00 c0       	push   $0xc00056e8
c0002c22:	6a 68                	push   $0x68
c0002c24:	68 63 55 00 c0       	push   $0xc0005563
c0002c29:	e8 06 f7 ff ff       	call   c0002334 <panic_spin>
c0002c2e:	83 c4 10             	add    $0x10,%esp
    if (!(*pte & 0x00000001)) {
c0002c31:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002c34:	8b 00                	mov    (%eax),%eax
c0002c36:	83 e0 01             	and    $0x1,%eax
c0002c39:	85 c0                	test   %eax,%eax
c0002c3b:	75 12                	jne    c0002c4f <page_table_add+0x7d>
      *pte = (page_phyaddr | PG_US_U | PG_RW_W | PG_P_1); // US=1,RW=1,P=1
c0002c3d:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002c40:	83 c8 07             	or     $0x7,%eax
c0002c43:	89 c2                	mov    %eax,%edx
c0002c45:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002c48:	89 10                	mov    %edx,(%eax)
    // 取高20位，低12位置0
    memset((void *)((int)pte & 0xfffff000), 0, PG_SIZE);
    ASSERT(!(*pte & 0x00000001));
    *pte = (page_phyaddr | PG_US_U | PG_RW_W | PG_P_1); // US=1,RW=1,P=1
  }
}
c0002c4a:	e9 95 00 00 00       	jmp    c0002ce4 <page_table_add+0x112>
      PANIC("pte repeat");
c0002c4f:	68 88 55 00 c0       	push   $0xc0005588
c0002c54:	68 e8 56 00 c0       	push   $0xc00056e8
c0002c59:	6a 6d                	push   $0x6d
c0002c5b:	68 63 55 00 c0       	push   $0xc0005563
c0002c60:	e8 cf f6 ff ff       	call   c0002334 <panic_spin>
c0002c65:	83 c4 10             	add    $0x10,%esp
      *pte = (page_phyaddr | PG_US_U | PG_RW_W | PG_P_1); // US=1,RW=1,P=1
c0002c68:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0002c6b:	83 c8 07             	or     $0x7,%eax
c0002c6e:	89 c2                	mov    %eax,%edx
c0002c70:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002c73:	89 10                	mov    %edx,(%eax)
}
c0002c75:	eb 6d                	jmp    c0002ce4 <page_table_add+0x112>
    uint32_t pde_pyhaddr = (uint32_t)palloc(&kernel_pool);
c0002c77:	83 ec 0c             	sub    $0xc,%esp
c0002c7a:	68 e0 89 00 c0       	push   $0xc00089e0
c0002c7f:	e8 fa fe ff ff       	call   c0002b7e <palloc>
c0002c84:	83 c4 10             	add    $0x10,%esp
c0002c87:	89 45 e4             	mov    %eax,-0x1c(%ebp)
    *pde = (pde_pyhaddr | PG_US_U | PG_RW_W | PG_P_1);
c0002c8a:	8b 45 e4             	mov    -0x1c(%ebp),%eax
c0002c8d:	83 c8 07             	or     $0x7,%eax
c0002c90:	89 c2                	mov    %eax,%edx
c0002c92:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002c95:	89 10                	mov    %edx,(%eax)
    memset((void *)((int)pte & 0xfffff000), 0, PG_SIZE);
c0002c97:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002c9a:	25 00 f0 ff ff       	and    $0xfffff000,%eax
c0002c9f:	83 ec 04             	sub    $0x4,%esp
c0002ca2:	68 00 10 00 00       	push   $0x1000
c0002ca7:	6a 00                	push   $0x0
c0002ca9:	50                   	push   %eax
c0002caa:	e8 5b f7 ff ff       	call   c000240a <memset>
c0002caf:	83 c4 10             	add    $0x10,%esp
    ASSERT(!(*pte & 0x00000001));
c0002cb2:	8b 45 e8             	mov    -0x18(%ebp),%eax
c0002cb5:	8b 00                	mov    (%eax),%eax
c0002cb7:	83 e0 01             	and    $0x1,%eax
c0002cba:	85 c0                	test   %eax,%eax
c0002cbc:	74 19                	je     c0002cd7 <page_table_add+0x105>
c0002cbe:	68 73 55 00 c0       	push   $0xc0005573
c0002cc3:	68 e8 56 00 c0       	push   $0xc00056e8
c0002cc8:	6a 77                	push   $0x77
c0002cca:	68 63 55 00 c0       	push   $0xc0005563
c0002ccf:	e8 60 f6 ff ff       	call   c0002334 <panic_spin>
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
c0002cfc:	68 93 55 00 c0       	push   $0xc0005593
c0002d01:	68 f8 56 00 c0       	push   $0xc00056f8
c0002d06:	68 82 00 00 00       	push   $0x82
c0002d0b:	68 63 55 00 c0       	push   $0xc0005563
c0002d10:	e8 1f f6 ff ff       	call   c0002334 <panic_spin>
c0002d15:	83 c4 10             	add    $0x10,%esp
  void *vaddr_start = vaddr_get(pf, pg_cnt);
c0002d18:	83 ec 08             	sub    $0x8,%esp
c0002d1b:	ff 75 0c             	push   0xc(%ebp)
c0002d1e:	ff 75 08             	push   0x8(%ebp)
c0002d21:	e8 f5 fc ff ff       	call   c0002a1b <vaddr_get>
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
c0002d4f:	b8 e0 89 00 c0       	mov    $0xc00089e0,%eax
c0002d54:	eb 05                	jmp    c0002d5b <malloc_page+0x74>
c0002d56:	b8 20 8a 00 c0       	mov    $0xc0008a20,%eax
c0002d5b:	89 45 e8             	mov    %eax,-0x18(%ebp)

  // 虚拟地址连续但物理地址可以不连续，所以逐个做映射
  while (cnt-- > 0) {
c0002d5e:	eb 37                	jmp    c0002d97 <malloc_page+0xb0>
    void *page_phyaddr = palloc(mem_pool);
c0002d60:	83 ec 0c             	sub    $0xc,%esp
c0002d63:	ff 75 e8             	push   -0x18(%ebp)
c0002d66:	e8 13 fe ff ff       	call   c0002b7e <palloc>
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
c0002d88:	e8 45 fe ff ff       	call   c0002bd2 <page_table_add>
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
c0002dd7:	e8 2e f6 ff ff       	call   c000240a <memset>
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
c0002ded:	68 30 8a 00 c0       	push   $0xc0008a30
c0002df2:	e8 d2 0d 00 00       	call   c0003bc9 <lock_acquire>
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
c0002e22:	e8 e3 f5 ff ff       	call   c000240a <memset>
c0002e27:	83 c4 10             	add    $0x10,%esp
  }
  lock_release(&user_pool.lock);
c0002e2a:	83 ec 0c             	sub    $0xc,%esp
c0002e2d:	68 30 8a 00 c0       	push   $0xc0008a30
c0002e32:	e8 07 0e 00 00       	call   c0003c3e <lock_release>
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
c0002e4f:	b8 e0 89 00 c0       	mov    $0xc00089e0,%eax
c0002e54:	eb 05                	jmp    c0002e5b <get_a_page+0x1c>
c0002e56:	b8 20 8a 00 c0       	mov    $0xc0008a20,%eax
c0002e5b:	89 45 f4             	mov    %eax,-0xc(%ebp)
  lock_acquire(&mem_pool->lock);
c0002e5e:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002e61:	83 c0 10             	add    $0x10,%eax
c0002e64:	83 ec 0c             	sub    $0xc,%esp
c0002e67:	50                   	push   %eax
c0002e68:	e8 5c 0d 00 00       	call   c0003bc9 <lock_acquire>
c0002e6d:	83 c4 10             	add    $0x10,%esp
  struct task_struct *cur = running_thread();
c0002e70:	e8 91 03 00 00       	call   c0003206 <running_thread>
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
c0002ea6:	68 af 55 00 c0       	push   $0xc00055af
c0002eab:	68 04 57 00 c0       	push   $0xc0005704
c0002eb0:	68 b6 00 00 00       	push   $0xb6
c0002eb5:	68 63 55 00 c0       	push   $0xc0005563
c0002eba:	e8 75 f4 ff ff       	call   c0002334 <panic_spin>
c0002ebf:	83 c4 10             	add    $0x10,%esp
    bitmap_set(&cur->userprog_vaddr.vaddr_bitmap, bit_idx, 1);
c0002ec2:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002ec5:	8b 55 f0             	mov    -0x10(%ebp),%edx
c0002ec8:	83 c2 38             	add    $0x38,%edx
c0002ecb:	83 ec 04             	sub    $0x4,%esp
c0002ece:	6a 01                	push   $0x1
c0002ed0:	50                   	push   %eax
c0002ed1:	52                   	push   %edx
c0002ed2:	e8 8e fa ff ff       	call   c0002965 <bitmap_set>
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
c0002eec:	8b 15 54 8a 00 c0    	mov    0xc0008a54,%edx
c0002ef2:	8b 45 0c             	mov    0xc(%ebp),%eax
c0002ef5:	29 d0                	sub    %edx,%eax
c0002ef7:	c1 e8 0c             	shr    $0xc,%eax
c0002efa:	89 45 ec             	mov    %eax,-0x14(%ebp)
    ASSERT(bit_idx > 0);
c0002efd:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c0002f01:	7f 1c                	jg     c0002f1f <get_a_page+0xe0>
c0002f03:	68 af 55 00 c0       	push   $0xc00055af
c0002f08:	68 04 57 00 c0       	push   $0xc0005704
c0002f0d:	68 ba 00 00 00       	push   $0xba
c0002f12:	68 63 55 00 c0       	push   $0xc0005563
c0002f17:	e8 18 f4 ff ff       	call   c0002334 <panic_spin>
c0002f1c:	83 c4 10             	add    $0x10,%esp
    bitmap_set(&kernel_vaddr.vaddr_bitmap, bit_idx, 1);
c0002f1f:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002f22:	83 ec 04             	sub    $0x4,%esp
c0002f25:	6a 01                	push   $0x1
c0002f27:	50                   	push   %eax
c0002f28:	68 4c 8a 00 c0       	push   $0xc0008a4c
c0002f2d:	e8 33 fa ff ff       	call   c0002965 <bitmap_set>
c0002f32:	83 c4 10             	add    $0x10,%esp
c0002f35:	eb 1c                	jmp    c0002f53 <get_a_page+0x114>
  } else {
    PANIC("get_a_pages: not allow kernel alloc userspace or user alloc "
c0002f37:	68 bc 55 00 c0       	push   $0xc00055bc
c0002f3c:	68 04 57 00 c0       	push   $0xc0005704
c0002f41:	68 bd 00 00 00       	push   $0xbd
c0002f46:	68 63 55 00 c0       	push   $0xc0005563
c0002f4b:	e8 e4 f3 ff ff       	call   c0002334 <panic_spin>
c0002f50:	83 c4 10             	add    $0x10,%esp
          "kernelspace by get_a_page");
  }

  void *page_phyaddr = palloc(mem_pool);
c0002f53:	83 ec 0c             	sub    $0xc,%esp
c0002f56:	ff 75 f4             	push   -0xc(%ebp)
c0002f59:	e8 20 fc ff ff       	call   c0002b7e <palloc>
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
c0002f7b:	e8 52 fc ff ff       	call   c0002bd2 <page_table_add>
c0002f80:	83 c4 10             	add    $0x10,%esp
  lock_release(&mem_pool->lock);
c0002f83:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002f86:	83 c0 10             	add    $0x10,%eax
c0002f89:	83 ec 0c             	sub    $0xc,%esp
c0002f8c:	50                   	push   %eax
c0002f8d:	e8 ac 0c 00 00       	call   c0003c3e <lock_release>
c0002f92:	83 c4 10             	add    $0x10,%esp
  return (void *)vaddr;
c0002f95:	8b 45 0c             	mov    0xc(%ebp),%eax
}
c0002f98:	c9                   	leave  
c0002f99:	c3                   	ret    

c0002f9a <addr_v2p>:

// 得到vaddr映射的物理地址
uint32_t addr_v2p(uint32_t vaddr) {
c0002f9a:	55                   	push   %ebp
c0002f9b:	89 e5                	mov    %esp,%ebp
c0002f9d:	83 ec 10             	sub    $0x10,%esp
  uint32_t *pte = pte_ptr(vaddr);
c0002fa0:	ff 75 08             	push   0x8(%ebp)
c0002fa3:	e8 8a fb ff ff       	call   c0002b32 <pte_ptr>
c0002fa8:	83 c4 04             	add    $0x4,%esp
c0002fab:	89 45 fc             	mov    %eax,-0x4(%ebp)
  return ((*pte & 0xfffff000) +
c0002fae:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0002fb1:	8b 00                	mov    (%eax),%eax
c0002fb3:	25 00 f0 ff ff       	and    $0xfffff000,%eax
c0002fb8:	89 c2                	mov    %eax,%edx
          (vaddr & 0x00000fff)); // 去掉页表物理地址低12位属性 + vaddr低12位
c0002fba:	8b 45 08             	mov    0x8(%ebp),%eax
c0002fbd:	25 ff 0f 00 00       	and    $0xfff,%eax
  return ((*pte & 0xfffff000) +
c0002fc2:	09 d0                	or     %edx,%eax
}
c0002fc4:	c9                   	leave  
c0002fc5:	c3                   	ret    

c0002fc6 <mem_pool_init>:

// 初始化内存池
static void mem_pool_init(uint32_t all_mem) {
c0002fc6:	55                   	push   %ebp
c0002fc7:	89 e5                	mov    %esp,%ebp
c0002fc9:	83 ec 38             	sub    $0x38,%esp
  put_str("   mem_pool_init start\n");
c0002fcc:	83 ec 0c             	sub    $0xc,%esp
c0002fcf:	68 12 56 00 c0       	push   $0xc0005612
c0002fd4:	e8 37 eb ff ff       	call   c0001b10 <put_str>
c0002fd9:	83 c4 10             	add    $0x10,%esp
  uint32_t page_table_size = PG_SIZE * 256; // 页表+页目录表
c0002fdc:	c7 45 f4 00 00 10 00 	movl   $0x100000,-0xc(%ebp)
  uint32_t used_mem = page_table_size + 0x100000; // 已用：页表占大小+低端1MB
c0002fe3:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0002fe6:	05 00 00 10 00       	add    $0x100000,%eax
c0002feb:	89 45 f0             	mov    %eax,-0x10(%ebp)
  uint32_t free_mem = all_mem - used_mem;
c0002fee:	8b 45 08             	mov    0x8(%ebp),%eax
c0002ff1:	2b 45 f0             	sub    -0x10(%ebp),%eax
c0002ff4:	89 45 ec             	mov    %eax,-0x14(%ebp)
  uint16_t all_free_pages = free_mem / PG_SIZE; // free_mem转为的物理内存页数
c0002ff7:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0002ffa:	c1 e8 0c             	shr    $0xc,%eax
c0002ffd:	66 89 45 ea          	mov    %ax,-0x16(%ebp)
  uint16_t kernel_free_pages = all_free_pages / 2;
c0003001:	0f b7 45 ea          	movzwl -0x16(%ebp),%eax
c0003005:	66 d1 e8             	shr    %ax
c0003008:	66 89 45 e8          	mov    %ax,-0x18(%ebp)
  uint16_t user_free_pages = all_free_pages - kernel_free_pages;
c000300c:	0f b7 45 ea          	movzwl -0x16(%ebp),%eax
c0003010:	66 2b 45 e8          	sub    -0x18(%ebp),%ax
c0003014:	66 89 45 e6          	mov    %ax,-0x1a(%ebp)

  uint32_t kbm_len = kernel_free_pages / 8;
c0003018:	0f b7 45 e8          	movzwl -0x18(%ebp),%eax
c000301c:	66 c1 e8 03          	shr    $0x3,%ax
c0003020:	0f b7 c0             	movzwl %ax,%eax
c0003023:	89 45 e0             	mov    %eax,-0x20(%ebp)
  uint32_t ubm_len = user_free_pages / 8;
c0003026:	0f b7 45 e6          	movzwl -0x1a(%ebp),%eax
c000302a:	66 c1 e8 03          	shr    $0x3,%ax
c000302e:	0f b7 c0             	movzwl %ax,%eax
c0003031:	89 45 dc             	mov    %eax,-0x24(%ebp)

  // 内核内存池起始地址
  uint32_t kp_start = used_mem;
c0003034:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0003037:	89 45 d8             	mov    %eax,-0x28(%ebp)
  // 用户内存池起始地址
  uint32_t up_start = kp_start + kernel_free_pages * PG_SIZE;
c000303a:	0f b7 45 e8          	movzwl -0x18(%ebp),%eax
c000303e:	c1 e0 0c             	shl    $0xc,%eax
c0003041:	89 c2                	mov    %eax,%edx
c0003043:	8b 45 d8             	mov    -0x28(%ebp),%eax
c0003046:	01 d0                	add    %edx,%eax
c0003048:	89 45 d4             	mov    %eax,-0x2c(%ebp)

  kernel_pool.phy_addr_start = kp_start;
c000304b:	8b 45 d8             	mov    -0x28(%ebp),%eax
c000304e:	a3 e8 89 00 c0       	mov    %eax,0xc00089e8
  user_pool.phy_addr_start = up_start;
c0003053:	8b 45 d4             	mov    -0x2c(%ebp),%eax
c0003056:	a3 28 8a 00 c0       	mov    %eax,0xc0008a28

  kernel_pool.pool_size = kernel_free_pages * PG_SIZE;
c000305b:	0f b7 45 e8          	movzwl -0x18(%ebp),%eax
c000305f:	c1 e0 0c             	shl    $0xc,%eax
c0003062:	a3 ec 89 00 c0       	mov    %eax,0xc00089ec
  user_pool.pool_size = user_free_pages * PG_SIZE;
c0003067:	0f b7 45 e6          	movzwl -0x1a(%ebp),%eax
c000306b:	c1 e0 0c             	shl    $0xc,%eax
c000306e:	a3 2c 8a 00 c0       	mov    %eax,0xc0008a2c

  kernel_pool.pool_bitmap.btmp_bytes_len = kbm_len;
c0003073:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0003076:	a3 e0 89 00 c0       	mov    %eax,0xc00089e0
  user_pool.pool_bitmap.btmp_bytes_len = ubm_len;
c000307b:	8b 45 dc             	mov    -0x24(%ebp),%eax
c000307e:	a3 20 8a 00 c0       	mov    %eax,0xc0008a20

  kernel_pool.pool_bitmap.bits = (void *)MEM_BITMAP_BASE;
c0003083:	c7 05 e4 89 00 c0 00 	movl   $0xc009a000,0xc00089e4
c000308a:	a0 09 c0 
  user_pool.pool_bitmap.bits = (void *)(MEM_BITMAP_BASE + kbm_len);
c000308d:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0003090:	2d 00 60 f6 3f       	sub    $0x3ff66000,%eax
c0003095:	a3 24 8a 00 c0       	mov    %eax,0xc0008a24

  /* -----------------------输出内存池信息 -----------------------*/
  put_str("     kernel_pool_bitmap start: ");
c000309a:	83 ec 0c             	sub    $0xc,%esp
c000309d:	68 2c 56 00 c0       	push   $0xc000562c
c00030a2:	e8 69 ea ff ff       	call   c0001b10 <put_str>
c00030a7:	83 c4 10             	add    $0x10,%esp
  put_int((int)kernel_pool.pool_bitmap.bits);
c00030aa:	a1 e4 89 00 c0       	mov    0xc00089e4,%eax
c00030af:	83 ec 0c             	sub    $0xc,%esp
c00030b2:	50                   	push   %eax
c00030b3:	e8 44 eb ff ff       	call   c0001bfc <put_int>
c00030b8:	83 c4 10             	add    $0x10,%esp
  put_str(" kernel_pool_phy_addr start: ");
c00030bb:	83 ec 0c             	sub    $0xc,%esp
c00030be:	68 4c 56 00 c0       	push   $0xc000564c
c00030c3:	e8 48 ea ff ff       	call   c0001b10 <put_str>
c00030c8:	83 c4 10             	add    $0x10,%esp
  put_int(kernel_pool.phy_addr_start);
c00030cb:	a1 e8 89 00 c0       	mov    0xc00089e8,%eax
c00030d0:	83 ec 0c             	sub    $0xc,%esp
c00030d3:	50                   	push   %eax
c00030d4:	e8 23 eb ff ff       	call   c0001bfc <put_int>
c00030d9:	83 c4 10             	add    $0x10,%esp
  put_str("\n");
c00030dc:	83 ec 0c             	sub    $0xc,%esp
c00030df:	68 6a 56 00 c0       	push   $0xc000566a
c00030e4:	e8 27 ea ff ff       	call   c0001b10 <put_str>
c00030e9:	83 c4 10             	add    $0x10,%esp
  put_str("     user_pool_bitmap start: ");
c00030ec:	83 ec 0c             	sub    $0xc,%esp
c00030ef:	68 6c 56 00 c0       	push   $0xc000566c
c00030f4:	e8 17 ea ff ff       	call   c0001b10 <put_str>
c00030f9:	83 c4 10             	add    $0x10,%esp
  put_int((int)user_pool.pool_bitmap.bits);
c00030fc:	a1 24 8a 00 c0       	mov    0xc0008a24,%eax
c0003101:	83 ec 0c             	sub    $0xc,%esp
c0003104:	50                   	push   %eax
c0003105:	e8 f2 ea ff ff       	call   c0001bfc <put_int>
c000310a:	83 c4 10             	add    $0x10,%esp
  put_str(" user_pool_phy_addr start: ");
c000310d:	83 ec 0c             	sub    $0xc,%esp
c0003110:	68 8a 56 00 c0       	push   $0xc000568a
c0003115:	e8 f6 e9 ff ff       	call   c0001b10 <put_str>
c000311a:	83 c4 10             	add    $0x10,%esp
  put_int(user_pool.phy_addr_start);
c000311d:	a1 28 8a 00 c0       	mov    0xc0008a28,%eax
c0003122:	83 ec 0c             	sub    $0xc,%esp
c0003125:	50                   	push   %eax
c0003126:	e8 d1 ea ff ff       	call   c0001bfc <put_int>
c000312b:	83 c4 10             	add    $0x10,%esp
  put_str("\n");
c000312e:	83 ec 0c             	sub    $0xc,%esp
c0003131:	68 6a 56 00 c0       	push   $0xc000566a
c0003136:	e8 d5 e9 ff ff       	call   c0001b10 <put_str>
c000313b:	83 c4 10             	add    $0x10,%esp
  bitmap_init(&kernel_pool.pool_bitmap); // 将位图置0-> 表示位对应的页未分配
c000313e:	83 ec 0c             	sub    $0xc,%esp
c0003141:	68 e0 89 00 c0       	push   $0xc00089e0
c0003146:	e8 8d f6 ff ff       	call   c00027d8 <bitmap_init>
c000314b:	83 c4 10             	add    $0x10,%esp
  bitmap_init(&user_pool.pool_bitmap);
c000314e:	83 ec 0c             	sub    $0xc,%esp
c0003151:	68 20 8a 00 c0       	push   $0xc0008a20
c0003156:	e8 7d f6 ff ff       	call   c00027d8 <bitmap_init>
c000315b:	83 c4 10             	add    $0x10,%esp
  lock_init(&kernel_pool.lock);
c000315e:	83 ec 0c             	sub    $0xc,%esp
c0003161:	68 f0 89 00 c0       	push   $0xc00089f0
c0003166:	e8 84 08 00 00       	call   c00039ef <lock_init>
c000316b:	83 c4 10             	add    $0x10,%esp
  lock_init(&user_pool.lock);
c000316e:	83 ec 0c             	sub    $0xc,%esp
c0003171:	68 30 8a 00 c0       	push   $0xc0008a30
c0003176:	e8 74 08 00 00       	call   c00039ef <lock_init>
c000317b:	83 c4 10             	add    $0x10,%esp

  // 初始化内核虚拟地址池
  kernel_vaddr.vaddr_bitmap.btmp_bytes_len = kbm_len;
c000317e:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0003181:	a3 4c 8a 00 c0       	mov    %eax,0xc0008a4c
  kernel_vaddr.vaddr_bitmap.bits =
      (void *)(MEM_BITMAP_BASE + kbm_len + ubm_len);
c0003186:	8b 55 e0             	mov    -0x20(%ebp),%edx
c0003189:	8b 45 dc             	mov    -0x24(%ebp),%eax
c000318c:	01 d0                	add    %edx,%eax
c000318e:	2d 00 60 f6 3f       	sub    $0x3ff66000,%eax
  kernel_vaddr.vaddr_bitmap.bits =
c0003193:	a3 50 8a 00 c0       	mov    %eax,0xc0008a50
  kernel_vaddr.vaddr_start = K_HEAP_START;
c0003198:	c7 05 54 8a 00 c0 00 	movl   $0xc0100000,0xc0008a54
c000319f:	00 10 c0 
  bitmap_init(&kernel_vaddr.vaddr_bitmap);
c00031a2:	83 ec 0c             	sub    $0xc,%esp
c00031a5:	68 4c 8a 00 c0       	push   $0xc0008a4c
c00031aa:	e8 29 f6 ff ff       	call   c00027d8 <bitmap_init>
c00031af:	83 c4 10             	add    $0x10,%esp
  put_str("   mem_pool_init done\n");
c00031b2:	83 ec 0c             	sub    $0xc,%esp
c00031b5:	68 a6 56 00 c0       	push   $0xc00056a6
c00031ba:	e8 51 e9 ff ff       	call   c0001b10 <put_str>
c00031bf:	83 c4 10             	add    $0x10,%esp
}
c00031c2:	90                   	nop
c00031c3:	c9                   	leave  
c00031c4:	c3                   	ret    

c00031c5 <mem_init>:

// 内存管理部分初始化入口
void mem_init() {
c00031c5:	55                   	push   %ebp
c00031c6:	89 e5                	mov    %esp,%ebp
c00031c8:	83 ec 18             	sub    $0x18,%esp
  put_str("mem_init start\n");
c00031cb:	83 ec 0c             	sub    $0xc,%esp
c00031ce:	68 bd 56 00 c0       	push   $0xc00056bd
c00031d3:	e8 38 e9 ff ff       	call   c0001b10 <put_str>
c00031d8:	83 c4 10             	add    $0x10,%esp
  uint32_t mem_bytes_total = (*(uint32_t *)(0xb00));
c00031db:	b8 00 0b 00 00       	mov    $0xb00,%eax
c00031e0:	8b 00                	mov    (%eax),%eax
c00031e2:	89 45 f4             	mov    %eax,-0xc(%ebp)
  mem_pool_init(mem_bytes_total); // 初始化内存池
c00031e5:	83 ec 0c             	sub    $0xc,%esp
c00031e8:	ff 75 f4             	push   -0xc(%ebp)
c00031eb:	e8 d6 fd ff ff       	call   c0002fc6 <mem_pool_init>
c00031f0:	83 c4 10             	add    $0x10,%esp
  put_str("mem_init done\n");
c00031f3:	83 ec 0c             	sub    $0xc,%esp
c00031f6:	68 cd 56 00 c0       	push   $0xc00056cd
c00031fb:	e8 10 e9 ff ff       	call   c0001b10 <put_str>
c0003200:	83 c4 10             	add    $0x10,%esp
c0003203:	90                   	nop
c0003204:	c9                   	leave  
c0003205:	c3                   	ret    

c0003206 <running_thread>:

// 保存cur线程的寄存器映像，将下个线程next的寄存器映像装载到处理器
extern void switch_to(struct task_struct *cur, struct task_struct *next);

// 获取当前线程的pcb指针
struct task_struct *running_thread() {
c0003206:	55                   	push   %ebp
c0003207:	89 e5                	mov    %esp,%ebp
c0003209:	83 ec 10             	sub    $0x10,%esp
  uint32_t esp;
  asm("mov %%esp, %0" : "=g"(esp));
c000320c:	89 e0                	mov    %esp,%eax
c000320e:	89 45 fc             	mov    %eax,-0x4(%ebp)
  return (struct task_struct *)(esp &
c0003211:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0003214:	25 00 f0 ff ff       	and    $0xfffff000,%eax
                                0xfffff000); // 取esp整数部分，即pcb起始地址
}
c0003219:	c9                   	leave  
c000321a:	c3                   	ret    

c000321b <allocate_pid>:

// 分配pid
static pid_t allocate_pid(void) {
c000321b:	55                   	push   %ebp
c000321c:	89 e5                	mov    %esp,%ebp
c000321e:	83 ec 08             	sub    $0x8,%esp
  static pid_t next_pid = 0;
  lock_acquire(&pid_lock);
c0003221:	83 ec 0c             	sub    $0xc,%esp
c0003224:	68 7c 8a 00 c0       	push   $0xc0008a7c
c0003229:	e8 9b 09 00 00       	call   c0003bc9 <lock_acquire>
c000322e:	83 c4 10             	add    $0x10,%esp
  next_pid++;
c0003231:	0f b7 05 9c 8a 00 c0 	movzwl 0xc0008a9c,%eax
c0003238:	83 c0 01             	add    $0x1,%eax
c000323b:	66 a3 9c 8a 00 c0    	mov    %ax,0xc0008a9c
  lock_release(&pid_lock);
c0003241:	83 ec 0c             	sub    $0xc,%esp
c0003244:	68 7c 8a 00 c0       	push   $0xc0008a7c
c0003249:	e8 f0 09 00 00       	call   c0003c3e <lock_release>
c000324e:	83 c4 10             	add    $0x10,%esp
  return next_pid;
c0003251:	0f b7 05 9c 8a 00 c0 	movzwl 0xc0008a9c,%eax
}
c0003258:	c9                   	leave  
c0003259:	c3                   	ret    

c000325a <kernel_thread>:

// 由kernel_thread去执行func(func_arg)
static void kernel_thread(thread_func *func, void *func_arg) {
c000325a:	55                   	push   %ebp
c000325b:	89 e5                	mov    %esp,%ebp
c000325d:	83 ec 08             	sub    $0x8,%esp
  intr_enable(); // 开中断避免func独享处理器
c0003260:	e8 8f e7 ff ff       	call   c00019f4 <intr_enable>
  func(func_arg);
c0003265:	83 ec 0c             	sub    $0xc,%esp
c0003268:	ff 75 0c             	push   0xc(%ebp)
c000326b:	8b 45 08             	mov    0x8(%ebp),%eax
c000326e:	ff d0                	call   *%eax
c0003270:	83 c4 10             	add    $0x10,%esp
}
c0003273:	90                   	nop
c0003274:	c9                   	leave  
c0003275:	c3                   	ret    

c0003276 <thread_create>:

// 初始化线程栈，将待执行func和func_arg放到栈中相应位置
void thread_create(struct task_struct *pthread, thread_func func,
                   void *func_arg) {
c0003276:	55                   	push   %ebp
c0003277:	89 e5                	mov    %esp,%ebp
c0003279:	83 ec 10             	sub    $0x10,%esp
  pthread->self_kstack -= sizeof(struct intr_stack); // 预留中断使用栈的空间
c000327c:	8b 45 08             	mov    0x8(%ebp),%eax
c000327f:	8b 00                	mov    (%eax),%eax
c0003281:	8d 90 d0 fe ff ff    	lea    -0x130(%eax),%edx
c0003287:	8b 45 08             	mov    0x8(%ebp),%eax
c000328a:	89 10                	mov    %edx,(%eax)
  pthread->self_kstack -= sizeof(struct thread_stack); // 预留线程栈空间
c000328c:	8b 45 08             	mov    0x8(%ebp),%eax
c000328f:	8b 00                	mov    (%eax),%eax
c0003291:	8d 50 80             	lea    -0x80(%eax),%edx
c0003294:	8b 45 08             	mov    0x8(%ebp),%eax
c0003297:	89 10                	mov    %edx,(%eax)

  struct thread_stack *kthread_stack =
c0003299:	8b 45 08             	mov    0x8(%ebp),%eax
c000329c:	8b 00                	mov    (%eax),%eax
c000329e:	89 45 fc             	mov    %eax,-0x4(%ebp)
      (struct thread_stack *)pthread->self_kstack;

  // kernel_thread使用ret方式调用
  kthread_stack->eip = kernel_thread;
c00032a1:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00032a4:	c7 40 10 5a 32 00 c0 	movl   $0xc000325a,0x10(%eax)
  kthread_stack->function = func;
c00032ab:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00032ae:	8b 55 0c             	mov    0xc(%ebp),%edx
c00032b1:	89 50 18             	mov    %edx,0x18(%eax)
  kthread_stack->func_arg = func_arg;
c00032b4:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00032b7:	8b 55 10             	mov    0x10(%ebp),%edx
c00032ba:	89 50 1c             	mov    %edx,0x1c(%eax)

  kthread_stack->ebp = kthread_stack->ebx = kthread_stack->esi =
      kthread_stack->edi = 0;
c00032bd:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00032c0:	c7 40 08 00 00 00 00 	movl   $0x0,0x8(%eax)
c00032c7:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00032ca:	8b 50 08             	mov    0x8(%eax),%edx
  kthread_stack->ebp = kthread_stack->ebx = kthread_stack->esi =
c00032cd:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00032d0:	89 50 0c             	mov    %edx,0xc(%eax)
c00032d3:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00032d6:	8b 50 0c             	mov    0xc(%eax),%edx
c00032d9:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00032dc:	89 50 04             	mov    %edx,0x4(%eax)
c00032df:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00032e2:	8b 50 04             	mov    0x4(%eax),%edx
c00032e5:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00032e8:	89 10                	mov    %edx,(%eax)
}
c00032ea:	90                   	nop
c00032eb:	c9                   	leave  
c00032ec:	c3                   	ret    

c00032ed <init_thread>:

// 初始化线程基本信息
void init_thread(struct task_struct *pthread, char *name, int prio) {
c00032ed:	55                   	push   %ebp
c00032ee:	89 e5                	mov    %esp,%ebp
c00032f0:	83 ec 08             	sub    $0x8,%esp
  memset(pthread, 0, sizeof(*pthread)); // PCB一页清0
c00032f3:	83 ec 04             	sub    $0x4,%esp
c00032f6:	6a 48                	push   $0x48
c00032f8:	6a 00                	push   $0x0
c00032fa:	ff 75 08             	push   0x8(%ebp)
c00032fd:	e8 08 f1 ff ff       	call   c000240a <memset>
c0003302:	83 c4 10             	add    $0x10,%esp
  pthread->pid = allocate_pid();
c0003305:	e8 11 ff ff ff       	call   c000321b <allocate_pid>
c000330a:	8b 55 08             	mov    0x8(%ebp),%edx
c000330d:	66 89 42 04          	mov    %ax,0x4(%edx)
  strcpy(pthread->name, name);
c0003311:	8b 45 08             	mov    0x8(%ebp),%eax
c0003314:	83 c0 0c             	add    $0xc,%eax
c0003317:	83 ec 08             	sub    $0x8,%esp
c000331a:	ff 75 0c             	push   0xc(%ebp)
c000331d:	50                   	push   %eax
c000331e:	e8 1e f2 ff ff       	call   c0002541 <strcpy>
c0003323:	83 c4 10             	add    $0x10,%esp

  if (pthread == main_thread) {
c0003326:	a1 58 8a 00 c0       	mov    0xc0008a58,%eax
c000332b:	39 45 08             	cmp    %eax,0x8(%ebp)
c000332e:	75 0c                	jne    c000333c <init_thread+0x4f>
    pthread->status = TASK_RUNNING;
c0003330:	8b 45 08             	mov    0x8(%ebp),%eax
c0003333:	c7 40 08 00 00 00 00 	movl   $0x0,0x8(%eax)
c000333a:	eb 0a                	jmp    c0003346 <init_thread+0x59>
  } else {
    pthread->status = TASK_READY;
c000333c:	8b 45 08             	mov    0x8(%ebp),%eax
c000333f:	c7 40 08 01 00 00 00 	movl   $0x1,0x8(%eax)
  }

  pthread->self_kstack =
      (uint32_t *)((uint32_t)pthread + PG_SIZE); // 线程的内核栈顶地址
c0003346:	8b 45 08             	mov    0x8(%ebp),%eax
c0003349:	05 00 10 00 00       	add    $0x1000,%eax
c000334e:	89 c2                	mov    %eax,%edx
  pthread->self_kstack =
c0003350:	8b 45 08             	mov    0x8(%ebp),%eax
c0003353:	89 10                	mov    %edx,(%eax)
  pthread->priority = prio;
c0003355:	8b 45 10             	mov    0x10(%ebp),%eax
c0003358:	89 c2                	mov    %eax,%edx
c000335a:	8b 45 08             	mov    0x8(%ebp),%eax
c000335d:	88 50 1c             	mov    %dl,0x1c(%eax)
  pthread->ticks = prio;
c0003360:	8b 45 10             	mov    0x10(%ebp),%eax
c0003363:	89 c2                	mov    %eax,%edx
c0003365:	8b 45 08             	mov    0x8(%ebp),%eax
c0003368:	88 50 1d             	mov    %dl,0x1d(%eax)
  pthread->elapsed_ticks = 0;
c000336b:	8b 45 08             	mov    0x8(%ebp),%eax
c000336e:	c7 40 20 00 00 00 00 	movl   $0x0,0x20(%eax)
  pthread->pgdir = NULL;
c0003375:	8b 45 08             	mov    0x8(%ebp),%eax
c0003378:	c7 40 34 00 00 00 00 	movl   $0x0,0x34(%eax)
  pthread->stack_magic = 0x20021112; // 自定义魔数
c000337f:	8b 45 08             	mov    0x8(%ebp),%eax
c0003382:	c7 40 44 12 11 02 20 	movl   $0x20021112,0x44(%eax)
}
c0003389:	90                   	nop
c000338a:	c9                   	leave  
c000338b:	c3                   	ret    

c000338c <thread_start>:

// 创建线程，线程执行函数是function(func_arg)
struct task_struct *thread_start(char *name, int prio, thread_func func,
                                 void *func_arg) {
c000338c:	55                   	push   %ebp
c000338d:	89 e5                	mov    %esp,%ebp
c000338f:	83 ec 18             	sub    $0x18,%esp
  struct task_struct *thread = get_kernel_pages(1); // PCB指针->最低地址
c0003392:	83 ec 0c             	sub    $0xc,%esp
c0003395:	6a 01                	push   $0x1
c0003397:	e8 0d fa ff ff       	call   c0002da9 <get_kernel_pages>
c000339c:	83 c4 10             	add    $0x10,%esp
c000339f:	89 45 f4             	mov    %eax,-0xc(%ebp)
  init_thread(thread, name, prio);
c00033a2:	83 ec 04             	sub    $0x4,%esp
c00033a5:	ff 75 0c             	push   0xc(%ebp)
c00033a8:	ff 75 08             	push   0x8(%ebp)
c00033ab:	ff 75 f4             	push   -0xc(%ebp)
c00033ae:	e8 3a ff ff ff       	call   c00032ed <init_thread>
c00033b3:	83 c4 10             	add    $0x10,%esp
  thread_create(thread, func, func_arg);
c00033b6:	83 ec 04             	sub    $0x4,%esp
c00033b9:	ff 75 14             	push   0x14(%ebp)
c00033bc:	ff 75 10             	push   0x10(%ebp)
c00033bf:	ff 75 f4             	push   -0xc(%ebp)
c00033c2:	e8 af fe ff ff       	call   c0003276 <thread_create>
c00033c7:	83 c4 10             	add    $0x10,%esp

  ASSERT(!elem_find(&thread_ready_list, &thread->general_tag));
c00033ca:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00033cd:	83 c0 24             	add    $0x24,%eax
c00033d0:	83 ec 08             	sub    $0x8,%esp
c00033d3:	50                   	push   %eax
c00033d4:	68 5c 8a 00 c0       	push   $0xc0008a5c
c00033d9:	e8 e6 04 00 00       	call   c00038c4 <elem_find>
c00033de:	83 c4 10             	add    $0x10,%esp
c00033e1:	85 c0                	test   %eax,%eax
c00033e3:	74 19                	je     c00033fe <thread_start+0x72>
c00033e5:	68 10 57 00 c0       	push   $0xc0005710
c00033ea:	68 90 59 00 c0       	push   $0xc0005990
c00033ef:	6a 5e                	push   $0x5e
c00033f1:	68 45 57 00 c0       	push   $0xc0005745
c00033f6:	e8 39 ef ff ff       	call   c0002334 <panic_spin>
c00033fb:	83 c4 10             	add    $0x10,%esp
  list_append(&thread_ready_list, &thread->general_tag); // 加入就绪线程队列
c00033fe:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003401:	83 c0 24             	add    $0x24,%eax
c0003404:	83 ec 08             	sub    $0x8,%esp
c0003407:	50                   	push   %eax
c0003408:	68 5c 8a 00 c0       	push   $0xc0008a5c
c000340d:	e8 38 04 00 00       	call   c000384a <list_append>
c0003412:	83 c4 10             	add    $0x10,%esp
  ASSERT(!elem_find(&thread_all_list, &thread->all_list_tag));
c0003415:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003418:	83 c0 2c             	add    $0x2c,%eax
c000341b:	83 ec 08             	sub    $0x8,%esp
c000341e:	50                   	push   %eax
c000341f:	68 6c 8a 00 c0       	push   $0xc0008a6c
c0003424:	e8 9b 04 00 00       	call   c00038c4 <elem_find>
c0003429:	83 c4 10             	add    $0x10,%esp
c000342c:	85 c0                	test   %eax,%eax
c000342e:	74 19                	je     c0003449 <thread_start+0xbd>
c0003430:	68 58 57 00 c0       	push   $0xc0005758
c0003435:	68 90 59 00 c0       	push   $0xc0005990
c000343a:	6a 60                	push   $0x60
c000343c:	68 45 57 00 c0       	push   $0xc0005745
c0003441:	e8 ee ee ff ff       	call   c0002334 <panic_spin>
c0003446:	83 c4 10             	add    $0x10,%esp
  list_append(&thread_all_list, &thread->all_list_tag); // 加入全部线程队列
c0003449:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000344c:	83 c0 2c             	add    $0x2c,%eax
c000344f:	83 ec 08             	sub    $0x8,%esp
c0003452:	50                   	push   %eax
c0003453:	68 6c 8a 00 c0       	push   $0xc0008a6c
c0003458:	e8 ed 03 00 00       	call   c000384a <list_append>
c000345d:	83 c4 10             	add    $0x10,%esp

  return thread;
c0003460:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c0003463:	c9                   	leave  
c0003464:	c3                   	ret    

c0003465 <make_main_thread>:

// 将kernel中的main函数完善为主线程
static void make_main_thread(void) {
c0003465:	55                   	push   %ebp
c0003466:	89 e5                	mov    %esp,%ebp
c0003468:	83 ec 08             	sub    $0x8,%esp
  main_thread = running_thread();
c000346b:	e8 96 fd ff ff       	call   c0003206 <running_thread>
c0003470:	a3 58 8a 00 c0       	mov    %eax,0xc0008a58
  init_thread(main_thread, "main", 31);
c0003475:	a1 58 8a 00 c0       	mov    0xc0008a58,%eax
c000347a:	83 ec 04             	sub    $0x4,%esp
c000347d:	6a 1f                	push   $0x1f
c000347f:	68 8c 57 00 c0       	push   $0xc000578c
c0003484:	50                   	push   %eax
c0003485:	e8 63 fe ff ff       	call   c00032ed <init_thread>
c000348a:	83 c4 10             	add    $0x10,%esp

  ASSERT(!elem_find(&thread_all_list, &main_thread->all_list_tag));
c000348d:	a1 58 8a 00 c0       	mov    0xc0008a58,%eax
c0003492:	83 c0 2c             	add    $0x2c,%eax
c0003495:	83 ec 08             	sub    $0x8,%esp
c0003498:	50                   	push   %eax
c0003499:	68 6c 8a 00 c0       	push   $0xc0008a6c
c000349e:	e8 21 04 00 00       	call   c00038c4 <elem_find>
c00034a3:	83 c4 10             	add    $0x10,%esp
c00034a6:	85 c0                	test   %eax,%eax
c00034a8:	74 19                	je     c00034c3 <make_main_thread+0x5e>
c00034aa:	68 94 57 00 c0       	push   $0xc0005794
c00034af:	68 a0 59 00 c0       	push   $0xc00059a0
c00034b4:	6a 6b                	push   $0x6b
c00034b6:	68 45 57 00 c0       	push   $0xc0005745
c00034bb:	e8 74 ee ff ff       	call   c0002334 <panic_spin>
c00034c0:	83 c4 10             	add    $0x10,%esp
  list_append(&thread_all_list, &main_thread->all_list_tag);
c00034c3:	a1 58 8a 00 c0       	mov    0xc0008a58,%eax
c00034c8:	83 c0 2c             	add    $0x2c,%eax
c00034cb:	83 ec 08             	sub    $0x8,%esp
c00034ce:	50                   	push   %eax
c00034cf:	68 6c 8a 00 c0       	push   $0xc0008a6c
c00034d4:	e8 71 03 00 00       	call   c000384a <list_append>
c00034d9:	83 c4 10             	add    $0x10,%esp
}
c00034dc:	90                   	nop
c00034dd:	c9                   	leave  
c00034de:	c3                   	ret    

c00034df <schedule>:

// 调度函数
void schedule() {
c00034df:	55                   	push   %ebp
c00034e0:	89 e5                	mov    %esp,%ebp
c00034e2:	83 ec 18             	sub    $0x18,%esp
  ASSERT(intr_get_status() == INTR_OFF); // 关中断状态
c00034e5:	e8 97 e5 ff ff       	call   c0001a81 <intr_get_status>
c00034ea:	85 c0                	test   %eax,%eax
c00034ec:	74 19                	je     c0003507 <schedule+0x28>
c00034ee:	68 cd 57 00 c0       	push   $0xc00057cd
c00034f3:	68 b4 59 00 c0       	push   $0xc00059b4
c00034f8:	6a 71                	push   $0x71
c00034fa:	68 45 57 00 c0       	push   $0xc0005745
c00034ff:	e8 30 ee ff ff       	call   c0002334 <panic_spin>
c0003504:	83 c4 10             	add    $0x10,%esp

  struct task_struct *cur = running_thread();
c0003507:	e8 fa fc ff ff       	call   c0003206 <running_thread>
c000350c:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (cur->status == TASK_RUNNING) { // 时间片到了-> 加入就绪队列队尾
c000350f:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003512:	8b 40 08             	mov    0x8(%eax),%eax
c0003515:	85 c0                	test   %eax,%eax
c0003517:	75 62                	jne    c000357b <schedule+0x9c>
    ASSERT(!elem_find(&thread_ready_list, &cur->general_tag));
c0003519:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000351c:	83 c0 24             	add    $0x24,%eax
c000351f:	83 ec 08             	sub    $0x8,%esp
c0003522:	50                   	push   %eax
c0003523:	68 5c 8a 00 c0       	push   $0xc0008a5c
c0003528:	e8 97 03 00 00       	call   c00038c4 <elem_find>
c000352d:	83 c4 10             	add    $0x10,%esp
c0003530:	85 c0                	test   %eax,%eax
c0003532:	74 19                	je     c000354d <schedule+0x6e>
c0003534:	68 ec 57 00 c0       	push   $0xc00057ec
c0003539:	68 b4 59 00 c0       	push   $0xc00059b4
c000353e:	6a 75                	push   $0x75
c0003540:	68 45 57 00 c0       	push   $0xc0005745
c0003545:	e8 ea ed ff ff       	call   c0002334 <panic_spin>
c000354a:	83 c4 10             	add    $0x10,%esp
    list_append(&thread_ready_list, &cur->general_tag);
c000354d:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003550:	83 c0 24             	add    $0x24,%eax
c0003553:	83 ec 08             	sub    $0x8,%esp
c0003556:	50                   	push   %eax
c0003557:	68 5c 8a 00 c0       	push   $0xc0008a5c
c000355c:	e8 e9 02 00 00       	call   c000384a <list_append>
c0003561:	83 c4 10             	add    $0x10,%esp
    cur->ticks = cur->priority;
c0003564:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003567:	0f b6 50 1c          	movzbl 0x1c(%eax),%edx
c000356b:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000356e:	88 50 1d             	mov    %dl,0x1d(%eax)
    cur->status = TASK_READY;
c0003571:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003574:	c7 40 08 01 00 00 00 	movl   $0x1,0x8(%eax)
  } else {
    // TODO：阻塞情况-> 加入阻塞队列
  }

  ASSERT(!list_empty(&thread_ready_list));
c000357b:	83 ec 0c             	sub    $0xc,%esp
c000357e:	68 5c 8a 00 c0       	push   $0xc0008a5c
c0003583:	e8 09 04 00 00       	call   c0003991 <list_empty>
c0003588:	83 c4 10             	add    $0x10,%esp
c000358b:	85 c0                	test   %eax,%eax
c000358d:	74 19                	je     c00035a8 <schedule+0xc9>
c000358f:	68 20 58 00 c0       	push   $0xc0005820
c0003594:	68 b4 59 00 c0       	push   $0xc00059b4
c0003599:	6a 7d                	push   $0x7d
c000359b:	68 45 57 00 c0       	push   $0xc0005745
c00035a0:	e8 8f ed ff ff       	call   c0002334 <panic_spin>
c00035a5:	83 c4 10             	add    $0x10,%esp
  thread_tag = NULL;
c00035a8:	c7 05 98 8a 00 c0 00 	movl   $0x0,0xc0008a98
c00035af:	00 00 00 
  thread_tag =
      list_pop(&thread_ready_list); // 弹出就绪队列中的下一个处理线程结点（tag）
c00035b2:	83 ec 0c             	sub    $0xc,%esp
c00035b5:	68 5c 8a 00 c0       	push   $0xc0008a5c
c00035ba:	e8 e3 02 00 00       	call   c00038a2 <list_pop>
c00035bf:	83 c4 10             	add    $0x10,%esp
  thread_tag =
c00035c2:	a3 98 8a 00 c0       	mov    %eax,0xc0008a98
  struct task_struct *next =
      elem2entry(struct task_struct, general_tag, thread_tag);
c00035c7:	a1 98 8a 00 c0       	mov    0xc0008a98,%eax
c00035cc:	83 e8 24             	sub    $0x24,%eax
  struct task_struct *next =
c00035cf:	89 45 f0             	mov    %eax,-0x10(%ebp)
  next->status = TASK_RUNNING;
c00035d2:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00035d5:	c7 40 08 00 00 00 00 	movl   $0x0,0x8(%eax)

  /* 激活页表，并根据任务是否为进程来修改tss.esp0 */
  process_active(next);
c00035dc:	83 ec 0c             	sub    $0xc,%esp
c00035df:	ff 75 f0             	push   -0x10(%ebp)
c00035e2:	e8 1c 10 00 00       	call   c0004603 <process_active>
c00035e7:	83 c4 10             	add    $0x10,%esp
  // 从此之后进程/线程一律作为内核线程去处理（0特权级、使用内核页表）

  switch_to(cur, next); // 任务切换
c00035ea:	83 ec 08             	sub    $0x8,%esp
c00035ed:	ff 75 f0             	push   -0x10(%ebp)
c00035f0:	ff 75 f4             	push   -0xc(%ebp)
c00035f3:	e8 b8 03 00 00       	call   c00039b0 <switch_to>
c00035f8:	83 c4 10             	add    $0x10,%esp
}
c00035fb:	90                   	nop
c00035fc:	c9                   	leave  
c00035fd:	c3                   	ret    

c00035fe <thread_init>:

// 初始化线程环境
void thread_init(void) {
c00035fe:	55                   	push   %ebp
c00035ff:	89 e5                	mov    %esp,%ebp
c0003601:	83 ec 08             	sub    $0x8,%esp
  put_str("thread_init start\n");
c0003604:	83 ec 0c             	sub    $0xc,%esp
c0003607:	68 40 58 00 c0       	push   $0xc0005840
c000360c:	e8 ff e4 ff ff       	call   c0001b10 <put_str>
c0003611:	83 c4 10             	add    $0x10,%esp
  list_init(&thread_ready_list);
c0003614:	83 ec 0c             	sub    $0xc,%esp
c0003617:	68 5c 8a 00 c0       	push   $0xc0008a5c
c000361c:	e8 98 01 00 00       	call   c00037b9 <list_init>
c0003621:	83 c4 10             	add    $0x10,%esp
  list_init(&thread_all_list);
c0003624:	83 ec 0c             	sub    $0xc,%esp
c0003627:	68 6c 8a 00 c0       	push   $0xc0008a6c
c000362c:	e8 88 01 00 00       	call   c00037b9 <list_init>
c0003631:	83 c4 10             	add    $0x10,%esp
  lock_init(&pid_lock);
c0003634:	83 ec 0c             	sub    $0xc,%esp
c0003637:	68 7c 8a 00 c0       	push   $0xc0008a7c
c000363c:	e8 ae 03 00 00       	call   c00039ef <lock_init>
c0003641:	83 c4 10             	add    $0x10,%esp
  make_main_thread(); // 为当前main函数创建线程，在其pcb中写入线程信息
c0003644:	e8 1c fe ff ff       	call   c0003465 <make_main_thread>
  put_str("thread_init done\n");
c0003649:	83 ec 0c             	sub    $0xc,%esp
c000364c:	68 53 58 00 c0       	push   $0xc0005853
c0003651:	e8 ba e4 ff ff       	call   c0001b10 <put_str>
c0003656:	83 c4 10             	add    $0x10,%esp
}
c0003659:	90                   	nop
c000365a:	c9                   	leave  
c000365b:	c3                   	ret    

c000365c <thread_block>:

// 线程自愿阻塞，标志状态为stat
void thread_block(enum task_status stat) {
c000365c:	55                   	push   %ebp
c000365d:	89 e5                	mov    %esp,%ebp
c000365f:	83 ec 18             	sub    $0x18,%esp
  // TASK_BLOCKED、TASK_WAITING、TASK_HANGING三种状态不会被调度
  ASSERT(((stat == TASK_BLOCKED) || (stat == TASK_WAITING) ||
c0003662:	83 7d 08 02          	cmpl   $0x2,0x8(%ebp)
c0003666:	74 28                	je     c0003690 <thread_block+0x34>
c0003668:	83 7d 08 03          	cmpl   $0x3,0x8(%ebp)
c000366c:	74 22                	je     c0003690 <thread_block+0x34>
c000366e:	83 7d 08 04          	cmpl   $0x4,0x8(%ebp)
c0003672:	74 1c                	je     c0003690 <thread_block+0x34>
c0003674:	68 68 58 00 c0       	push   $0xc0005868
c0003679:	68 c0 59 00 c0       	push   $0xc00059c0
c000367e:	68 99 00 00 00       	push   $0x99
c0003683:	68 45 57 00 c0       	push   $0xc0005745
c0003688:	e8 a7 ec ff ff       	call   c0002334 <panic_spin>
c000368d:	83 c4 10             	add    $0x10,%esp
          (stat == TASK_HANGING)));
  enum intr_status old_status = intr_disable();
c0003690:	e8 88 e3 ff ff       	call   c0001a1d <intr_disable>
c0003695:	89 45 f4             	mov    %eax,-0xc(%ebp)
  struct task_struct *cur_thread = running_thread();
c0003698:	e8 69 fb ff ff       	call   c0003206 <running_thread>
c000369d:	89 45 f0             	mov    %eax,-0x10(%ebp)
  cur_thread->status = stat; // 修改状态为非RUNNING，不让其回到ready_list中
c00036a0:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00036a3:	8b 55 08             	mov    0x8(%ebp),%edx
c00036a6:	89 50 08             	mov    %edx,0x8(%eax)
  schedule();                // 将当前线程换下处理器
c00036a9:	e8 31 fe ff ff       	call   c00034df <schedule>
  intr_set_status(old_status); // 待当前线程被解除阻塞后才继续运行
c00036ae:	83 ec 0c             	sub    $0xc,%esp
c00036b1:	ff 75 f4             	push   -0xc(%ebp)
c00036b4:	e8 aa e3 ff ff       	call   c0001a63 <intr_set_status>
c00036b9:	83 c4 10             	add    $0x10,%esp
}
c00036bc:	90                   	nop
c00036bd:	c9                   	leave  
c00036be:	c3                   	ret    

c00036bf <thread_unblock>:

// 线程唤醒
void thread_unblock(struct task_struct *pthread) {
c00036bf:	55                   	push   %ebp
c00036c0:	89 e5                	mov    %esp,%ebp
c00036c2:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status = intr_disable();
c00036c5:	e8 53 e3 ff ff       	call   c0001a1d <intr_disable>
c00036ca:	89 45 f4             	mov    %eax,-0xc(%ebp)
  ASSERT(((pthread->status == TASK_BLOCKED) ||
c00036cd:	8b 45 08             	mov    0x8(%ebp),%eax
c00036d0:	8b 40 08             	mov    0x8(%eax),%eax
c00036d3:	83 f8 02             	cmp    $0x2,%eax
c00036d6:	74 32                	je     c000370a <thread_unblock+0x4b>
c00036d8:	8b 45 08             	mov    0x8(%ebp),%eax
c00036db:	8b 40 08             	mov    0x8(%eax),%eax
c00036de:	83 f8 03             	cmp    $0x3,%eax
c00036e1:	74 27                	je     c000370a <thread_unblock+0x4b>
c00036e3:	8b 45 08             	mov    0x8(%ebp),%eax
c00036e6:	8b 40 08             	mov    0x8(%eax),%eax
c00036e9:	83 f8 04             	cmp    $0x4,%eax
c00036ec:	74 1c                	je     c000370a <thread_unblock+0x4b>
c00036ee:	68 b8 58 00 c0       	push   $0xc00058b8
c00036f3:	68 d0 59 00 c0       	push   $0xc00059d0
c00036f8:	68 a5 00 00 00       	push   $0xa5
c00036fd:	68 45 57 00 c0       	push   $0xc0005745
c0003702:	e8 2d ec ff ff       	call   c0002334 <panic_spin>
c0003707:	83 c4 10             	add    $0x10,%esp
          (pthread->status == TASK_WAITING) ||
          (pthread->status == TASK_HANGING)));
  if (pthread->status != TASK_READY) {
c000370a:	8b 45 08             	mov    0x8(%ebp),%eax
c000370d:	8b 40 08             	mov    0x8(%eax),%eax
c0003710:	83 f8 01             	cmp    $0x1,%eax
c0003713:	0f 84 8f 00 00 00    	je     c00037a8 <thread_unblock+0xe9>
    ASSERT(!elem_find(&thread_ready_list, &pthread->general_tag));
c0003719:	8b 45 08             	mov    0x8(%ebp),%eax
c000371c:	83 c0 24             	add    $0x24,%eax
c000371f:	83 ec 08             	sub    $0x8,%esp
c0003722:	50                   	push   %eax
c0003723:	68 5c 8a 00 c0       	push   $0xc0008a5c
c0003728:	e8 97 01 00 00       	call   c00038c4 <elem_find>
c000372d:	83 c4 10             	add    $0x10,%esp
c0003730:	85 c0                	test   %eax,%eax
c0003732:	74 1c                	je     c0003750 <thread_unblock+0x91>
c0003734:	68 28 59 00 c0       	push   $0xc0005928
c0003739:	68 d0 59 00 c0       	push   $0xc00059d0
c000373e:	68 a9 00 00 00       	push   $0xa9
c0003743:	68 45 57 00 c0       	push   $0xc0005745
c0003748:	e8 e7 eb ff ff       	call   c0002334 <panic_spin>
c000374d:	83 c4 10             	add    $0x10,%esp
    if (elem_find(&thread_ready_list, &pthread->general_tag)) {
c0003750:	8b 45 08             	mov    0x8(%ebp),%eax
c0003753:	83 c0 24             	add    $0x24,%eax
c0003756:	83 ec 08             	sub    $0x8,%esp
c0003759:	50                   	push   %eax
c000375a:	68 5c 8a 00 c0       	push   $0xc0008a5c
c000375f:	e8 60 01 00 00       	call   c00038c4 <elem_find>
c0003764:	83 c4 10             	add    $0x10,%esp
c0003767:	85 c0                	test   %eax,%eax
c0003769:	74 1c                	je     c0003787 <thread_unblock+0xc8>
      PANIC("thread_unblock: blocked thread in ready_list\n");
c000376b:	68 60 59 00 c0       	push   $0xc0005960
c0003770:	68 d0 59 00 c0       	push   $0xc00059d0
c0003775:	68 ab 00 00 00       	push   $0xab
c000377a:	68 45 57 00 c0       	push   $0xc0005745
c000377f:	e8 b0 eb ff ff       	call   c0002334 <panic_spin>
c0003784:	83 c4 10             	add    $0x10,%esp
    }
    list_push(&thread_ready_list,
c0003787:	8b 45 08             	mov    0x8(%ebp),%eax
c000378a:	83 c0 24             	add    $0x24,%eax
c000378d:	83 ec 08             	sub    $0x8,%esp
c0003790:	50                   	push   %eax
c0003791:	68 5c 8a 00 c0       	push   $0xc0008a5c
c0003796:	e8 91 00 00 00       	call   c000382c <list_push>
c000379b:	83 c4 10             	add    $0x10,%esp
              &pthread->general_tag); // 放在就绪队列最前面(尽快调度
    pthread->status = TASK_READY;
c000379e:	8b 45 08             	mov    0x8(%ebp),%eax
c00037a1:	c7 40 08 01 00 00 00 	movl   $0x1,0x8(%eax)
  }
  intr_set_status(old_status);
c00037a8:	83 ec 0c             	sub    $0xc,%esp
c00037ab:	ff 75 f4             	push   -0xc(%ebp)
c00037ae:	e8 b0 e2 ff ff       	call   c0001a63 <intr_set_status>
c00037b3:	83 c4 10             	add    $0x10,%esp
c00037b6:	90                   	nop
c00037b7:	c9                   	leave  
c00037b8:	c3                   	ret    

c00037b9 <list_init>:
#include "list.h"
#include "global.h"
#include "interrupt.h"
#include <stdint.h>

void list_init(struct list *list) {
c00037b9:	55                   	push   %ebp
c00037ba:	89 e5                	mov    %esp,%ebp
  list->head.prev = NULL;
c00037bc:	8b 45 08             	mov    0x8(%ebp),%eax
c00037bf:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
  list->head.next = &list->tail;
c00037c5:	8b 45 08             	mov    0x8(%ebp),%eax
c00037c8:	8d 50 08             	lea    0x8(%eax),%edx
c00037cb:	8b 45 08             	mov    0x8(%ebp),%eax
c00037ce:	89 50 04             	mov    %edx,0x4(%eax)
  list->tail.prev = &list->head;
c00037d1:	8b 55 08             	mov    0x8(%ebp),%edx
c00037d4:	8b 45 08             	mov    0x8(%ebp),%eax
c00037d7:	89 50 08             	mov    %edx,0x8(%eax)
  list->tail.next = NULL;
c00037da:	8b 45 08             	mov    0x8(%ebp),%eax
c00037dd:	c7 40 0c 00 00 00 00 	movl   $0x0,0xc(%eax)
}
c00037e4:	90                   	nop
c00037e5:	5d                   	pop    %ebp
c00037e6:	c3                   	ret    

c00037e7 <list_insert_before>:

// 把elem插入在元素before之前
void list_insert_before(struct list_elem *before, struct list_elem *elem) {
c00037e7:	55                   	push   %ebp
c00037e8:	89 e5                	mov    %esp,%ebp
c00037ea:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status = intr_disable(); // 关中断保证原子性
c00037ed:	e8 2b e2 ff ff       	call   c0001a1d <intr_disable>
c00037f2:	89 45 f4             	mov    %eax,-0xc(%ebp)
  before->prev->next = elem;
c00037f5:	8b 45 08             	mov    0x8(%ebp),%eax
c00037f8:	8b 00                	mov    (%eax),%eax
c00037fa:	8b 55 0c             	mov    0xc(%ebp),%edx
c00037fd:	89 50 04             	mov    %edx,0x4(%eax)
  elem->prev = before->prev;
c0003800:	8b 45 08             	mov    0x8(%ebp),%eax
c0003803:	8b 10                	mov    (%eax),%edx
c0003805:	8b 45 0c             	mov    0xc(%ebp),%eax
c0003808:	89 10                	mov    %edx,(%eax)
  elem->next = before;
c000380a:	8b 45 0c             	mov    0xc(%ebp),%eax
c000380d:	8b 55 08             	mov    0x8(%ebp),%edx
c0003810:	89 50 04             	mov    %edx,0x4(%eax)
  before->prev = elem;
c0003813:	8b 45 08             	mov    0x8(%ebp),%eax
c0003816:	8b 55 0c             	mov    0xc(%ebp),%edx
c0003819:	89 10                	mov    %edx,(%eax)
  intr_set_status(old_status);
c000381b:	83 ec 0c             	sub    $0xc,%esp
c000381e:	ff 75 f4             	push   -0xc(%ebp)
c0003821:	e8 3d e2 ff ff       	call   c0001a63 <intr_set_status>
c0003826:	83 c4 10             	add    $0x10,%esp
}
c0003829:	90                   	nop
c000382a:	c9                   	leave  
c000382b:	c3                   	ret    

c000382c <list_push>:

// 添加元素到列表队首
void list_push(struct list *plist, struct list_elem *elem) {
c000382c:	55                   	push   %ebp
c000382d:	89 e5                	mov    %esp,%ebp
c000382f:	83 ec 08             	sub    $0x8,%esp
  list_insert_before(plist->head.next, elem);
c0003832:	8b 45 08             	mov    0x8(%ebp),%eax
c0003835:	8b 40 04             	mov    0x4(%eax),%eax
c0003838:	83 ec 08             	sub    $0x8,%esp
c000383b:	ff 75 0c             	push   0xc(%ebp)
c000383e:	50                   	push   %eax
c000383f:	e8 a3 ff ff ff       	call   c00037e7 <list_insert_before>
c0003844:	83 c4 10             	add    $0x10,%esp
}
c0003847:	90                   	nop
c0003848:	c9                   	leave  
c0003849:	c3                   	ret    

c000384a <list_append>:

// 追加元素到链表队尾
void list_append(struct list *plist, struct list_elem *elem) {
c000384a:	55                   	push   %ebp
c000384b:	89 e5                	mov    %esp,%ebp
c000384d:	83 ec 08             	sub    $0x8,%esp
  list_insert_before(&plist->tail, elem);
c0003850:	8b 45 08             	mov    0x8(%ebp),%eax
c0003853:	83 c0 08             	add    $0x8,%eax
c0003856:	83 ec 08             	sub    $0x8,%esp
c0003859:	ff 75 0c             	push   0xc(%ebp)
c000385c:	50                   	push   %eax
c000385d:	e8 85 ff ff ff       	call   c00037e7 <list_insert_before>
c0003862:	83 c4 10             	add    $0x10,%esp
}
c0003865:	90                   	nop
c0003866:	c9                   	leave  
c0003867:	c3                   	ret    

c0003868 <list_remove>:

void list_remove(struct list_elem *pelem) {
c0003868:	55                   	push   %ebp
c0003869:	89 e5                	mov    %esp,%ebp
c000386b:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status = intr_disable();
c000386e:	e8 aa e1 ff ff       	call   c0001a1d <intr_disable>
c0003873:	89 45 f4             	mov    %eax,-0xc(%ebp)
  pelem->prev->next = pelem->next;
c0003876:	8b 45 08             	mov    0x8(%ebp),%eax
c0003879:	8b 00                	mov    (%eax),%eax
c000387b:	8b 55 08             	mov    0x8(%ebp),%edx
c000387e:	8b 52 04             	mov    0x4(%edx),%edx
c0003881:	89 50 04             	mov    %edx,0x4(%eax)
  pelem->next->prev = pelem->prev;
c0003884:	8b 45 08             	mov    0x8(%ebp),%eax
c0003887:	8b 40 04             	mov    0x4(%eax),%eax
c000388a:	8b 55 08             	mov    0x8(%ebp),%edx
c000388d:	8b 12                	mov    (%edx),%edx
c000388f:	89 10                	mov    %edx,(%eax)
  intr_set_status(old_status);
c0003891:	83 ec 0c             	sub    $0xc,%esp
c0003894:	ff 75 f4             	push   -0xc(%ebp)
c0003897:	e8 c7 e1 ff ff       	call   c0001a63 <intr_set_status>
c000389c:	83 c4 10             	add    $0x10,%esp
}
c000389f:	90                   	nop
c00038a0:	c9                   	leave  
c00038a1:	c3                   	ret    

c00038a2 <list_pop>:

// 将链表第1个元素弹出并返回
struct list_elem *list_pop(struct list *plist) {
c00038a2:	55                   	push   %ebp
c00038a3:	89 e5                	mov    %esp,%ebp
c00038a5:	83 ec 18             	sub    $0x18,%esp
  struct list_elem *elem = plist->head.next;
c00038a8:	8b 45 08             	mov    0x8(%ebp),%eax
c00038ab:	8b 40 04             	mov    0x4(%eax),%eax
c00038ae:	89 45 f4             	mov    %eax,-0xc(%ebp)
  list_remove(elem);
c00038b1:	83 ec 0c             	sub    $0xc,%esp
c00038b4:	ff 75 f4             	push   -0xc(%ebp)
c00038b7:	e8 ac ff ff ff       	call   c0003868 <list_remove>
c00038bc:	83 c4 10             	add    $0x10,%esp
  return elem;
c00038bf:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c00038c2:	c9                   	leave  
c00038c3:	c3                   	ret    

c00038c4 <elem_find>:

bool elem_find(struct list *plist, struct list_elem *obj_elem) {
c00038c4:	55                   	push   %ebp
c00038c5:	89 e5                	mov    %esp,%ebp
c00038c7:	83 ec 10             	sub    $0x10,%esp
  struct list_elem *elem = plist->head.next;
c00038ca:	8b 45 08             	mov    0x8(%ebp),%eax
c00038cd:	8b 40 04             	mov    0x4(%eax),%eax
c00038d0:	89 45 fc             	mov    %eax,-0x4(%ebp)
  while (elem != &plist->tail) {
c00038d3:	eb 18                	jmp    c00038ed <elem_find+0x29>
    if (elem == obj_elem) {
c00038d5:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00038d8:	3b 45 0c             	cmp    0xc(%ebp),%eax
c00038db:	75 07                	jne    c00038e4 <elem_find+0x20>
      return true;
c00038dd:	b8 01 00 00 00       	mov    $0x1,%eax
c00038e2:	eb 19                	jmp    c00038fd <elem_find+0x39>
    }
    elem = elem->next;
c00038e4:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00038e7:	8b 40 04             	mov    0x4(%eax),%eax
c00038ea:	89 45 fc             	mov    %eax,-0x4(%ebp)
  while (elem != &plist->tail) {
c00038ed:	8b 45 08             	mov    0x8(%ebp),%eax
c00038f0:	83 c0 08             	add    $0x8,%eax
c00038f3:	39 45 fc             	cmp    %eax,-0x4(%ebp)
c00038f6:	75 dd                	jne    c00038d5 <elem_find+0x11>
  }
  return false;
c00038f8:	b8 00 00 00 00       	mov    $0x0,%eax
}
c00038fd:	c9                   	leave  
c00038fe:	c3                   	ret    

c00038ff <list_traversal>:

// 遍历逐个判断是否有符合条件(回调函数f)的元素
struct list_elem *list_traversal(struct list *plist, func f, int arg) {
c00038ff:	55                   	push   %ebp
c0003900:	89 e5                	mov    %esp,%ebp
c0003902:	83 ec 18             	sub    $0x18,%esp
  struct list_elem *elem = plist->head.next;
c0003905:	8b 45 08             	mov    0x8(%ebp),%eax
c0003908:	8b 40 04             	mov    0x4(%eax),%eax
c000390b:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (list_empty(plist)) {
c000390e:	83 ec 0c             	sub    $0xc,%esp
c0003911:	ff 75 08             	push   0x8(%ebp)
c0003914:	e8 78 00 00 00       	call   c0003991 <list_empty>
c0003919:	83 c4 10             	add    $0x10,%esp
c000391c:	85 c0                	test   %eax,%eax
c000391e:	74 2a                	je     c000394a <list_traversal+0x4b>
    return NULL;
c0003920:	b8 00 00 00 00       	mov    $0x0,%eax
c0003925:	eb 33                	jmp    c000395a <list_traversal+0x5b>
  }
  while (elem != &plist->tail) {
    if (f(elem, arg)) {
c0003927:	83 ec 08             	sub    $0x8,%esp
c000392a:	ff 75 10             	push   0x10(%ebp)
c000392d:	ff 75 f4             	push   -0xc(%ebp)
c0003930:	8b 45 0c             	mov    0xc(%ebp),%eax
c0003933:	ff d0                	call   *%eax
c0003935:	83 c4 10             	add    $0x10,%esp
c0003938:	85 c0                	test   %eax,%eax
c000393a:	74 05                	je     c0003941 <list_traversal+0x42>
      return elem;
c000393c:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000393f:	eb 19                	jmp    c000395a <list_traversal+0x5b>
    }
    elem = elem->next;
c0003941:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0003944:	8b 40 04             	mov    0x4(%eax),%eax
c0003947:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while (elem != &plist->tail) {
c000394a:	8b 45 08             	mov    0x8(%ebp),%eax
c000394d:	83 c0 08             	add    $0x8,%eax
c0003950:	39 45 f4             	cmp    %eax,-0xc(%ebp)
c0003953:	75 d2                	jne    c0003927 <list_traversal+0x28>
  }
  return NULL;
c0003955:	b8 00 00 00 00       	mov    $0x0,%eax
}
c000395a:	c9                   	leave  
c000395b:	c3                   	ret    

c000395c <list_len>:

uint32_t list_len(struct list *plist) {
c000395c:	55                   	push   %ebp
c000395d:	89 e5                	mov    %esp,%ebp
c000395f:	83 ec 10             	sub    $0x10,%esp
  struct list_elem *elem = plist->head.next;
c0003962:	8b 45 08             	mov    0x8(%ebp),%eax
c0003965:	8b 40 04             	mov    0x4(%eax),%eax
c0003968:	89 45 fc             	mov    %eax,-0x4(%ebp)
  uint32_t len = 0;
c000396b:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%ebp)
  while (elem != &plist->tail) {
c0003972:	eb 0d                	jmp    c0003981 <list_len+0x25>
    len++;
c0003974:	83 45 f8 01          	addl   $0x1,-0x8(%ebp)
    elem = elem->next;
c0003978:	8b 45 fc             	mov    -0x4(%ebp),%eax
c000397b:	8b 40 04             	mov    0x4(%eax),%eax
c000397e:	89 45 fc             	mov    %eax,-0x4(%ebp)
  while (elem != &plist->tail) {
c0003981:	8b 45 08             	mov    0x8(%ebp),%eax
c0003984:	83 c0 08             	add    $0x8,%eax
c0003987:	39 45 fc             	cmp    %eax,-0x4(%ebp)
c000398a:	75 e8                	jne    c0003974 <list_len+0x18>
  }
  return len;
c000398c:	8b 45 f8             	mov    -0x8(%ebp),%eax
}
c000398f:	c9                   	leave  
c0003990:	c3                   	ret    

c0003991 <list_empty>:

bool list_empty(struct list *plist) {
c0003991:	55                   	push   %ebp
c0003992:	89 e5                	mov    %esp,%ebp
  return (plist->head.next == &plist->tail ? true : false);
c0003994:	8b 45 08             	mov    0x8(%ebp),%eax
c0003997:	8b 40 04             	mov    0x4(%eax),%eax
c000399a:	8b 55 08             	mov    0x8(%ebp),%edx
c000399d:	83 c2 08             	add    $0x8,%edx
c00039a0:	39 d0                	cmp    %edx,%eax
c00039a2:	0f 94 c0             	sete   %al
c00039a5:	0f b6 c0             	movzbl %al,%eax
c00039a8:	5d                   	pop    %ebp
c00039a9:	c3                   	ret    
c00039aa:	66 90                	xchg   %ax,%ax
c00039ac:	66 90                	xchg   %ax,%ax
c00039ae:	66 90                	xchg   %ax,%ax

c00039b0 <switch_to>:
c00039b0:	56                   	push   %esi
c00039b1:	57                   	push   %edi
c00039b2:	53                   	push   %ebx
c00039b3:	55                   	push   %ebp
c00039b4:	8b 44 24 14          	mov    0x14(%esp),%eax
c00039b8:	89 20                	mov    %esp,(%eax)
c00039ba:	8b 44 24 18          	mov    0x18(%esp),%eax
c00039be:	8b 20                	mov    (%eax),%esp
c00039c0:	5d                   	pop    %ebp
c00039c1:	5b                   	pop    %ebx
c00039c2:	5f                   	pop    %edi
c00039c3:	5e                   	pop    %esi
c00039c4:	c3                   	ret    

c00039c5 <sema_init>:
#include "interrupt.h"
#include "list.h"
#include "stdint.h"
#include "thread.h"

void sema_init(struct semaphore *psema, uint8_t value) {
c00039c5:	55                   	push   %ebp
c00039c6:	89 e5                	mov    %esp,%ebp
c00039c8:	83 ec 18             	sub    $0x18,%esp
c00039cb:	8b 45 0c             	mov    0xc(%ebp),%eax
c00039ce:	88 45 f4             	mov    %al,-0xc(%ebp)
  psema->value = value;
c00039d1:	8b 45 08             	mov    0x8(%ebp),%eax
c00039d4:	0f b6 55 f4          	movzbl -0xc(%ebp),%edx
c00039d8:	88 10                	mov    %dl,(%eax)
  list_init(&psema->waiters);
c00039da:	8b 45 08             	mov    0x8(%ebp),%eax
c00039dd:	83 c0 04             	add    $0x4,%eax
c00039e0:	83 ec 0c             	sub    $0xc,%esp
c00039e3:	50                   	push   %eax
c00039e4:	e8 d0 fd ff ff       	call   c00037b9 <list_init>
c00039e9:	83 c4 10             	add    $0x10,%esp
}
c00039ec:	90                   	nop
c00039ed:	c9                   	leave  
c00039ee:	c3                   	ret    

c00039ef <lock_init>:

void lock_init(struct lock *plock) {
c00039ef:	55                   	push   %ebp
c00039f0:	89 e5                	mov    %esp,%ebp
c00039f2:	83 ec 08             	sub    $0x8,%esp
  plock->holder = NULL;
c00039f5:	8b 45 08             	mov    0x8(%ebp),%eax
c00039f8:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
  plock->holder_repeat_nr = 0;
c00039fe:	8b 45 08             	mov    0x8(%ebp),%eax
c0003a01:	c7 40 18 00 00 00 00 	movl   $0x0,0x18(%eax)
  sema_init(&plock->semaphore, 1);
c0003a08:	8b 45 08             	mov    0x8(%ebp),%eax
c0003a0b:	83 c0 04             	add    $0x4,%eax
c0003a0e:	83 ec 08             	sub    $0x8,%esp
c0003a11:	6a 01                	push   $0x1
c0003a13:	50                   	push   %eax
c0003a14:	e8 ac ff ff ff       	call   c00039c5 <sema_init>
c0003a19:	83 c4 10             	add    $0x10,%esp
}
c0003a1c:	90                   	nop
c0003a1d:	c9                   	leave  
c0003a1e:	c3                   	ret    

c0003a1f <sema_down>:

void sema_down(struct semaphore *psema) {
c0003a1f:	55                   	push   %ebp
c0003a20:	89 e5                	mov    %esp,%ebp
c0003a22:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status = intr_disable();
c0003a25:	e8 f3 df ff ff       	call   c0001a1d <intr_disable>
c0003a2a:	89 45 f4             	mov    %eax,-0xc(%ebp)
  while (psema->value == 0) { // 已经被别人持有
c0003a2d:	e9 98 00 00 00       	jmp    c0003aca <sema_down+0xab>
    ASSERT(!elem_find(&psema->waiters, &running_thread()->general_tag));
c0003a32:	e8 cf f7 ff ff       	call   c0003206 <running_thread>
c0003a37:	8d 50 24             	lea    0x24(%eax),%edx
c0003a3a:	8b 45 08             	mov    0x8(%ebp),%eax
c0003a3d:	83 c0 04             	add    $0x4,%eax
c0003a40:	83 ec 08             	sub    $0x8,%esp
c0003a43:	52                   	push   %edx
c0003a44:	50                   	push   %eax
c0003a45:	e8 7a fe ff ff       	call   c00038c4 <elem_find>
c0003a4a:	83 c4 10             	add    $0x10,%esp
c0003a4d:	85 c0                	test   %eax,%eax
c0003a4f:	74 19                	je     c0003a6a <sema_down+0x4b>
c0003a51:	68 e0 59 00 c0       	push   $0xc00059e0
c0003a56:	68 e4 5a 00 c0       	push   $0xc0005ae4
c0003a5b:	6a 16                	push   $0x16
c0003a5d:	68 1c 5a 00 c0       	push   $0xc0005a1c
c0003a62:	e8 cd e8 ff ff       	call   c0002334 <panic_spin>
c0003a67:	83 c4 10             	add    $0x10,%esp
    if (elem_find(&psema->waiters, &running_thread()->general_tag)) {
c0003a6a:	e8 97 f7 ff ff       	call   c0003206 <running_thread>
c0003a6f:	8d 50 24             	lea    0x24(%eax),%edx
c0003a72:	8b 45 08             	mov    0x8(%ebp),%eax
c0003a75:	83 c0 04             	add    $0x4,%eax
c0003a78:	83 ec 08             	sub    $0x8,%esp
c0003a7b:	52                   	push   %edx
c0003a7c:	50                   	push   %eax
c0003a7d:	e8 42 fe ff ff       	call   c00038c4 <elem_find>
c0003a82:	83 c4 10             	add    $0x10,%esp
c0003a85:	85 c0                	test   %eax,%eax
c0003a87:	74 19                	je     c0003aa2 <sema_down+0x83>
      PANIC("sema_down: thread blocked has been in waiters_list\n");
c0003a89:	68 2c 5a 00 c0       	push   $0xc0005a2c
c0003a8e:	68 e4 5a 00 c0       	push   $0xc0005ae4
c0003a93:	6a 18                	push   $0x18
c0003a95:	68 1c 5a 00 c0       	push   $0xc0005a1c
c0003a9a:	e8 95 e8 ff ff       	call   c0002334 <panic_spin>
c0003a9f:	83 c4 10             	add    $0x10,%esp
    }
    // 当前线程把自己加入该锁的等待队列，然后阻塞自己
    list_append(&psema->waiters, &running_thread()->general_tag);
c0003aa2:	e8 5f f7 ff ff       	call   c0003206 <running_thread>
c0003aa7:	8d 50 24             	lea    0x24(%eax),%edx
c0003aaa:	8b 45 08             	mov    0x8(%ebp),%eax
c0003aad:	83 c0 04             	add    $0x4,%eax
c0003ab0:	83 ec 08             	sub    $0x8,%esp
c0003ab3:	52                   	push   %edx
c0003ab4:	50                   	push   %eax
c0003ab5:	e8 90 fd ff ff       	call   c000384a <list_append>
c0003aba:	83 c4 10             	add    $0x10,%esp
    thread_block(TASK_BLOCKED);
c0003abd:	83 ec 0c             	sub    $0xc,%esp
c0003ac0:	6a 02                	push   $0x2
c0003ac2:	e8 95 fb ff ff       	call   c000365c <thread_block>
c0003ac7:	83 c4 10             	add    $0x10,%esp
  while (psema->value == 0) { // 已经被别人持有
c0003aca:	8b 45 08             	mov    0x8(%ebp),%eax
c0003acd:	0f b6 00             	movzbl (%eax),%eax
c0003ad0:	84 c0                	test   %al,%al
c0003ad2:	0f 84 5a ff ff ff    	je     c0003a32 <sema_down+0x13>
  }
  // value=1或被唤醒后-> 获得锁
  psema->value--;
c0003ad8:	8b 45 08             	mov    0x8(%ebp),%eax
c0003adb:	0f b6 00             	movzbl (%eax),%eax
c0003ade:	8d 50 ff             	lea    -0x1(%eax),%edx
c0003ae1:	8b 45 08             	mov    0x8(%ebp),%eax
c0003ae4:	88 10                	mov    %dl,(%eax)
  ASSERT(psema->value == 0);
c0003ae6:	8b 45 08             	mov    0x8(%ebp),%eax
c0003ae9:	0f b6 00             	movzbl (%eax),%eax
c0003aec:	84 c0                	test   %al,%al
c0003aee:	74 19                	je     c0003b09 <sema_down+0xea>
c0003af0:	68 60 5a 00 c0       	push   $0xc0005a60
c0003af5:	68 e4 5a 00 c0       	push   $0xc0005ae4
c0003afa:	6a 20                	push   $0x20
c0003afc:	68 1c 5a 00 c0       	push   $0xc0005a1c
c0003b01:	e8 2e e8 ff ff       	call   c0002334 <panic_spin>
c0003b06:	83 c4 10             	add    $0x10,%esp
  intr_set_status(old_status);
c0003b09:	83 ec 0c             	sub    $0xc,%esp
c0003b0c:	ff 75 f4             	push   -0xc(%ebp)
c0003b0f:	e8 4f df ff ff       	call   c0001a63 <intr_set_status>
c0003b14:	83 c4 10             	add    $0x10,%esp
}
c0003b17:	90                   	nop
c0003b18:	c9                   	leave  
c0003b19:	c3                   	ret    

c0003b1a <sema_up>:

void sema_up(struct semaphore *psema) {
c0003b1a:	55                   	push   %ebp
c0003b1b:	89 e5                	mov    %esp,%ebp
c0003b1d:	83 ec 18             	sub    $0x18,%esp
  enum intr_status old_status = intr_disable();
c0003b20:	e8 f8 de ff ff       	call   c0001a1d <intr_disable>
c0003b25:	89 45 f4             	mov    %eax,-0xc(%ebp)
  ASSERT(psema->value == 0);
c0003b28:	8b 45 08             	mov    0x8(%ebp),%eax
c0003b2b:	0f b6 00             	movzbl (%eax),%eax
c0003b2e:	84 c0                	test   %al,%al
c0003b30:	74 19                	je     c0003b4b <sema_up+0x31>
c0003b32:	68 60 5a 00 c0       	push   $0xc0005a60
c0003b37:	68 f0 5a 00 c0       	push   $0xc0005af0
c0003b3c:	6a 26                	push   $0x26
c0003b3e:	68 1c 5a 00 c0       	push   $0xc0005a1c
c0003b43:	e8 ec e7 ff ff       	call   c0002334 <panic_spin>
c0003b48:	83 c4 10             	add    $0x10,%esp
  if (!list_empty(&psema->waiters)) {
c0003b4b:	8b 45 08             	mov    0x8(%ebp),%eax
c0003b4e:	83 c0 04             	add    $0x4,%eax
c0003b51:	83 ec 0c             	sub    $0xc,%esp
c0003b54:	50                   	push   %eax
c0003b55:	e8 37 fe ff ff       	call   c0003991 <list_empty>
c0003b5a:	83 c4 10             	add    $0x10,%esp
c0003b5d:	85 c0                	test   %eax,%eax
c0003b5f:	75 26                	jne    c0003b87 <sema_up+0x6d>
    struct task_struct *thread_blocked =
        elem2entry(struct task_struct, general_tag, list_pop(&psema->waiters));
c0003b61:	8b 45 08             	mov    0x8(%ebp),%eax
c0003b64:	83 c0 04             	add    $0x4,%eax
c0003b67:	83 ec 0c             	sub    $0xc,%esp
c0003b6a:	50                   	push   %eax
c0003b6b:	e8 32 fd ff ff       	call   c00038a2 <list_pop>
c0003b70:	83 c4 10             	add    $0x10,%esp
c0003b73:	83 e8 24             	sub    $0x24,%eax
    struct task_struct *thread_blocked =
c0003b76:	89 45 f0             	mov    %eax,-0x10(%ebp)
    thread_unblock(thread_blocked);
c0003b79:	83 ec 0c             	sub    $0xc,%esp
c0003b7c:	ff 75 f0             	push   -0x10(%ebp)
c0003b7f:	e8 3b fb ff ff       	call   c00036bf <thread_unblock>
c0003b84:	83 c4 10             	add    $0x10,%esp
  }
  psema->value++;
c0003b87:	8b 45 08             	mov    0x8(%ebp),%eax
c0003b8a:	0f b6 00             	movzbl (%eax),%eax
c0003b8d:	8d 50 01             	lea    0x1(%eax),%edx
c0003b90:	8b 45 08             	mov    0x8(%ebp),%eax
c0003b93:	88 10                	mov    %dl,(%eax)
  ASSERT(psema->value == 1);
c0003b95:	8b 45 08             	mov    0x8(%ebp),%eax
c0003b98:	0f b6 00             	movzbl (%eax),%eax
c0003b9b:	3c 01                	cmp    $0x1,%al
c0003b9d:	74 19                	je     c0003bb8 <sema_up+0x9e>
c0003b9f:	68 72 5a 00 c0       	push   $0xc0005a72
c0003ba4:	68 f0 5a 00 c0       	push   $0xc0005af0
c0003ba9:	6a 2d                	push   $0x2d
c0003bab:	68 1c 5a 00 c0       	push   $0xc0005a1c
c0003bb0:	e8 7f e7 ff ff       	call   c0002334 <panic_spin>
c0003bb5:	83 c4 10             	add    $0x10,%esp
  intr_set_status(old_status);
c0003bb8:	83 ec 0c             	sub    $0xc,%esp
c0003bbb:	ff 75 f4             	push   -0xc(%ebp)
c0003bbe:	e8 a0 de ff ff       	call   c0001a63 <intr_set_status>
c0003bc3:	83 c4 10             	add    $0x10,%esp
}
c0003bc6:	90                   	nop
c0003bc7:	c9                   	leave  
c0003bc8:	c3                   	ret    

c0003bc9 <lock_acquire>:

// 获取锁plock
void lock_acquire(struct lock *plock) {
c0003bc9:	55                   	push   %ebp
c0003bca:	89 e5                	mov    %esp,%ebp
c0003bcc:	53                   	push   %ebx
c0003bcd:	83 ec 04             	sub    $0x4,%esp
  if (plock->holder != running_thread()) { // 判断是否已持有该锁
c0003bd0:	8b 45 08             	mov    0x8(%ebp),%eax
c0003bd3:	8b 18                	mov    (%eax),%ebx
c0003bd5:	e8 2c f6 ff ff       	call   c0003206 <running_thread>
c0003bda:	39 c3                	cmp    %eax,%ebx
c0003bdc:	74 4b                	je     c0003c29 <lock_acquire+0x60>
    sema_down(&plock->semaphore);          // 信号量P操作(原子
c0003bde:	8b 45 08             	mov    0x8(%ebp),%eax
c0003be1:	83 c0 04             	add    $0x4,%eax
c0003be4:	83 ec 0c             	sub    $0xc,%esp
c0003be7:	50                   	push   %eax
c0003be8:	e8 32 fe ff ff       	call   c0003a1f <sema_down>
c0003bed:	83 c4 10             	add    $0x10,%esp
    plock->holder = running_thread();
c0003bf0:	e8 11 f6 ff ff       	call   c0003206 <running_thread>
c0003bf5:	8b 55 08             	mov    0x8(%ebp),%edx
c0003bf8:	89 02                	mov    %eax,(%edx)
    ASSERT(plock->holder_repeat_nr == 0);
c0003bfa:	8b 45 08             	mov    0x8(%ebp),%eax
c0003bfd:	8b 40 18             	mov    0x18(%eax),%eax
c0003c00:	85 c0                	test   %eax,%eax
c0003c02:	74 19                	je     c0003c1d <lock_acquire+0x54>
c0003c04:	68 84 5a 00 c0       	push   $0xc0005a84
c0003c09:	68 f8 5a 00 c0       	push   $0xc0005af8
c0003c0e:	6a 36                	push   $0x36
c0003c10:	68 1c 5a 00 c0       	push   $0xc0005a1c
c0003c15:	e8 1a e7 ff ff       	call   c0002334 <panic_spin>
c0003c1a:	83 c4 10             	add    $0x10,%esp
    plock->holder_repeat_nr = 1;
c0003c1d:	8b 45 08             	mov    0x8(%ebp),%eax
c0003c20:	c7 40 18 01 00 00 00 	movl   $0x1,0x18(%eax)
  } else {
    plock->holder_repeat_nr++;
  }
}
c0003c27:	eb 0f                	jmp    c0003c38 <lock_acquire+0x6f>
    plock->holder_repeat_nr++;
c0003c29:	8b 45 08             	mov    0x8(%ebp),%eax
c0003c2c:	8b 40 18             	mov    0x18(%eax),%eax
c0003c2f:	8d 50 01             	lea    0x1(%eax),%edx
c0003c32:	8b 45 08             	mov    0x8(%ebp),%eax
c0003c35:	89 50 18             	mov    %edx,0x18(%eax)
}
c0003c38:	90                   	nop
c0003c39:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c0003c3c:	c9                   	leave  
c0003c3d:	c3                   	ret    

c0003c3e <lock_release>:

// 释放锁plock
void lock_release(struct lock *plock) {
c0003c3e:	55                   	push   %ebp
c0003c3f:	89 e5                	mov    %esp,%ebp
c0003c41:	53                   	push   %ebx
c0003c42:	83 ec 04             	sub    $0x4,%esp
  ASSERT(plock->holder == running_thread());
c0003c45:	8b 45 08             	mov    0x8(%ebp),%eax
c0003c48:	8b 18                	mov    (%eax),%ebx
c0003c4a:	e8 b7 f5 ff ff       	call   c0003206 <running_thread>
c0003c4f:	39 c3                	cmp    %eax,%ebx
c0003c51:	74 19                	je     c0003c6c <lock_release+0x2e>
c0003c53:	68 a4 5a 00 c0       	push   $0xc0005aa4
c0003c58:	68 08 5b 00 c0       	push   $0xc0005b08
c0003c5d:	6a 3f                	push   $0x3f
c0003c5f:	68 1c 5a 00 c0       	push   $0xc0005a1c
c0003c64:	e8 cb e6 ff ff       	call   c0002334 <panic_spin>
c0003c69:	83 c4 10             	add    $0x10,%esp
  if (plock->holder_repeat_nr > 1) {
c0003c6c:	8b 45 08             	mov    0x8(%ebp),%eax
c0003c6f:	8b 40 18             	mov    0x18(%eax),%eax
c0003c72:	83 f8 01             	cmp    $0x1,%eax
c0003c75:	76 11                	jbe    c0003c88 <lock_release+0x4a>
    // 此时还不能释放锁
    plock->holder_repeat_nr--;
c0003c77:	8b 45 08             	mov    0x8(%ebp),%eax
c0003c7a:	8b 40 18             	mov    0x18(%eax),%eax
c0003c7d:	8d 50 ff             	lea    -0x1(%eax),%edx
c0003c80:	8b 45 08             	mov    0x8(%ebp),%eax
c0003c83:	89 50 18             	mov    %edx,0x18(%eax)
    return;
c0003c86:	eb 49                	jmp    c0003cd1 <lock_release+0x93>
  }
  ASSERT(plock->holder_repeat_nr == 1);
c0003c88:	8b 45 08             	mov    0x8(%ebp),%eax
c0003c8b:	8b 40 18             	mov    0x18(%eax),%eax
c0003c8e:	83 f8 01             	cmp    $0x1,%eax
c0003c91:	74 19                	je     c0003cac <lock_release+0x6e>
c0003c93:	68 c6 5a 00 c0       	push   $0xc0005ac6
c0003c98:	68 08 5b 00 c0       	push   $0xc0005b08
c0003c9d:	6a 45                	push   $0x45
c0003c9f:	68 1c 5a 00 c0       	push   $0xc0005a1c
c0003ca4:	e8 8b e6 ff ff       	call   c0002334 <panic_spin>
c0003ca9:	83 c4 10             	add    $0x10,%esp

  plock->holder = NULL; // 把锁的持有者置空放在V操作前
c0003cac:	8b 45 08             	mov    0x8(%ebp),%eax
c0003caf:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
  plock->holder_repeat_nr = 0;
c0003cb5:	8b 45 08             	mov    0x8(%ebp),%eax
c0003cb8:	c7 40 18 00 00 00 00 	movl   $0x0,0x18(%eax)
  sema_up(&plock->semaphore); // 信号量V操作(原子
c0003cbf:	8b 45 08             	mov    0x8(%ebp),%eax
c0003cc2:	83 c0 04             	add    $0x4,%eax
c0003cc5:	83 ec 0c             	sub    $0xc,%esp
c0003cc8:	50                   	push   %eax
c0003cc9:	e8 4c fe ff ff       	call   c0003b1a <sema_up>
c0003cce:	83 c4 10             	add    $0x10,%esp
c0003cd1:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c0003cd4:	c9                   	leave  
c0003cd5:	c3                   	ret    

c0003cd6 <console_init>:
#include "print.h"
#include "sync.h"

static struct lock console_lock; // 终端锁

void console_init() { lock_init(&console_lock); }
c0003cd6:	55                   	push   %ebp
c0003cd7:	89 e5                	mov    %esp,%ebp
c0003cd9:	83 ec 08             	sub    $0x8,%esp
c0003cdc:	83 ec 0c             	sub    $0xc,%esp
c0003cdf:	68 a0 8a 00 c0       	push   $0xc0008aa0
c0003ce4:	e8 06 fd ff ff       	call   c00039ef <lock_init>
c0003ce9:	83 c4 10             	add    $0x10,%esp
c0003cec:	90                   	nop
c0003ced:	c9                   	leave  
c0003cee:	c3                   	ret    

c0003cef <console_acquire>:

// 获取终端
void console_acquire() { lock_acquire(&console_lock); }
c0003cef:	55                   	push   %ebp
c0003cf0:	89 e5                	mov    %esp,%ebp
c0003cf2:	83 ec 08             	sub    $0x8,%esp
c0003cf5:	83 ec 0c             	sub    $0xc,%esp
c0003cf8:	68 a0 8a 00 c0       	push   $0xc0008aa0
c0003cfd:	e8 c7 fe ff ff       	call   c0003bc9 <lock_acquire>
c0003d02:	83 c4 10             	add    $0x10,%esp
c0003d05:	90                   	nop
c0003d06:	c9                   	leave  
c0003d07:	c3                   	ret    

c0003d08 <console_release>:

// 释放终端
void console_release() { lock_release(&console_lock); }
c0003d08:	55                   	push   %ebp
c0003d09:	89 e5                	mov    %esp,%ebp
c0003d0b:	83 ec 08             	sub    $0x8,%esp
c0003d0e:	83 ec 0c             	sub    $0xc,%esp
c0003d11:	68 a0 8a 00 c0       	push   $0xc0008aa0
c0003d16:	e8 23 ff ff ff       	call   c0003c3e <lock_release>
c0003d1b:	83 c4 10             	add    $0x10,%esp
c0003d1e:	90                   	nop
c0003d1f:	c9                   	leave  
c0003d20:	c3                   	ret    

c0003d21 <console_put_str>:

// 终端中输出字符串
void console_put_str(char *str) {
c0003d21:	55                   	push   %ebp
c0003d22:	89 e5                	mov    %esp,%ebp
c0003d24:	83 ec 08             	sub    $0x8,%esp
  console_acquire();
c0003d27:	e8 c3 ff ff ff       	call   c0003cef <console_acquire>
  put_str(str);
c0003d2c:	83 ec 0c             	sub    $0xc,%esp
c0003d2f:	ff 75 08             	push   0x8(%ebp)
c0003d32:	e8 d9 dd ff ff       	call   c0001b10 <put_str>
c0003d37:	83 c4 10             	add    $0x10,%esp
  console_release();
c0003d3a:	e8 c9 ff ff ff       	call   c0003d08 <console_release>
}
c0003d3f:	90                   	nop
c0003d40:	c9                   	leave  
c0003d41:	c3                   	ret    

c0003d42 <console_put_char>:

// 终端中输出字符
void console_put_char(uint8_t char_asci) {
c0003d42:	55                   	push   %ebp
c0003d43:	89 e5                	mov    %esp,%ebp
c0003d45:	83 ec 18             	sub    $0x18,%esp
c0003d48:	8b 45 08             	mov    0x8(%ebp),%eax
c0003d4b:	88 45 f4             	mov    %al,-0xc(%ebp)
  console_acquire();
c0003d4e:	e8 9c ff ff ff       	call   c0003cef <console_acquire>
  put_char(char_asci);
c0003d53:	0f b6 45 f4          	movzbl -0xc(%ebp),%eax
c0003d57:	83 ec 0c             	sub    $0xc,%esp
c0003d5a:	50                   	push   %eax
c0003d5b:	e8 ce dd ff ff       	call   c0001b2e <put_char>
c0003d60:	83 c4 10             	add    $0x10,%esp
  console_release();
c0003d63:	e8 a0 ff ff ff       	call   c0003d08 <console_release>
}
c0003d68:	90                   	nop
c0003d69:	c9                   	leave  
c0003d6a:	c3                   	ret    

c0003d6b <console_put_int>:

// 终端中输出十六进制整数
void console_put_int(uint32_t num) {
c0003d6b:	55                   	push   %ebp
c0003d6c:	89 e5                	mov    %esp,%ebp
c0003d6e:	83 ec 08             	sub    $0x8,%esp
  console_acquire();
c0003d71:	e8 79 ff ff ff       	call   c0003cef <console_acquire>
  put_int(num);
c0003d76:	83 ec 0c             	sub    $0xc,%esp
c0003d79:	ff 75 08             	push   0x8(%ebp)
c0003d7c:	e8 7b de ff ff       	call   c0001bfc <put_int>
c0003d81:	83 c4 10             	add    $0x10,%esp
  console_release();
c0003d84:	e8 7f ff ff ff       	call   c0003d08 <console_release>
c0003d89:	90                   	nop
c0003d8a:	c9                   	leave  
c0003d8b:	c3                   	ret    

c0003d8c <inb>:
static inline void outsw(uint16_t port, const void *addr, uint32_t word_cnt) {
  asm volatile("cld; rep outsw" : "+S"(addr), "+c"(word_cnt) : "d"(port));
}

// 从端口读1字节
static inline uint8_t inb(uint16_t port) {
c0003d8c:	55                   	push   %ebp
c0003d8d:	89 e5                	mov    %esp,%ebp
c0003d8f:	83 ec 14             	sub    $0x14,%esp
c0003d92:	8b 45 08             	mov    0x8(%ebp),%eax
c0003d95:	66 89 45 ec          	mov    %ax,-0x14(%ebp)
  uint8_t data;
  asm volatile("inb %w1, %b0" : "=a"(data) : "Nd"(port));
c0003d99:	0f b7 45 ec          	movzwl -0x14(%ebp),%eax
c0003d9d:	89 c2                	mov    %eax,%edx
c0003d9f:	ec                   	in     (%dx),%al
c0003da0:	88 45 ff             	mov    %al,-0x1(%ebp)
  return data;
c0003da3:	0f b6 45 ff          	movzbl -0x1(%ebp),%eax
}
c0003da7:	c9                   	leave  
c0003da8:	c3                   	ret    

c0003da9 <intr_keyboard_handler>:
    /* 0x3A */ {caps_lock_char, caps_lock_char}
    /*其他按键暂不处理*/
};

// 键盘中断处理程序
static void intr_keyboard_handler(void) {
c0003da9:	55                   	push   %ebp
c0003daa:	89 e5                	mov    %esp,%ebp
c0003dac:	83 ec 28             	sub    $0x28,%esp
  //bool ctrl_down_last = ctrl_status; // 记录三个组合键是否被按下
  bool shift_down_last = shift_status;
c0003daf:	a1 30 8b 00 c0       	mov    0xc0008b30,%eax
c0003db4:	89 45 ec             	mov    %eax,-0x14(%ebp)
  bool caps_lock_last = caps_lock_status;
c0003db7:	a1 38 8b 00 c0       	mov    0xc0008b38,%eax
c0003dbc:	89 45 e8             	mov    %eax,-0x18(%ebp)
  bool break_code;

  uint16_t scancode = inb(KBD_BUF_PORT); // 获取扫描码
c0003dbf:	6a 60                	push   $0x60
c0003dc1:	e8 c6 ff ff ff       	call   c0003d8c <inb>
c0003dc6:	83 c4 04             	add    $0x4,%esp
c0003dc9:	0f b6 c0             	movzbl %al,%eax
c0003dcc:	66 89 45 f6          	mov    %ax,-0xa(%ebp)

  // scancode是e0开头-> 有多个扫描码，所以马上结束此次函数等下个码进来
  if (scancode == 0xe0) {
c0003dd0:	66 81 7d f6 e0 00    	cmpw   $0xe0,-0xa(%ebp)
c0003dd6:	75 0f                	jne    c0003de7 <intr_keyboard_handler+0x3e>
    ext_scancode = true; // 打开e0标记
c0003dd8:	c7 05 3c 8b 00 c0 01 	movl   $0x1,0xc0008b3c
c0003ddf:	00 00 00 
    return;
c0003de2:	e9 40 02 00 00       	jmp    c0004027 <intr_keyboard_handler+0x27e>
  }

  // 上次以0xe0开头-> 将扫描码合并
  if (ext_scancode) {
c0003de7:	a1 3c 8b 00 c0       	mov    0xc0008b3c,%eax
c0003dec:	85 c0                	test   %eax,%eax
c0003dee:	74 10                	je     c0003e00 <intr_keyboard_handler+0x57>
    scancode = ((0xe000) | scancode);
c0003df0:	66 81 4d f6 00 e0    	orw    $0xe000,-0xa(%ebp)
    ext_scancode = false; // 关闭e0标记
c0003df6:	c7 05 3c 8b 00 c0 00 	movl   $0x0,0xc0008b3c
c0003dfd:	00 00 00 
  }

  break_code = ((scancode & 0x0080) != 0); // 获取break_code
c0003e00:	0f b7 45 f6          	movzwl -0xa(%ebp),%eax
c0003e04:	25 80 00 00 00       	and    $0x80,%eax
c0003e09:	85 c0                	test   %eax,%eax
c0003e0b:	0f 95 c0             	setne  %al
c0003e0e:	0f b6 c0             	movzbl %al,%eax
c0003e11:	89 45 e4             	mov    %eax,-0x1c(%ebp)

  if (break_code) {                            // 断码处理
c0003e14:	83 7d e4 00          	cmpl   $0x0,-0x1c(%ebp)
c0003e18:	74 6a                	je     c0003e84 <intr_keyboard_handler+0xdb>
    uint16_t make_code = (scancode &= 0xff7f); // 通过将第8位置0来获得其通码
c0003e1a:	66 81 65 f6 7f ff    	andw   $0xff7f,-0xa(%ebp)
c0003e20:	0f b7 45 f6          	movzwl -0xa(%ebp),%eax
c0003e24:	66 89 45 e0          	mov    %ax,-0x20(%ebp)

    // 判断三个键是否弹起
    if (make_code == ctrl_l_make || make_code == ctrl_r_make) {
c0003e28:	66 83 7d e0 1d       	cmpw   $0x1d,-0x20(%ebp)
c0003e2d:	74 08                	je     c0003e37 <intr_keyboard_handler+0x8e>
c0003e2f:	66 81 7d e0 1d e0    	cmpw   $0xe01d,-0x20(%ebp)
c0003e35:	75 0c                	jne    c0003e43 <intr_keyboard_handler+0x9a>
      ctrl_status = false;
c0003e37:	c7 05 2c 8b 00 c0 00 	movl   $0x0,0xc0008b2c
c0003e3e:	00 00 00 
c0003e41:	eb 3c                	jmp    c0003e7f <intr_keyboard_handler+0xd6>
    } else if (make_code == shift_l_make || make_code == shift_r_make) {
c0003e43:	66 83 7d e0 2a       	cmpw   $0x2a,-0x20(%ebp)
c0003e48:	74 07                	je     c0003e51 <intr_keyboard_handler+0xa8>
c0003e4a:	66 83 7d e0 36       	cmpw   $0x36,-0x20(%ebp)
c0003e4f:	75 0c                	jne    c0003e5d <intr_keyboard_handler+0xb4>
      shift_status = false;
c0003e51:	c7 05 30 8b 00 c0 00 	movl   $0x0,0xc0008b30
c0003e58:	00 00 00 
c0003e5b:	eb 22                	jmp    c0003e7f <intr_keyboard_handler+0xd6>
    } else if (make_code == alt_l_make || make_code == alt_r_make) {
c0003e5d:	66 83 7d e0 38       	cmpw   $0x38,-0x20(%ebp)
c0003e62:	74 0c                	je     c0003e70 <intr_keyboard_handler+0xc7>
c0003e64:	66 81 7d e0 38 e0    	cmpw   $0xe038,-0x20(%ebp)
c0003e6a:	0f 85 b0 01 00 00    	jne    c0004020 <intr_keyboard_handler+0x277>
      alt_status = false;
c0003e70:	c7 05 34 8b 00 c0 00 	movl   $0x0,0xc0008b34
c0003e77:	00 00 00 
    } // caps_lock不是弹起后关闭，需单独处理

    return;
c0003e7a:	e9 a1 01 00 00       	jmp    c0004020 <intr_keyboard_handler+0x277>
c0003e7f:	e9 9c 01 00 00       	jmp    c0004020 <intr_keyboard_handler+0x277>
  } else if ((scancode > 0x00 && scancode < 0x3b) || (scancode == alt_r_make) ||
c0003e84:	66 83 7d f6 00       	cmpw   $0x0,-0xa(%ebp)
c0003e89:	74 07                	je     c0003e92 <intr_keyboard_handler+0xe9>
c0003e8b:	66 83 7d f6 3a       	cmpw   $0x3a,-0xa(%ebp)
c0003e90:	76 14                	jbe    c0003ea6 <intr_keyboard_handler+0xfd>
c0003e92:	66 81 7d f6 38 e0    	cmpw   $0xe038,-0xa(%ebp)
c0003e98:	74 0c                	je     c0003ea6 <intr_keyboard_handler+0xfd>
c0003e9a:	66 81 7d f6 1d e0    	cmpw   $0xe01d,-0xa(%ebp)
c0003ea0:	0f 85 68 01 00 00    	jne    c000400e <intr_keyboard_handler+0x265>
             (scancode == ctrl_r_make)) { // 通码处理
    bool shift = false;                   // 判断是否与shift组合
c0003ea6:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
    if ((scancode < 0x0e) || (scancode == 0x29) || (scancode == 0x1a) ||
c0003ead:	66 83 7d f6 0d       	cmpw   $0xd,-0xa(%ebp)
c0003eb2:	76 3f                	jbe    c0003ef3 <intr_keyboard_handler+0x14a>
c0003eb4:	66 83 7d f6 29       	cmpw   $0x29,-0xa(%ebp)
c0003eb9:	74 38                	je     c0003ef3 <intr_keyboard_handler+0x14a>
c0003ebb:	66 83 7d f6 1a       	cmpw   $0x1a,-0xa(%ebp)
c0003ec0:	74 31                	je     c0003ef3 <intr_keyboard_handler+0x14a>
c0003ec2:	66 83 7d f6 1b       	cmpw   $0x1b,-0xa(%ebp)
c0003ec7:	74 2a                	je     c0003ef3 <intr_keyboard_handler+0x14a>
        (scancode == 0x1b) || (scancode == 0x2b) || (scancode == 0x27) ||
c0003ec9:	66 83 7d f6 2b       	cmpw   $0x2b,-0xa(%ebp)
c0003ece:	74 23                	je     c0003ef3 <intr_keyboard_handler+0x14a>
c0003ed0:	66 83 7d f6 27       	cmpw   $0x27,-0xa(%ebp)
c0003ed5:	74 1c                	je     c0003ef3 <intr_keyboard_handler+0x14a>
c0003ed7:	66 83 7d f6 28       	cmpw   $0x28,-0xa(%ebp)
c0003edc:	74 15                	je     c0003ef3 <intr_keyboard_handler+0x14a>
        (scancode == 0x28) || (scancode == 0x33) || (scancode == 0x34) ||
c0003ede:	66 83 7d f6 33       	cmpw   $0x33,-0xa(%ebp)
c0003ee3:	74 0e                	je     c0003ef3 <intr_keyboard_handler+0x14a>
c0003ee5:	66 83 7d f6 34       	cmpw   $0x34,-0xa(%ebp)
c0003eea:	74 07                	je     c0003ef3 <intr_keyboard_handler+0x14a>
c0003eec:	66 83 7d f6 35       	cmpw   $0x35,-0xa(%ebp)
c0003ef1:	75 0f                	jne    c0003f02 <intr_keyboard_handler+0x159>
        (scancode == 0x35)) { // 双字符键
      if (shift_down_last) {
c0003ef3:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c0003ef7:	74 3a                	je     c0003f33 <intr_keyboard_handler+0x18a>
        shift = true;
c0003ef9:	c7 45 f0 01 00 00 00 	movl   $0x1,-0x10(%ebp)
      if (shift_down_last) {
c0003f00:	eb 31                	jmp    c0003f33 <intr_keyboard_handler+0x18a>
      }
    } else { // 字母键
      if (shift_down_last && caps_lock_last) {
c0003f02:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c0003f06:	74 0f                	je     c0003f17 <intr_keyboard_handler+0x16e>
c0003f08:	83 7d e8 00          	cmpl   $0x0,-0x18(%ebp)
c0003f0c:	74 09                	je     c0003f17 <intr_keyboard_handler+0x16e>
        shift = false;
c0003f0e:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
c0003f15:	eb 1c                	jmp    c0003f33 <intr_keyboard_handler+0x18a>
      } else if (shift_down_last || caps_lock_last) {
c0003f17:	83 7d ec 00          	cmpl   $0x0,-0x14(%ebp)
c0003f1b:	75 06                	jne    c0003f23 <intr_keyboard_handler+0x17a>
c0003f1d:	83 7d e8 00          	cmpl   $0x0,-0x18(%ebp)
c0003f21:	74 09                	je     c0003f2c <intr_keyboard_handler+0x183>
        shift = true;
c0003f23:	c7 45 f0 01 00 00 00 	movl   $0x1,-0x10(%ebp)
c0003f2a:	eb 07                	jmp    c0003f33 <intr_keyboard_handler+0x18a>
      } else {
        shift = false;
c0003f2c:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
      }
    }

    uint8_t index = (scancode &= 0x00ff); // 针对高字节是e0的码,将高字节置0
c0003f33:	66 81 65 f6 ff 00    	andw   $0xff,-0xa(%ebp)
c0003f39:	0f b7 45 f6          	movzwl -0xa(%ebp),%eax
c0003f3d:	88 45 e3             	mov    %al,-0x1d(%ebp)
    char cur_char = keymap[index][shift]; // 找到对应ASCII字符
c0003f40:	0f b6 45 e3          	movzbl -0x1d(%ebp),%eax
c0003f44:	8d 14 00             	lea    (%eax,%eax,1),%edx
c0003f47:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0003f4a:	01 d0                	add    %edx,%eax
c0003f4c:	05 e0 80 00 c0       	add    $0xc00080e0,%eax
c0003f51:	0f b6 00             	movzbl (%eax),%eax
c0003f54:	88 45 e2             	mov    %al,-0x1e(%ebp)

    if (cur_char) { // 只处理ASCII码不为0的键
c0003f57:	80 7d e2 00          	cmpb   $0x0,-0x1e(%ebp)
c0003f5b:	74 45                	je     c0003fa2 <intr_keyboard_handler+0x1f9>
      // 若缓冲区未满且待加入的cur_char不为0，则将其加入到缓冲区中
      if (!ioq_full(&kbd_buf)) {
c0003f5d:	83 ec 0c             	sub    $0xc,%esp
c0003f60:	68 c0 8a 00 c0       	push   $0xc0008ac0
c0003f65:	e8 64 01 00 00       	call   c00040ce <ioq_full>
c0003f6a:	83 c4 10             	add    $0x10,%esp
c0003f6d:	85 c0                	test   %eax,%eax
c0003f6f:	0f 85 ae 00 00 00    	jne    c0004023 <intr_keyboard_handler+0x27a>
        put_char(cur_char); // 临时的
c0003f75:	0f b6 45 e2          	movzbl -0x1e(%ebp),%eax
c0003f79:	0f b6 c0             	movzbl %al,%eax
c0003f7c:	83 ec 0c             	sub    $0xc,%esp
c0003f7f:	50                   	push   %eax
c0003f80:	e8 a9 db ff ff       	call   c0001b2e <put_char>
c0003f85:	83 c4 10             	add    $0x10,%esp
        ioq_putchar(&kbd_buf, cur_char);
c0003f88:	0f be 45 e2          	movsbl -0x1e(%ebp),%eax
c0003f8c:	83 ec 08             	sub    $0x8,%esp
c0003f8f:	50                   	push   %eax
c0003f90:	68 c0 8a 00 c0       	push   $0xc0008ac0
c0003f95:	e8 00 03 00 00       	call   c000429a <ioq_putchar>
c0003f9a:	83 c4 10             	add    $0x10,%esp
      }
      return;
c0003f9d:	e9 81 00 00 00       	jmp    c0004023 <intr_keyboard_handler+0x27a>
    }

    if (scancode == ctrl_l_char || scancode == ctrl_r_char) {
c0003fa2:	66 83 7d f6 00       	cmpw   $0x0,-0xa(%ebp)
c0003fa7:	74 07                	je     c0003fb0 <intr_keyboard_handler+0x207>
c0003fa9:	66 83 7d f6 00       	cmpw   $0x0,-0xa(%ebp)
c0003fae:	75 0c                	jne    c0003fbc <intr_keyboard_handler+0x213>
      ctrl_status = true;
c0003fb0:	c7 05 2c 8b 00 c0 01 	movl   $0x1,0xc0008b2c
c0003fb7:	00 00 00 
c0003fba:	eb 50                	jmp    c000400c <intr_keyboard_handler+0x263>
    } else if (scancode == shift_l_make || scancode == shift_r_make) {
c0003fbc:	66 83 7d f6 2a       	cmpw   $0x2a,-0xa(%ebp)
c0003fc1:	74 07                	je     c0003fca <intr_keyboard_handler+0x221>
c0003fc3:	66 83 7d f6 36       	cmpw   $0x36,-0xa(%ebp)
c0003fc8:	75 0c                	jne    c0003fd6 <intr_keyboard_handler+0x22d>
      shift_status = true;
c0003fca:	c7 05 30 8b 00 c0 01 	movl   $0x1,0xc0008b30
c0003fd1:	00 00 00 
c0003fd4:	eb 36                	jmp    c000400c <intr_keyboard_handler+0x263>
    } else if (scancode == alt_l_make || scancode == alt_r_make) {
c0003fd6:	66 83 7d f6 38       	cmpw   $0x38,-0xa(%ebp)
c0003fdb:	74 08                	je     c0003fe5 <intr_keyboard_handler+0x23c>
c0003fdd:	66 81 7d f6 38 e0    	cmpw   $0xe038,-0xa(%ebp)
c0003fe3:	75 0c                	jne    c0003ff1 <intr_keyboard_handler+0x248>
      alt_status = true;
c0003fe5:	c7 05 34 8b 00 c0 01 	movl   $0x1,0xc0008b34
c0003fec:	00 00 00 
c0003fef:	eb 1b                	jmp    c000400c <intr_keyboard_handler+0x263>
    } else if (scancode == caps_lock_make) {
c0003ff1:	66 83 7d f6 3a       	cmpw   $0x3a,-0xa(%ebp)
c0003ff6:	75 2e                	jne    c0004026 <intr_keyboard_handler+0x27d>
      caps_lock_status = !caps_lock_status;
c0003ff8:	a1 38 8b 00 c0       	mov    0xc0008b38,%eax
c0003ffd:	85 c0                	test   %eax,%eax
c0003fff:	0f 94 c0             	sete   %al
c0004002:	0f b6 c0             	movzbl %al,%eax
c0004005:	a3 38 8b 00 c0       	mov    %eax,0xc0008b38
             (scancode == ctrl_r_make)) { // 通码处理
c000400a:	eb 1a                	jmp    c0004026 <intr_keyboard_handler+0x27d>
c000400c:	eb 18                	jmp    c0004026 <intr_keyboard_handler+0x27d>
    }
  } else {
    put_str("unknown key\n");
c000400e:	83 ec 0c             	sub    $0xc,%esp
c0004011:	68 15 5b 00 c0       	push   $0xc0005b15
c0004016:	e8 f5 da ff ff       	call   c0001b10 <put_str>
c000401b:	83 c4 10             	add    $0x10,%esp
c000401e:	eb 07                	jmp    c0004027 <intr_keyboard_handler+0x27e>
    return;
c0004020:	90                   	nop
c0004021:	eb 04                	jmp    c0004027 <intr_keyboard_handler+0x27e>
      return;
c0004023:	90                   	nop
c0004024:	eb 01                	jmp    c0004027 <intr_keyboard_handler+0x27e>
             (scancode == ctrl_r_make)) { // 通码处理
c0004026:	90                   	nop
  }
}
c0004027:	c9                   	leave  
c0004028:	c3                   	ret    

c0004029 <keyboard_init>:

// 键盘初始化
void keyboard_init() {
c0004029:	55                   	push   %ebp
c000402a:	89 e5                	mov    %esp,%ebp
c000402c:	83 ec 08             	sub    $0x8,%esp
  put_str("keyboard_init start\n");
c000402f:	83 ec 0c             	sub    $0xc,%esp
c0004032:	68 22 5b 00 c0       	push   $0xc0005b22
c0004037:	e8 d4 da ff ff       	call   c0001b10 <put_str>
c000403c:	83 c4 10             	add    $0x10,%esp
  ioqueue_init(&kbd_buf);
c000403f:	83 ec 0c             	sub    $0xc,%esp
c0004042:	68 c0 8a 00 c0       	push   $0xc0008ac0
c0004047:	e8 28 00 00 00       	call   c0004074 <ioqueue_init>
c000404c:	83 c4 10             	add    $0x10,%esp
  register_handler(0x21, intr_keyboard_handler);
c000404f:	83 ec 08             	sub    $0x8,%esp
c0004052:	68 a9 3d 00 c0       	push   $0xc0003da9
c0004057:	6a 21                	push   $0x21
c0004059:	e8 e8 d9 ff ff       	call   c0001a46 <register_handler>
c000405e:	83 c4 10             	add    $0x10,%esp
  put_str("keyboard_init done\n");
c0004061:	83 ec 0c             	sub    $0xc,%esp
c0004064:	68 37 5b 00 c0       	push   $0xc0005b37
c0004069:	e8 a2 da ff ff       	call   c0001b10 <put_str>
c000406e:	83 c4 10             	add    $0x10,%esp
c0004071:	90                   	nop
c0004072:	c9                   	leave  
c0004073:	c3                   	ret    

c0004074 <ioqueue_init>:
#include "debug.h"
#include "global.h"
#include "interrupt.h"
#include "stdint.h"

void ioqueue_init(struct ioqueue *ioq) {
c0004074:	55                   	push   %ebp
c0004075:	89 e5                	mov    %esp,%ebp
c0004077:	83 ec 08             	sub    $0x8,%esp
  lock_init(&ioq->lock);
c000407a:	8b 45 08             	mov    0x8(%ebp),%eax
c000407d:	83 ec 0c             	sub    $0xc,%esp
c0004080:	50                   	push   %eax
c0004081:	e8 69 f9 ff ff       	call   c00039ef <lock_init>
c0004086:	83 c4 10             	add    $0x10,%esp
  ioq->producer = ioq->consumer = NULL;
c0004089:	8b 45 08             	mov    0x8(%ebp),%eax
c000408c:	c7 40 20 00 00 00 00 	movl   $0x0,0x20(%eax)
c0004093:	8b 45 08             	mov    0x8(%ebp),%eax
c0004096:	8b 50 20             	mov    0x20(%eax),%edx
c0004099:	8b 45 08             	mov    0x8(%ebp),%eax
c000409c:	89 50 1c             	mov    %edx,0x1c(%eax)
  ioq->head = ioq->tail = 0;
c000409f:	8b 45 08             	mov    0x8(%ebp),%eax
c00040a2:	c7 40 68 00 00 00 00 	movl   $0x0,0x68(%eax)
c00040a9:	8b 45 08             	mov    0x8(%ebp),%eax
c00040ac:	8b 50 68             	mov    0x68(%eax),%edx
c00040af:	8b 45 08             	mov    0x8(%ebp),%eax
c00040b2:	89 50 64             	mov    %edx,0x64(%eax)
}
c00040b5:	90                   	nop
c00040b6:	c9                   	leave  
c00040b7:	c3                   	ret    

c00040b8 <next_pos>:

// 返回pos在缓冲区中的下一个位置值
static int32_t next_pos(int32_t pos) { return (pos + 1) % bufsize; }
c00040b8:	55                   	push   %ebp
c00040b9:	89 e5                	mov    %esp,%ebp
c00040bb:	8b 45 08             	mov    0x8(%ebp),%eax
c00040be:	83 c0 01             	add    $0x1,%eax
c00040c1:	99                   	cltd   
c00040c2:	c1 ea 1a             	shr    $0x1a,%edx
c00040c5:	01 d0                	add    %edx,%eax
c00040c7:	83 e0 3f             	and    $0x3f,%eax
c00040ca:	29 d0                	sub    %edx,%eax
c00040cc:	5d                   	pop    %ebp
c00040cd:	c3                   	ret    

c00040ce <ioq_full>:

bool ioq_full(struct ioqueue *ioq) {
c00040ce:	55                   	push   %ebp
c00040cf:	89 e5                	mov    %esp,%ebp
c00040d1:	83 ec 08             	sub    $0x8,%esp
  ASSERT(intr_get_status() == INTR_OFF);
c00040d4:	e8 a8 d9 ff ff       	call   c0001a81 <intr_get_status>
c00040d9:	85 c0                	test   %eax,%eax
c00040db:	74 19                	je     c00040f6 <ioq_full+0x28>
c00040dd:	68 4c 5b 00 c0       	push   $0xc0005b4c
c00040e2:	68 b0 5b 00 c0       	push   $0xc0005bb0
c00040e7:	6a 11                	push   $0x11
c00040e9:	68 6a 5b 00 c0       	push   $0xc0005b6a
c00040ee:	e8 41 e2 ff ff       	call   c0002334 <panic_spin>
c00040f3:	83 c4 10             	add    $0x10,%esp
  return next_pos(ioq->head) == ioq->tail;
c00040f6:	8b 45 08             	mov    0x8(%ebp),%eax
c00040f9:	8b 40 64             	mov    0x64(%eax),%eax
c00040fc:	83 ec 0c             	sub    $0xc,%esp
c00040ff:	50                   	push   %eax
c0004100:	e8 b3 ff ff ff       	call   c00040b8 <next_pos>
c0004105:	83 c4 10             	add    $0x10,%esp
c0004108:	8b 55 08             	mov    0x8(%ebp),%edx
c000410b:	8b 52 68             	mov    0x68(%edx),%edx
c000410e:	39 d0                	cmp    %edx,%eax
c0004110:	0f 94 c0             	sete   %al
c0004113:	0f b6 c0             	movzbl %al,%eax
}
c0004116:	c9                   	leave  
c0004117:	c3                   	ret    

c0004118 <ioq_empty>:

bool ioq_empty(struct ioqueue *ioq) {
c0004118:	55                   	push   %ebp
c0004119:	89 e5                	mov    %esp,%ebp
c000411b:	83 ec 08             	sub    $0x8,%esp
  ASSERT(intr_get_status() == INTR_OFF);
c000411e:	e8 5e d9 ff ff       	call   c0001a81 <intr_get_status>
c0004123:	85 c0                	test   %eax,%eax
c0004125:	74 19                	je     c0004140 <ioq_empty+0x28>
c0004127:	68 4c 5b 00 c0       	push   $0xc0005b4c
c000412c:	68 bc 5b 00 c0       	push   $0xc0005bbc
c0004131:	6a 16                	push   $0x16
c0004133:	68 6a 5b 00 c0       	push   $0xc0005b6a
c0004138:	e8 f7 e1 ff ff       	call   c0002334 <panic_spin>
c000413d:	83 c4 10             	add    $0x10,%esp
  return ioq->head == ioq->tail;
c0004140:	8b 45 08             	mov    0x8(%ebp),%eax
c0004143:	8b 50 64             	mov    0x64(%eax),%edx
c0004146:	8b 45 08             	mov    0x8(%ebp),%eax
c0004149:	8b 40 68             	mov    0x68(%eax),%eax
c000414c:	39 c2                	cmp    %eax,%edx
c000414e:	0f 94 c0             	sete   %al
c0004151:	0f b6 c0             	movzbl %al,%eax
}
c0004154:	c9                   	leave  
c0004155:	c3                   	ret    

c0004156 <ioq_wait>:

// 使当前生产者/消费者在此缓冲区上等待
static void ioq_wait(struct task_struct **waiter) {
c0004156:	55                   	push   %ebp
c0004157:	89 e5                	mov    %esp,%ebp
c0004159:	83 ec 08             	sub    $0x8,%esp
  ASSERT(*waiter == NULL && waiter != NULL);
c000415c:	8b 45 08             	mov    0x8(%ebp),%eax
c000415f:	8b 00                	mov    (%eax),%eax
c0004161:	85 c0                	test   %eax,%eax
c0004163:	75 06                	jne    c000416b <ioq_wait+0x15>
c0004165:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c0004169:	75 19                	jne    c0004184 <ioq_wait+0x2e>
c000416b:	68 7c 5b 00 c0       	push   $0xc0005b7c
c0004170:	68 c8 5b 00 c0       	push   $0xc0005bc8
c0004175:	6a 1c                	push   $0x1c
c0004177:	68 6a 5b 00 c0       	push   $0xc0005b6a
c000417c:	e8 b3 e1 ff ff       	call   c0002334 <panic_spin>
c0004181:	83 c4 10             	add    $0x10,%esp
  *waiter = running_thread();
c0004184:	e8 7d f0 ff ff       	call   c0003206 <running_thread>
c0004189:	8b 55 08             	mov    0x8(%ebp),%edx
c000418c:	89 02                	mov    %eax,(%edx)
  thread_block(TASK_BLOCKED);
c000418e:	83 ec 0c             	sub    $0xc,%esp
c0004191:	6a 02                	push   $0x2
c0004193:	e8 c4 f4 ff ff       	call   c000365c <thread_block>
c0004198:	83 c4 10             	add    $0x10,%esp
}
c000419b:	90                   	nop
c000419c:	c9                   	leave  
c000419d:	c3                   	ret    

c000419e <wakeup>:

// 唤醒waiter
static void wakeup(struct task_struct **waiter) {
c000419e:	55                   	push   %ebp
c000419f:	89 e5                	mov    %esp,%ebp
c00041a1:	83 ec 08             	sub    $0x8,%esp
  ASSERT(*waiter != NULL);
c00041a4:	8b 45 08             	mov    0x8(%ebp),%eax
c00041a7:	8b 00                	mov    (%eax),%eax
c00041a9:	85 c0                	test   %eax,%eax
c00041ab:	75 19                	jne    c00041c6 <wakeup+0x28>
c00041ad:	68 9e 5b 00 c0       	push   $0xc0005b9e
c00041b2:	68 d4 5b 00 c0       	push   $0xc0005bd4
c00041b7:	6a 23                	push   $0x23
c00041b9:	68 6a 5b 00 c0       	push   $0xc0005b6a
c00041be:	e8 71 e1 ff ff       	call   c0002334 <panic_spin>
c00041c3:	83 c4 10             	add    $0x10,%esp
  thread_unblock(*waiter);
c00041c6:	8b 45 08             	mov    0x8(%ebp),%eax
c00041c9:	8b 00                	mov    (%eax),%eax
c00041cb:	83 ec 0c             	sub    $0xc,%esp
c00041ce:	50                   	push   %eax
c00041cf:	e8 eb f4 ff ff       	call   c00036bf <thread_unblock>
c00041d4:	83 c4 10             	add    $0x10,%esp
  *waiter = NULL;
c00041d7:	8b 45 08             	mov    0x8(%ebp),%eax
c00041da:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
}
c00041e0:	90                   	nop
c00041e1:	c9                   	leave  
c00041e2:	c3                   	ret    

c00041e3 <ioq_getchar>:

// 消费者从ioq队列中读一字节
char ioq_getchar(struct ioqueue *ioq) {
c00041e3:	55                   	push   %ebp
c00041e4:	89 e5                	mov    %esp,%ebp
c00041e6:	83 ec 18             	sub    $0x18,%esp
  ASSERT(intr_get_status() == INTR_OFF);
c00041e9:	e8 93 d8 ff ff       	call   c0001a81 <intr_get_status>
c00041ee:	85 c0                	test   %eax,%eax
c00041f0:	74 4b                	je     c000423d <ioq_getchar+0x5a>
c00041f2:	68 4c 5b 00 c0       	push   $0xc0005b4c
c00041f7:	68 dc 5b 00 c0       	push   $0xc0005bdc
c00041fc:	6a 2a                	push   $0x2a
c00041fe:	68 6a 5b 00 c0       	push   $0xc0005b6a
c0004203:	e8 2c e1 ff ff       	call   c0002334 <panic_spin>
c0004208:	83 c4 10             	add    $0x10,%esp
  while (ioq_empty(ioq)) {
c000420b:	eb 30                	jmp    c000423d <ioq_getchar+0x5a>
    // 缓冲区为空-> 先睡眠
    lock_acquire(&ioq->lock);
c000420d:	8b 45 08             	mov    0x8(%ebp),%eax
c0004210:	83 ec 0c             	sub    $0xc,%esp
c0004213:	50                   	push   %eax
c0004214:	e8 b0 f9 ff ff       	call   c0003bc9 <lock_acquire>
c0004219:	83 c4 10             	add    $0x10,%esp
    ioq_wait(&ioq->consumer);
c000421c:	8b 45 08             	mov    0x8(%ebp),%eax
c000421f:	83 c0 20             	add    $0x20,%eax
c0004222:	83 ec 0c             	sub    $0xc,%esp
c0004225:	50                   	push   %eax
c0004226:	e8 2b ff ff ff       	call   c0004156 <ioq_wait>
c000422b:	83 c4 10             	add    $0x10,%esp
    lock_release(&ioq->lock);
c000422e:	8b 45 08             	mov    0x8(%ebp),%eax
c0004231:	83 ec 0c             	sub    $0xc,%esp
c0004234:	50                   	push   %eax
c0004235:	e8 04 fa ff ff       	call   c0003c3e <lock_release>
c000423a:	83 c4 10             	add    $0x10,%esp
  while (ioq_empty(ioq)) {
c000423d:	83 ec 0c             	sub    $0xc,%esp
c0004240:	ff 75 08             	push   0x8(%ebp)
c0004243:	e8 d0 fe ff ff       	call   c0004118 <ioq_empty>
c0004248:	83 c4 10             	add    $0x10,%esp
c000424b:	85 c0                	test   %eax,%eax
c000424d:	75 be                	jne    c000420d <ioq_getchar+0x2a>
  }
  char byte = ioq->buf[ioq->tail]; // 从缓冲区中取出
c000424f:	8b 45 08             	mov    0x8(%ebp),%eax
c0004252:	8b 40 68             	mov    0x68(%eax),%eax
c0004255:	8b 55 08             	mov    0x8(%ebp),%edx
c0004258:	0f b6 44 02 24       	movzbl 0x24(%edx,%eax,1),%eax
c000425d:	88 45 f7             	mov    %al,-0x9(%ebp)
  ioq->tail = next_pos(ioq->tail); // 把读游标移到下一位置
c0004260:	8b 45 08             	mov    0x8(%ebp),%eax
c0004263:	8b 40 68             	mov    0x68(%eax),%eax
c0004266:	83 ec 0c             	sub    $0xc,%esp
c0004269:	50                   	push   %eax
c000426a:	e8 49 fe ff ff       	call   c00040b8 <next_pos>
c000426f:	83 c4 10             	add    $0x10,%esp
c0004272:	8b 55 08             	mov    0x8(%ebp),%edx
c0004275:	89 42 68             	mov    %eax,0x68(%edx)
  if (ioq->producer != NULL) {
c0004278:	8b 45 08             	mov    0x8(%ebp),%eax
c000427b:	8b 40 1c             	mov    0x1c(%eax),%eax
c000427e:	85 c0                	test   %eax,%eax
c0004280:	74 12                	je     c0004294 <ioq_getchar+0xb1>
    wakeup(&ioq->producer); // 唤醒生产者
c0004282:	8b 45 08             	mov    0x8(%ebp),%eax
c0004285:	83 c0 1c             	add    $0x1c,%eax
c0004288:	83 ec 0c             	sub    $0xc,%esp
c000428b:	50                   	push   %eax
c000428c:	e8 0d ff ff ff       	call   c000419e <wakeup>
c0004291:	83 c4 10             	add    $0x10,%esp
  }
  return byte;
c0004294:	0f b6 45 f7          	movzbl -0x9(%ebp),%eax
}
c0004298:	c9                   	leave  
c0004299:	c3                   	ret    

c000429a <ioq_putchar>:

// 生产者往ioq队列中写一字节
void ioq_putchar(struct ioqueue *ioq, char byte) {
c000429a:	55                   	push   %ebp
c000429b:	89 e5                	mov    %esp,%ebp
c000429d:	83 ec 18             	sub    $0x18,%esp
c00042a0:	8b 45 0c             	mov    0xc(%ebp),%eax
c00042a3:	88 45 f4             	mov    %al,-0xc(%ebp)
  ASSERT(intr_get_status() == INTR_OFF);
c00042a6:	e8 d6 d7 ff ff       	call   c0001a81 <intr_get_status>
c00042ab:	85 c0                	test   %eax,%eax
c00042ad:	74 4b                	je     c00042fa <ioq_putchar+0x60>
c00042af:	68 4c 5b 00 c0       	push   $0xc0005b4c
c00042b4:	68 e8 5b 00 c0       	push   $0xc0005be8
c00042b9:	6a 3b                	push   $0x3b
c00042bb:	68 6a 5b 00 c0       	push   $0xc0005b6a
c00042c0:	e8 6f e0 ff ff       	call   c0002334 <panic_spin>
c00042c5:	83 c4 10             	add    $0x10,%esp
  while (ioq_full(ioq)) {
c00042c8:	eb 30                	jmp    c00042fa <ioq_putchar+0x60>
    // 缓冲区满-> 先睡眠
    lock_acquire(&ioq->lock); // 避免惊群情况出现
c00042ca:	8b 45 08             	mov    0x8(%ebp),%eax
c00042cd:	83 ec 0c             	sub    $0xc,%esp
c00042d0:	50                   	push   %eax
c00042d1:	e8 f3 f8 ff ff       	call   c0003bc9 <lock_acquire>
c00042d6:	83 c4 10             	add    $0x10,%esp
    ioq_wait(&ioq->producer);
c00042d9:	8b 45 08             	mov    0x8(%ebp),%eax
c00042dc:	83 c0 1c             	add    $0x1c,%eax
c00042df:	83 ec 0c             	sub    $0xc,%esp
c00042e2:	50                   	push   %eax
c00042e3:	e8 6e fe ff ff       	call   c0004156 <ioq_wait>
c00042e8:	83 c4 10             	add    $0x10,%esp
    lock_release(&ioq->lock);
c00042eb:	8b 45 08             	mov    0x8(%ebp),%eax
c00042ee:	83 ec 0c             	sub    $0xc,%esp
c00042f1:	50                   	push   %eax
c00042f2:	e8 47 f9 ff ff       	call   c0003c3e <lock_release>
c00042f7:	83 c4 10             	add    $0x10,%esp
  while (ioq_full(ioq)) {
c00042fa:	83 ec 0c             	sub    $0xc,%esp
c00042fd:	ff 75 08             	push   0x8(%ebp)
c0004300:	e8 c9 fd ff ff       	call   c00040ce <ioq_full>
c0004305:	83 c4 10             	add    $0x10,%esp
c0004308:	85 c0                	test   %eax,%eax
c000430a:	75 be                	jne    c00042ca <ioq_putchar+0x30>
  }
  ioq->buf[ioq->head] = byte;      // 把字节放入缓冲区中
c000430c:	8b 45 08             	mov    0x8(%ebp),%eax
c000430f:	8b 40 64             	mov    0x64(%eax),%eax
c0004312:	8b 55 08             	mov    0x8(%ebp),%edx
c0004315:	0f b6 4d f4          	movzbl -0xc(%ebp),%ecx
c0004319:	88 4c 02 24          	mov    %cl,0x24(%edx,%eax,1)
  ioq->head = next_pos(ioq->head); // 把写游标移到下一位置
c000431d:	8b 45 08             	mov    0x8(%ebp),%eax
c0004320:	8b 40 64             	mov    0x64(%eax),%eax
c0004323:	83 ec 0c             	sub    $0xc,%esp
c0004326:	50                   	push   %eax
c0004327:	e8 8c fd ff ff       	call   c00040b8 <next_pos>
c000432c:	83 c4 10             	add    $0x10,%esp
c000432f:	8b 55 08             	mov    0x8(%ebp),%edx
c0004332:	89 42 64             	mov    %eax,0x64(%edx)
  if (ioq->consumer != NULL) {
c0004335:	8b 45 08             	mov    0x8(%ebp),%eax
c0004338:	8b 40 20             	mov    0x20(%eax),%eax
c000433b:	85 c0                	test   %eax,%eax
c000433d:	74 12                	je     c0004351 <ioq_putchar+0xb7>
    wakeup(&ioq->consumer); // 唤醒消费者
c000433f:	8b 45 08             	mov    0x8(%ebp),%eax
c0004342:	83 c0 20             	add    $0x20,%eax
c0004345:	83 ec 0c             	sub    $0xc,%esp
c0004348:	50                   	push   %eax
c0004349:	e8 50 fe ff ff       	call   c000419e <wakeup>
c000434e:	83 c4 10             	add    $0x10,%esp
  }
c0004351:	90                   	nop
c0004352:	c9                   	leave  
c0004353:	c3                   	ret    

c0004354 <update_tss_esp>:
};
static struct tss tss;
#define PG_SIZE 4096

// 更新tss中的esp0-> pthread的0级栈
void update_tss_esp(struct task_struct *pthread) {
c0004354:	55                   	push   %ebp
c0004355:	89 e5                	mov    %esp,%ebp
  // Linux任务切换-> 仅修改TSS中特权级0对应的栈
  tss.esp0 = (uint32_t *)((uint32_t)pthread + PG_SIZE);
c0004357:	8b 45 08             	mov    0x8(%ebp),%eax
c000435a:	05 00 10 00 00       	add    $0x1000,%eax
c000435f:	a3 44 8b 00 c0       	mov    %eax,0xc0008b44
}
c0004364:	90                   	nop
c0004365:	5d                   	pop    %ebp
c0004366:	c3                   	ret    

c0004367 <make_gdt_desc>:

// 创建GDT描述符
static struct gdt_desc make_gdt_desc(uint32_t *desc_addr, uint32_t limit,
                                     uint8_t attr_low, uint8_t attr_high) {
c0004367:	55                   	push   %ebp
c0004368:	89 e5                	mov    %esp,%ebp
c000436a:	83 ec 18             	sub    $0x18,%esp
c000436d:	8b 55 14             	mov    0x14(%ebp),%edx
c0004370:	8b 45 18             	mov    0x18(%ebp),%eax
c0004373:	88 55 ec             	mov    %dl,-0x14(%ebp)
c0004376:	88 45 e8             	mov    %al,-0x18(%ebp)
  uint32_t desc_base = (uint32_t)desc_addr;
c0004379:	8b 45 0c             	mov    0xc(%ebp),%eax
c000437c:	89 45 fc             	mov    %eax,-0x4(%ebp)
  struct gdt_desc desc;
  desc.limit_low_word = limit & 0x0000ffff;
c000437f:	8b 45 10             	mov    0x10(%ebp),%eax
c0004382:	66 89 45 f4          	mov    %ax,-0xc(%ebp)
  desc.base_low_word = desc_base & 0x0000ffff;
c0004386:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0004389:	66 89 45 f6          	mov    %ax,-0xa(%ebp)
  desc.base_mid_byte = ((desc_base & 0x00ff0000) >> 16);
c000438d:	8b 45 fc             	mov    -0x4(%ebp),%eax
c0004390:	c1 e8 10             	shr    $0x10,%eax
c0004393:	88 45 f8             	mov    %al,-0x8(%ebp)
  desc.attr_low_byte = (uint8_t)(attr_low);
c0004396:	0f b6 45 ec          	movzbl -0x14(%ebp),%eax
c000439a:	88 45 f9             	mov    %al,-0x7(%ebp)
  desc.limit_high_attr_high =
      (((limit & 0x000f0000) >> 16) + (uint8_t)(attr_high));
c000439d:	8b 45 10             	mov    0x10(%ebp),%eax
c00043a0:	c1 e8 10             	shr    $0x10,%eax
c00043a3:	83 e0 0f             	and    $0xf,%eax
c00043a6:	89 c2                	mov    %eax,%edx
c00043a8:	0f b6 45 e8          	movzbl -0x18(%ebp),%eax
c00043ac:	01 d0                	add    %edx,%eax
  desc.limit_high_attr_high =
c00043ae:	88 45 fa             	mov    %al,-0x6(%ebp)
  desc.base_high_byte = desc_base >> 24;
c00043b1:	8b 45 fc             	mov    -0x4(%ebp),%eax
c00043b4:	c1 e8 18             	shr    $0x18,%eax
c00043b7:	88 45 fb             	mov    %al,-0x5(%ebp)
  return desc;
c00043ba:	8b 4d 08             	mov    0x8(%ebp),%ecx
c00043bd:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00043c0:	8b 55 f8             	mov    -0x8(%ebp),%edx
c00043c3:	89 01                	mov    %eax,(%ecx)
c00043c5:	89 51 04             	mov    %edx,0x4(%ecx)
}
c00043c8:	8b 45 08             	mov    0x8(%ebp),%eax
c00043cb:	c9                   	leave  
c00043cc:	c2 04 00             	ret    $0x4

c00043cf <tss_init>:

// 初始化tss并装到GDT中，并在GDT中安装两个供用户进程用的描述符（DATA和CODE）
void tss_init() {
c00043cf:	55                   	push   %ebp
c00043d0:	89 e5                	mov    %esp,%ebp
c00043d2:	53                   	push   %ebx
c00043d3:	83 ec 24             	sub    $0x24,%esp
  put_str("tss_init start\n");
c00043d6:	83 ec 0c             	sub    $0xc,%esp
c00043d9:	68 f4 5b 00 c0       	push   $0xc0005bf4
c00043de:	e8 2d d7 ff ff       	call   c0001b10 <put_str>
c00043e3:	83 c4 10             	add    $0x10,%esp
  uint32_t tss_size = sizeof(tss);
c00043e6:	c7 45 f4 6c 00 00 00 	movl   $0x6c,-0xc(%ebp)
  memset(&tss, 0, tss_size);
c00043ed:	83 ec 04             	sub    $0x4,%esp
c00043f0:	ff 75 f4             	push   -0xc(%ebp)
c00043f3:	6a 00                	push   $0x0
c00043f5:	68 40 8b 00 c0       	push   $0xc0008b40
c00043fa:	e8 0b e0 ff ff       	call   c000240a <memset>
c00043ff:	83 c4 10             	add    $0x10,%esp
  tss.ss0 = SELECTOR_K_STACK;
c0004402:	c7 05 48 8b 00 c0 10 	movl   $0x10,0xc0008b48
c0004409:	00 00 00 
  tss.io_base = tss_size; // 表示此TSS中没有IO位图
c000440c:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000440f:	a3 a8 8b 00 c0       	mov    %eax,0xc0008ba8

  // gdt段基址为0x900，tss放第4个也就是0x900+0x20

  // GDT中添加dpl=0的tss描述符、dpl=3的数据段和代码段描述符
  *((struct gdt_desc *)0xc0000920) = make_gdt_desc(
c0004414:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0004417:	8d 50 ff             	lea    -0x1(%eax),%edx
c000441a:	bb 20 09 00 c0       	mov    $0xc0000920,%ebx
c000441f:	8d 45 e0             	lea    -0x20(%ebp),%eax
c0004422:	83 ec 0c             	sub    $0xc,%esp
c0004425:	68 80 00 00 00       	push   $0x80
c000442a:	68 89 00 00 00       	push   $0x89
c000442f:	52                   	push   %edx
c0004430:	68 40 8b 00 c0       	push   $0xc0008b40
c0004435:	50                   	push   %eax
c0004436:	e8 2c ff ff ff       	call   c0004367 <make_gdt_desc>
c000443b:	83 c4 1c             	add    $0x1c,%esp
c000443e:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0004441:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c0004444:	89 03                	mov    %eax,(%ebx)
c0004446:	89 53 04             	mov    %edx,0x4(%ebx)
      (uint32_t *)&tss, tss_size - 1, TSS_ATTR_LOW, TSS_ATTR_HIGH);
  *((struct gdt_desc *)0xc0000928) = make_gdt_desc(
c0004449:	bb 28 09 00 c0       	mov    $0xc0000928,%ebx
c000444e:	8d 45 e0             	lea    -0x20(%ebp),%eax
c0004451:	83 ec 0c             	sub    $0xc,%esp
c0004454:	68 c0 00 00 00       	push   $0xc0
c0004459:	68 f8 00 00 00       	push   $0xf8
c000445e:	68 ff ff 0f 00       	push   $0xfffff
c0004463:	6a 00                	push   $0x0
c0004465:	50                   	push   %eax
c0004466:	e8 fc fe ff ff       	call   c0004367 <make_gdt_desc>
c000446b:	83 c4 1c             	add    $0x1c,%esp
c000446e:	8b 45 e0             	mov    -0x20(%ebp),%eax
c0004471:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c0004474:	89 03                	mov    %eax,(%ebx)
c0004476:	89 53 04             	mov    %edx,0x4(%ebx)
      (uint32_t *)0, 0xfffff, GDT_CODE_ATTR_LOW_DPL3, GDT_ATTR_HIGH);
  *((struct gdt_desc *)0xc0000930) = make_gdt_desc(
c0004479:	bb 30 09 00 c0       	mov    $0xc0000930,%ebx
c000447e:	8d 45 e0             	lea    -0x20(%ebp),%eax
c0004481:	83 ec 0c             	sub    $0xc,%esp
c0004484:	68 c0 00 00 00       	push   $0xc0
c0004489:	68 f2 00 00 00       	push   $0xf2
c000448e:	68 ff ff 0f 00       	push   $0xfffff
c0004493:	6a 00                	push   $0x0
c0004495:	50                   	push   %eax
c0004496:	e8 cc fe ff ff       	call   c0004367 <make_gdt_desc>
c000449b:	83 c4 1c             	add    $0x1c,%esp
c000449e:	8b 45 e0             	mov    -0x20(%ebp),%eax
c00044a1:	8b 55 e4             	mov    -0x1c(%ebp),%edx
c00044a4:	89 03                	mov    %eax,(%ebx)
c00044a6:	89 53 04             	mov    %edx,0x4(%ebx)
      (uint32_t *)0, 0xfffff, GDT_DATA_ATTR_LOW_DPL3, GDT_ATTR_HIGH);

  // 16位表界限 & 32位表起始地址
  uint64_t gdt_operand = ((8 * 7 - 1) | ((uint64_t)(uint32_t)0xc0000900 << 16));
c00044a9:	c7 45 e8 37 00 00 09 	movl   $0x9000037,-0x18(%ebp)
c00044b0:	c7 45 ec 00 c0 00 00 	movl   $0xc000,-0x14(%ebp)
  asm volatile("lgdt %0" : : "m"(gdt_operand));  // GDT变更，重新加载GDT
c00044b7:	0f 01 55 e8          	lgdtl  -0x18(%ebp)
  asm volatile("ltr %w0" : : "r"(SELECTOR_TSS)); // 将tss加载到TR
c00044bb:	b8 20 00 00 00       	mov    $0x20,%eax
c00044c0:	0f 00 d8             	ltr    %ax
  put_str("tss_init and ltr done\n");
c00044c3:	83 ec 0c             	sub    $0xc,%esp
c00044c6:	68 04 5c 00 c0       	push   $0xc0005c04
c00044cb:	e8 40 d6 ff ff       	call   c0001b10 <put_str>
c00044d0:	83 c4 10             	add    $0x10,%esp
c00044d3:	90                   	nop
c00044d4:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c00044d7:	c9                   	leave  
c00044d8:	c3                   	ret    

c00044d9 <start_process>:
#include "userprog.h"

extern void intr_exit(void);

// 创建用户进程filename的上下文（填充用户进程的中断栈intr_stack
void start_process(void *filename_) {
c00044d9:	55                   	push   %ebp
c00044da:	89 e5                	mov    %esp,%ebp
c00044dc:	83 ec 18             	sub    $0x18,%esp
  void *func = filename_;
c00044df:	8b 45 08             	mov    0x8(%ebp),%eax
c00044e2:	89 45 f4             	mov    %eax,-0xc(%ebp)
  struct task_struct *cur = running_thread();
c00044e5:	e8 1c ed ff ff       	call   c0003206 <running_thread>
c00044ea:	89 45 f0             	mov    %eax,-0x10(%ebp)
  cur->self_kstack +=
c00044ed:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00044f0:	8b 00                	mov    (%eax),%eax
c00044f2:	8d 90 80 00 00 00    	lea    0x80(%eax),%edx
c00044f8:	8b 45 f0             	mov    -0x10(%ebp),%eax
c00044fb:	89 10                	mov    %edx,(%eax)
  /*
   *【创建线程的时候没预留但是运行正常的原因猜测】
   * 此时处与内核态，指针可能指向了内核空间。
   * PCB放在内核空间中，导致越界的空间可能是刚好初始化预留过的
   */
  struct intr_stack *proc_stack = (struct intr_stack *)cur->self_kstack;
c00044fd:	8b 45 f0             	mov    -0x10(%ebp),%eax
c0004500:	8b 00                	mov    (%eax),%eax
c0004502:	89 45 ec             	mov    %eax,-0x14(%ebp)
  proc_stack->edi = 0;
c0004505:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004508:	c7 40 04 00 00 00 00 	movl   $0x0,0x4(%eax)
  proc_stack->esi = 0;
c000450f:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004512:	c7 40 08 00 00 00 00 	movl   $0x0,0x8(%eax)
  proc_stack->ebp = 0;
c0004519:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000451c:	c7 40 0c 00 00 00 00 	movl   $0x0,0xc(%eax)
  proc_stack->esp_dummy = 0;
c0004523:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004526:	c7 40 10 00 00 00 00 	movl   $0x0,0x10(%eax)

  proc_stack->ebx = 0;
c000452d:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004530:	c7 40 14 00 00 00 00 	movl   $0x0,0x14(%eax)
  proc_stack->edx = 0;
c0004537:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000453a:	c7 40 18 00 00 00 00 	movl   $0x0,0x18(%eax)
  proc_stack->ecx = 0;
c0004541:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004544:	c7 40 1c 00 00 00 00 	movl   $0x0,0x1c(%eax)
  proc_stack->eax = 0;
c000454b:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000454e:	c7 40 20 00 00 00 00 	movl   $0x0,0x20(%eax)

  proc_stack->gs = 0; // 显存段用户态用不上
c0004555:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004558:	c7 40 24 00 00 00 00 	movl   $0x0,0x24(%eax)

  proc_stack->ds = SELECTOR_U_DATA;
c000455f:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004562:	c7 40 30 33 00 00 00 	movl   $0x33,0x30(%eax)
  proc_stack->es = SELECTOR_U_DATA;
c0004569:	8b 45 ec             	mov    -0x14(%ebp),%eax
c000456c:	c7 40 2c 33 00 00 00 	movl   $0x33,0x2c(%eax)
  proc_stack->fs = SELECTOR_U_DATA;
c0004573:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004576:	c7 40 28 33 00 00 00 	movl   $0x33,0x28(%eax)

  proc_stack->eip = func; // 待执行的用户程序
c000457d:	8b 55 f4             	mov    -0xc(%ebp),%edx
c0004580:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004583:	89 50 38             	mov    %edx,0x38(%eax)
  proc_stack->cs = SELECTOR_U_CODE;
c0004586:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004589:	c7 40 3c 2b 00 00 00 	movl   $0x2b,0x3c(%eax)
  proc_stack->eflags = (EFLAGS_IOPL_0 | EFLAGS_MBS | EFLAGS_IF_1);
c0004590:	8b 45 ec             	mov    -0x14(%ebp),%eax
c0004593:	c7 40 40 02 02 00 00 	movl   $0x202,0x40(%eax)

  // 为用户进程分配3特权级栈->（esp指向从用户内存池中分配的地址
  proc_stack->esp =
      (void *)((uint32_t)get_a_page(PF_USER, USER_STACK3_VADDR) + PG_SIZE);
c000459a:	83 ec 08             	sub    $0x8,%esp
c000459d:	68 00 f0 ff bf       	push   $0xbffff000
c00045a2:	6a 02                	push   $0x2
c00045a4:	e8 96 e8 ff ff       	call   c0002e3f <get_a_page>
c00045a9:	83 c4 10             	add    $0x10,%esp
c00045ac:	05 00 10 00 00       	add    $0x1000,%eax
c00045b1:	89 c2                	mov    %eax,%edx
  proc_stack->esp =
c00045b3:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00045b6:	89 50 44             	mov    %edx,0x44(%eax)
  proc_stack->ss = SELECTOR_U_DATA; // 栈段
c00045b9:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00045bc:	c7 40 48 33 00 00 00 	movl   $0x33,0x48(%eax)

  asm volatile("movl %0, %%esp; jmp intr_exit" ::"g"(proc_stack) : "memory");
c00045c3:	8b 65 ec             	mov    -0x14(%ebp),%esp
c00045c6:	e9 95 d6 ff ff       	jmp    c0001c60 <intr_exit>
}
c00045cb:	90                   	nop
c00045cc:	c9                   	leave  
c00045cd:	c3                   	ret    

c00045ce <page_dir_activate>:

// 激活进程/线程页表-> 更新cr3
void page_dir_activate(struct task_struct *p_thread) {
c00045ce:	55                   	push   %ebp
c00045cf:	89 e5                	mov    %esp,%ebp
c00045d1:	83 ec 18             	sub    $0x18,%esp
  // 内核线程，默认为内核页目录物理地址
  uint32_t pagedir_phy_addr = 0x100000;
c00045d4:	c7 45 f4 00 00 10 00 	movl   $0x100000,-0xc(%ebp)
  if (p_thread->pgdir != NULL) { // 用户进程有自己的页目录表
c00045db:	8b 45 08             	mov    0x8(%ebp),%eax
c00045de:	8b 40 34             	mov    0x34(%eax),%eax
c00045e1:	85 c0                	test   %eax,%eax
c00045e3:	74 15                	je     c00045fa <page_dir_activate+0x2c>
    pagedir_phy_addr = addr_v2p((uint32_t)p_thread->pgdir);
c00045e5:	8b 45 08             	mov    0x8(%ebp),%eax
c00045e8:	8b 40 34             	mov    0x34(%eax),%eax
c00045eb:	83 ec 0c             	sub    $0xc,%esp
c00045ee:	50                   	push   %eax
c00045ef:	e8 a6 e9 ff ff       	call   c0002f9a <addr_v2p>
c00045f4:	83 c4 10             	add    $0x10,%esp
c00045f7:	89 45 f4             	mov    %eax,-0xc(%ebp)
  }
  asm volatile("movl %0, %%cr3" ::"r"(pagedir_phy_addr) : "memory");
c00045fa:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00045fd:	0f 22 d8             	mov    %eax,%cr3
}
c0004600:	90                   	nop
c0004601:	c9                   	leave  
c0004602:	c3                   	ret    

c0004603 <process_active>:

// 激活页表，并根据任务是否为进程来修改tss.esp0
void process_active(struct task_struct *p_thread) {
c0004603:	55                   	push   %ebp
c0004604:	89 e5                	mov    %esp,%ebp
c0004606:	83 ec 08             	sub    $0x8,%esp
  ASSERT(p_thread != NULL);
c0004609:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
c000460d:	75 19                	jne    c0004628 <process_active+0x25>
c000460f:	68 1c 5c 00 c0       	push   $0xc0005c1c
c0004614:	68 d8 5c 00 c0       	push   $0xc0005cd8
c0004619:	6a 44                	push   $0x44
c000461b:	68 2d 5c 00 c0       	push   $0xc0005c2d
c0004620:	e8 0f dd ff ff       	call   c0002334 <panic_spin>
c0004625:	83 c4 10             	add    $0x10,%esp
  page_dir_activate(p_thread);
c0004628:	83 ec 0c             	sub    $0xc,%esp
c000462b:	ff 75 08             	push   0x8(%ebp)
c000462e:	e8 9b ff ff ff       	call   c00045ce <page_dir_activate>
c0004633:	83 c4 10             	add    $0x10,%esp

  if (p_thread->pgdir) {
c0004636:	8b 45 08             	mov    0x8(%ebp),%eax
c0004639:	8b 40 34             	mov    0x34(%eax),%eax
c000463c:	85 c0                	test   %eax,%eax
c000463e:	74 0e                	je     c000464e <process_active+0x4b>
    // 更新tss.esp0-> 进程的特权级0栈，用于此进程中断进入内核态下保留上下文
    update_tss_esp(p_thread);
c0004640:	83 ec 0c             	sub    $0xc,%esp
c0004643:	ff 75 08             	push   0x8(%ebp)
c0004646:	e8 09 fd ff ff       	call   c0004354 <update_tss_esp>
c000464b:	83 c4 10             	add    $0x10,%esp
  }
}
c000464e:	90                   	nop
c000464f:	c9                   	leave  
c0004650:	c3                   	ret    

c0004651 <create_page_dir>:

// 创建页目录表，返回页目录虚拟地址
uint32_t *create_page_dir(void) {
c0004651:	55                   	push   %ebp
c0004652:	89 e5                	mov    %esp,%ebp
c0004654:	83 ec 18             	sub    $0x18,%esp
  uint32_t *page_dir_vaddr = get_kernel_pages(1); // 内核空间申请
c0004657:	83 ec 0c             	sub    $0xc,%esp
c000465a:	6a 01                	push   $0x1
c000465c:	e8 48 e7 ff ff       	call   c0002da9 <get_kernel_pages>
c0004661:	83 c4 10             	add    $0x10,%esp
c0004664:	89 45 f4             	mov    %eax,-0xc(%ebp)
  if (page_dir_vaddr == NULL) {
c0004667:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
c000466b:	75 17                	jne    c0004684 <create_page_dir+0x33>
    console_put_str("create_page_dir: get_kernel_page failed!");
c000466d:	83 ec 0c             	sub    $0xc,%esp
c0004670:	68 40 5c 00 c0       	push   $0xc0005c40
c0004675:	e8 a7 f6 ff ff       	call   c0003d21 <console_put_str>
c000467a:	83 c4 10             	add    $0x10,%esp
    return NULL;
c000467d:	b8 00 00 00 00       	mov    $0x0,%eax
c0004682:	eb 43                	jmp    c00046c7 <create_page_dir+0x76>
  }

  // 为让所有进程共享内核：将内核所在页目录项（访问内核的入口）复制到进程页目录项目的同等位置
  // 1、复制页表（page_dir_vaddr + 0x300*4 ：内核页目录第768项
  memcpy((uint32_t *)((uint32_t)page_dir_vaddr + 0x300 * 4),
c0004684:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0004687:	05 00 0c 00 00       	add    $0xc00,%eax
c000468c:	83 ec 04             	sub    $0x4,%esp
c000468f:	68 00 04 00 00       	push   $0x400
c0004694:	68 00 fc ff ff       	push   $0xfffffc00
c0004699:	50                   	push   %eax
c000469a:	e8 be dd ff ff       	call   c000245d <memcpy>
c000469f:	83 c4 10             	add    $0x10,%esp
         (uint32_t *)(0xfffff000 + 0x300 * 4), 1024);
  // 2、更新页目录地址
  uint32_t new_page_dir_phy_addr = addr_v2p((uint32_t)page_dir_vaddr);
c00046a2:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00046a5:	83 ec 0c             	sub    $0xc,%esp
c00046a8:	50                   	push   %eax
c00046a9:	e8 ec e8 ff ff       	call   c0002f9a <addr_v2p>
c00046ae:	83 c4 10             	add    $0x10,%esp
c00046b1:	89 45 f0             	mov    %eax,-0x10(%ebp)
  page_dir_vaddr[1023] =
c00046b4:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00046b7:	05 fc 0f 00 00       	add    $0xffc,%eax
      new_page_dir_phy_addr | PG_US_U | PG_RW_W | PG_P_1; // 最后一项指向自己
c00046bc:	8b 55 f0             	mov    -0x10(%ebp),%edx
c00046bf:	83 ca 07             	or     $0x7,%edx
  page_dir_vaddr[1023] =
c00046c2:	89 10                	mov    %edx,(%eax)

  return page_dir_vaddr;
c00046c4:	8b 45 f4             	mov    -0xc(%ebp),%eax
}
c00046c7:	c9                   	leave  
c00046c8:	c3                   	ret    

c00046c9 <create_user_vaddr_bitmap>:

// 创建用户进程的虚拟内存池（bitmap
void create_user_vaddr_bitmap(struct task_struct *user_prog) {
c00046c9:	55                   	push   %ebp
c00046ca:	89 e5                	mov    %esp,%ebp
c00046cc:	83 ec 18             	sub    $0x18,%esp
  user_prog->userprog_vaddr.vaddr_start = USER_VADDR_START;
c00046cf:	8b 45 08             	mov    0x8(%ebp),%eax
c00046d2:	c7 40 40 00 80 04 08 	movl   $0x8048000,0x40(%eax)
  uint32_t bitmap_pg_cnt =
c00046d9:	c7 45 f4 17 00 00 00 	movl   $0x17,-0xc(%ebp)
      DIV_ROUND_UP((0xc0000000 - USER_VADDR_START) / PG_SIZE / 8, PG_SIZE);
  user_prog->userprog_vaddr.vaddr_bitmap.bits = get_kernel_pages(bitmap_pg_cnt);
c00046e0:	83 ec 0c             	sub    $0xc,%esp
c00046e3:	ff 75 f4             	push   -0xc(%ebp)
c00046e6:	e8 be e6 ff ff       	call   c0002da9 <get_kernel_pages>
c00046eb:	83 c4 10             	add    $0x10,%esp
c00046ee:	8b 55 08             	mov    0x8(%ebp),%edx
c00046f1:	89 42 3c             	mov    %eax,0x3c(%edx)
  user_prog->userprog_vaddr.vaddr_bitmap.btmp_bytes_len =
c00046f4:	8b 45 08             	mov    0x8(%ebp),%eax
c00046f7:	c7 40 38 f7 6f 01 00 	movl   $0x16ff7,0x38(%eax)
      (0xc0000000 - USER_VADDR_START) / PG_SIZE / 8;
  bitmap_init(&user_prog->userprog_vaddr.vaddr_bitmap);
c00046fe:	8b 45 08             	mov    0x8(%ebp),%eax
c0004701:	83 c0 38             	add    $0x38,%eax
c0004704:	83 ec 0c             	sub    $0xc,%esp
c0004707:	50                   	push   %eax
c0004708:	e8 cb e0 ff ff       	call   c00027d8 <bitmap_init>
c000470d:	83 c4 10             	add    $0x10,%esp
}
c0004710:	90                   	nop
c0004711:	c9                   	leave  
c0004712:	c3                   	ret    

c0004713 <process_execute>:

// 创建用户进程
void process_execute(void *filename, char *name) { // filename：用户进程地址
c0004713:	55                   	push   %ebp
c0004714:	89 e5                	mov    %esp,%ebp
c0004716:	83 ec 18             	sub    $0x18,%esp
  struct task_struct *thread = get_kernel_pages(1);
c0004719:	83 ec 0c             	sub    $0xc,%esp
c000471c:	6a 01                	push   $0x1
c000471e:	e8 86 e6 ff ff       	call   c0002da9 <get_kernel_pages>
c0004723:	83 c4 10             	add    $0x10,%esp
c0004726:	89 45 f4             	mov    %eax,-0xc(%ebp)
  init_thread(thread, name, default_prio);
c0004729:	83 ec 04             	sub    $0x4,%esp
c000472c:	6a 14                	push   $0x14
c000472e:	ff 75 0c             	push   0xc(%ebp)
c0004731:	ff 75 f4             	push   -0xc(%ebp)
c0004734:	e8 b4 eb ff ff       	call   c00032ed <init_thread>
c0004739:	83 c4 10             	add    $0x10,%esp
  create_user_vaddr_bitmap(thread);
c000473c:	83 ec 0c             	sub    $0xc,%esp
c000473f:	ff 75 f4             	push   -0xc(%ebp)
c0004742:	e8 82 ff ff ff       	call   c00046c9 <create_user_vaddr_bitmap>
c0004747:	83 c4 10             	add    $0x10,%esp
  thread_create(thread, start_process, filename);
c000474a:	83 ec 04             	sub    $0x4,%esp
c000474d:	ff 75 08             	push   0x8(%ebp)
c0004750:	68 d9 44 00 c0       	push   $0xc00044d9
c0004755:	ff 75 f4             	push   -0xc(%ebp)
c0004758:	e8 19 eb ff ff       	call   c0003276 <thread_create>
c000475d:	83 c4 10             	add    $0x10,%esp
  thread->pgdir = create_page_dir();
c0004760:	e8 ec fe ff ff       	call   c0004651 <create_page_dir>
c0004765:	8b 55 f4             	mov    -0xc(%ebp),%edx
c0004768:	89 42 34             	mov    %eax,0x34(%edx)

  enum intr_status old_status = intr_disable();
c000476b:	e8 ad d2 ff ff       	call   c0001a1d <intr_disable>
c0004770:	89 45 f0             	mov    %eax,-0x10(%ebp)
  ASSERT(!elem_find(&thread_ready_list, &thread->general_tag));
c0004773:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0004776:	83 c0 24             	add    $0x24,%eax
c0004779:	83 ec 08             	sub    $0x8,%esp
c000477c:	50                   	push   %eax
c000477d:	68 5c 8a 00 c0       	push   $0xc0008a5c
c0004782:	e8 3d f1 ff ff       	call   c00038c4 <elem_find>
c0004787:	83 c4 10             	add    $0x10,%esp
c000478a:	85 c0                	test   %eax,%eax
c000478c:	74 19                	je     c00047a7 <process_execute+0x94>
c000478e:	68 6c 5c 00 c0       	push   $0xc0005c6c
c0004793:	68 e8 5c 00 c0       	push   $0xc0005ce8
c0004798:	6a 75                	push   $0x75
c000479a:	68 2d 5c 00 c0       	push   $0xc0005c2d
c000479f:	e8 90 db ff ff       	call   c0002334 <panic_spin>
c00047a4:	83 c4 10             	add    $0x10,%esp
  list_append(&thread_ready_list, &thread->general_tag);
c00047a7:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00047aa:	83 c0 24             	add    $0x24,%eax
c00047ad:	83 ec 08             	sub    $0x8,%esp
c00047b0:	50                   	push   %eax
c00047b1:	68 5c 8a 00 c0       	push   $0xc0008a5c
c00047b6:	e8 8f f0 ff ff       	call   c000384a <list_append>
c00047bb:	83 c4 10             	add    $0x10,%esp

  ASSERT(!elem_find(&thread_all_list, &thread->all_list_tag));
c00047be:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00047c1:	83 c0 2c             	add    $0x2c,%eax
c00047c4:	83 ec 08             	sub    $0x8,%esp
c00047c7:	50                   	push   %eax
c00047c8:	68 6c 8a 00 c0       	push   $0xc0008a6c
c00047cd:	e8 f2 f0 ff ff       	call   c00038c4 <elem_find>
c00047d2:	83 c4 10             	add    $0x10,%esp
c00047d5:	85 c0                	test   %eax,%eax
c00047d7:	74 19                	je     c00047f2 <process_execute+0xdf>
c00047d9:	68 a4 5c 00 c0       	push   $0xc0005ca4
c00047de:	68 e8 5c 00 c0       	push   $0xc0005ce8
c00047e3:	6a 78                	push   $0x78
c00047e5:	68 2d 5c 00 c0       	push   $0xc0005c2d
c00047ea:	e8 45 db ff ff       	call   c0002334 <panic_spin>
c00047ef:	83 c4 10             	add    $0x10,%esp
    list_append(&thread_all_list, &thread->all_list_tag);
c00047f2:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00047f5:	83 c0 2c             	add    $0x2c,%eax
c00047f8:	83 ec 08             	sub    $0x8,%esp
c00047fb:	50                   	push   %eax
c00047fc:	68 6c 8a 00 c0       	push   $0xc0008a6c
c0004801:	e8 44 f0 ff ff       	call   c000384a <list_append>
c0004806:	83 c4 10             	add    $0x10,%esp
  intr_set_status(old_status);
c0004809:	83 ec 0c             	sub    $0xc,%esp
c000480c:	ff 75 f0             	push   -0x10(%ebp)
c000480f:	e8 4f d2 ff ff       	call   c0001a63 <intr_set_status>
c0004814:	83 c4 10             	add    $0x10,%esp
c0004817:	90                   	nop
c0004818:	c9                   	leave  
c0004819:	c3                   	ret    

c000481a <getpid>:
    retval;                                                                    \
  })

// 系统调用用户接口

uint32_t getpid() { return _syscall0(SYS_GETPID); }
c000481a:	55                   	push   %ebp
c000481b:	89 e5                	mov    %esp,%ebp
c000481d:	83 ec 10             	sub    $0x10,%esp
c0004820:	b8 00 00 00 00       	mov    $0x0,%eax
c0004825:	cd 80                	int    $0x80
c0004827:	89 45 fc             	mov    %eax,-0x4(%ebp)
c000482a:	8b 45 fc             	mov    -0x4(%ebp),%eax
c000482d:	c9                   	leave  
c000482e:	c3                   	ret    

c000482f <write>:

c000482f:	55                   	push   %ebp
c0004830:	89 e5                	mov    %esp,%ebp
c0004832:	53                   	push   %ebx
c0004833:	83 ec 10             	sub    $0x10,%esp
c0004836:	b8 01 00 00 00       	mov    $0x1,%eax
c000483b:	8b 55 08             	mov    0x8(%ebp),%edx
c000483e:	89 d3                	mov    %edx,%ebx
c0004840:	cd 80                	int    $0x80
c0004842:	89 45 f8             	mov    %eax,-0x8(%ebp)
c0004845:	8b 45 f8             	mov    -0x8(%ebp),%eax
c0004848:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c000484b:	c9                   	leave  
c000484c:	c3                   	ret    

c000484d <sys_getpid>:

#define syscall_nr 32 // 最大支持的系统调用子功能个数
typedef void *syscall;
syscall syscall_table[syscall_nr];

uint32_t sys_getpid(void) { return running_thread()->pid; }
c000484d:	55                   	push   %ebp
c000484e:	89 e5                	mov    %esp,%ebp
c0004850:	83 ec 08             	sub    $0x8,%esp
c0004853:	e8 ae e9 ff ff       	call   c0003206 <running_thread>
c0004858:	0f b7 40 04          	movzwl 0x4(%eax),%eax
c000485c:	98                   	cwtl   
c000485d:	c9                   	leave  
c000485e:	c3                   	ret    

c000485f <sys_write>:

// 打印字符串str（未实现文件系统前的丐版）
uint32_t sys_write(char *str) {
c000485f:	55                   	push   %ebp
c0004860:	89 e5                	mov    %esp,%ebp
c0004862:	83 ec 08             	sub    $0x8,%esp
  console_put_str(str);
c0004865:	83 ec 0c             	sub    $0xc,%esp
c0004868:	ff 75 08             	push   0x8(%ebp)
c000486b:	e8 b1 f4 ff ff       	call   c0003d21 <console_put_str>
c0004870:	83 c4 10             	add    $0x10,%esp
  return strlen(str);
c0004873:	83 ec 0c             	sub    $0xc,%esp
c0004876:	ff 75 08             	push   0x8(%ebp)
c0004879:	e8 18 dd ff ff       	call   c0002596 <strlen>
c000487e:	83 c4 10             	add    $0x10,%esp
}
c0004881:	c9                   	leave  
c0004882:	c3                   	ret    

c0004883 <syscall_init>:

// 初始化系统调用
void syscall_init(void) {
c0004883:	55                   	push   %ebp
c0004884:	89 e5                	mov    %esp,%ebp
c0004886:	83 ec 08             	sub    $0x8,%esp
  put_str("syscall_init start\n");
c0004889:	83 ec 0c             	sub    $0xc,%esp
c000488c:	68 f8 5c 00 c0       	push   $0xc0005cf8
c0004891:	e8 7a d2 ff ff       	call   c0001b10 <put_str>
c0004896:	83 c4 10             	add    $0x10,%esp
  syscall_table[SYS_GETPID] = sys_getpid;
c0004899:	c7 05 c0 8b 00 c0 4d 	movl   $0xc000484d,0xc0008bc0
c00048a0:	48 00 c0 
  syscall_table[SYS_WRITE] = sys_write;
c00048a3:	c7 05 c4 8b 00 c0 5f 	movl   $0xc000485f,0xc0008bc4
c00048aa:	48 00 c0 
  put_str("syscall_init done\n");
c00048ad:	83 ec 0c             	sub    $0xc,%esp
c00048b0:	68 0c 5d 00 c0       	push   $0xc0005d0c
c00048b5:	e8 56 d2 ff ff       	call   c0001b10 <put_str>
c00048ba:	83 c4 10             	add    $0x10,%esp
c00048bd:	90                   	nop
c00048be:	c9                   	leave  
c00048bf:	c3                   	ret    

c00048c0 <iota>:
#define va_start(ap, v) ap = (va_list)&v // 初始化指针ap向第一个固定参数v
#define va_arg(ap, t) *((t *)(ap += 4)) // ap指向下个参数并返回其值
#define va_end(ap) ap = NULL            // 清除ap

// 整型int转字符ASCII（base：转换的进制
static void iota(uint32_t value, char **buf_ptr_addr, uint8_t base) {
c00048c0:	55                   	push   %ebp
c00048c1:	89 e5                	mov    %esp,%ebp
c00048c3:	53                   	push   %ebx
c00048c4:	83 ec 24             	sub    $0x24,%esp
c00048c7:	8b 45 10             	mov    0x10(%ebp),%eax
c00048ca:	88 45 e4             	mov    %al,-0x1c(%ebp)
  uint32_t m = value % base; // 求模（最先掉低位但最后写入缓冲区
c00048cd:	0f b6 4d e4          	movzbl -0x1c(%ebp),%ecx
c00048d1:	8b 45 08             	mov    0x8(%ebp),%eax
c00048d4:	ba 00 00 00 00       	mov    $0x0,%edx
c00048d9:	f7 f1                	div    %ecx
c00048db:	89 55 f4             	mov    %edx,-0xc(%ebp)
  uint32_t i = value / base; // 取整
c00048de:	0f b6 5d e4          	movzbl -0x1c(%ebp),%ebx
c00048e2:	8b 45 08             	mov    0x8(%ebp),%eax
c00048e5:	ba 00 00 00 00       	mov    $0x0,%edx
c00048ea:	f7 f3                	div    %ebx
c00048ec:	89 45 f0             	mov    %eax,-0x10(%ebp)

  if (i) {
c00048ef:	83 7d f0 00          	cmpl   $0x0,-0x10(%ebp)
c00048f3:	74 16                	je     c000490b <iota+0x4b>
    iota(i, buf_ptr_addr, base);
c00048f5:	0f b6 45 e4          	movzbl -0x1c(%ebp),%eax
c00048f9:	83 ec 04             	sub    $0x4,%esp
c00048fc:	50                   	push   %eax
c00048fd:	ff 75 0c             	push   0xc(%ebp)
c0004900:	ff 75 f0             	push   -0x10(%ebp)
c0004903:	e8 b8 ff ff ff       	call   c00048c0 <iota>
c0004908:	83 c4 10             	add    $0x10,%esp
  }
  if (m < 10) {
c000490b:	83 7d f4 09          	cmpl   $0x9,-0xc(%ebp)
c000490f:	77 19                	ja     c000492a <iota+0x6a>
    //将数字 0～9 转换为字符'0'～'9'
    *((*buf_ptr_addr)++) = m + '0';
c0004911:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0004914:	8d 58 30             	lea    0x30(%eax),%ebx
c0004917:	8b 45 0c             	mov    0xc(%ebp),%eax
c000491a:	8b 00                	mov    (%eax),%eax
c000491c:	8d 48 01             	lea    0x1(%eax),%ecx
c000491f:	8b 55 0c             	mov    0xc(%ebp),%edx
c0004922:	89 0a                	mov    %ecx,(%edx)
c0004924:	89 da                	mov    %ebx,%edx
c0004926:	88 10                	mov    %dl,(%eax)
  } else {
    //将数字 A～F 转换为字符'A'～'F'
    *((*buf_ptr_addr)++) = m - 10 + 'A';
  }
}
c0004928:	eb 17                	jmp    c0004941 <iota+0x81>
    *((*buf_ptr_addr)++) = m - 10 + 'A';
c000492a:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000492d:	8d 58 37             	lea    0x37(%eax),%ebx
c0004930:	8b 45 0c             	mov    0xc(%ebp),%eax
c0004933:	8b 00                	mov    (%eax),%eax
c0004935:	8d 48 01             	lea    0x1(%eax),%ecx
c0004938:	8b 55 0c             	mov    0xc(%ebp),%edx
c000493b:	89 0a                	mov    %ecx,(%edx)
c000493d:	89 da                	mov    %ebx,%edx
c000493f:	88 10                	mov    %dl,(%eax)
}
c0004941:	90                   	nop
c0004942:	8b 5d fc             	mov    -0x4(%ebp),%ebx
c0004945:	c9                   	leave  
c0004946:	c3                   	ret    

c0004947 <vsprint>:

// 将参数ap按照格式format输出到字符串str，返回替换后str长度
uint32_t vsprint(char *str, const char *format, va_list ap) {
c0004947:	55                   	push   %ebp
c0004948:	89 e5                	mov    %esp,%ebp
c000494a:	83 ec 18             	sub    $0x18,%esp
  char *buf_ptr = str;
c000494d:	8b 45 08             	mov    0x8(%ebp),%eax
c0004950:	89 45 e8             	mov    %eax,-0x18(%ebp)
  const char *index_ptr = format;
c0004953:	8b 45 0c             	mov    0xc(%ebp),%eax
c0004956:	89 45 f4             	mov    %eax,-0xc(%ebp)
  char index_char = *index_ptr; // 指向format中的每个字符
c0004959:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000495c:	0f b6 00             	movzbl (%eax),%eax
c000495f:	88 45 f3             	mov    %al,-0xd(%ebp)
  int32_t arg_int;

  while (index_char) {
c0004962:	eb 69                	jmp    c00049cd <vsprint+0x86>
    if (index_char != '%') {
c0004964:	80 7d f3 25          	cmpb   $0x25,-0xd(%ebp)
c0004968:	74 1e                	je     c0004988 <vsprint+0x41>
      *(buf_ptr)++ = index_char;
c000496a:	8b 45 e8             	mov    -0x18(%ebp),%eax
c000496d:	8d 50 01             	lea    0x1(%eax),%edx
c0004970:	89 55 e8             	mov    %edx,-0x18(%ebp)
c0004973:	0f b6 55 f3          	movzbl -0xd(%ebp),%edx
c0004977:	88 10                	mov    %dl,(%eax)
      index_char = *(++index_ptr);
c0004979:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
c000497d:	8b 45 f4             	mov    -0xc(%ebp),%eax
c0004980:	0f b6 00             	movzbl (%eax),%eax
c0004983:	88 45 f3             	mov    %al,-0xd(%ebp)
      continue;
c0004986:	eb 45                	jmp    c00049cd <vsprint+0x86>
    }
    index_char = *(++index_ptr); // 得到%后面的字符
c0004988:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
c000498c:	8b 45 f4             	mov    -0xc(%ebp),%eax
c000498f:	0f b6 00             	movzbl (%eax),%eax
c0004992:	88 45 f3             	mov    %al,-0xd(%ebp)

    switch (index_char) {
c0004995:	0f be 45 f3          	movsbl -0xd(%ebp),%eax
c0004999:	83 f8 78             	cmp    $0x78,%eax
c000499c:	75 2f                	jne    c00049cd <vsprint+0x86>
    case 'x':
      arg_int = va_arg(ap, int);
c000499e:	83 45 10 04          	addl   $0x4,0x10(%ebp)
c00049a2:	8b 45 10             	mov    0x10(%ebp),%eax
c00049a5:	8b 00                	mov    (%eax),%eax
c00049a7:	89 45 ec             	mov    %eax,-0x14(%ebp)
      iota(arg_int, &buf_ptr, 16);
c00049aa:	8b 45 ec             	mov    -0x14(%ebp),%eax
c00049ad:	83 ec 04             	sub    $0x4,%esp
c00049b0:	6a 10                	push   $0x10
c00049b2:	8d 55 e8             	lea    -0x18(%ebp),%edx
c00049b5:	52                   	push   %edx
c00049b6:	50                   	push   %eax
c00049b7:	e8 04 ff ff ff       	call   c00048c0 <iota>
c00049bc:	83 c4 10             	add    $0x10,%esp
      index_char = *(++index_ptr); // 跳过格式字符并更新index_char
c00049bf:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
c00049c3:	8b 45 f4             	mov    -0xc(%ebp),%eax
c00049c6:	0f b6 00             	movzbl (%eax),%eax
c00049c9:	88 45 f3             	mov    %al,-0xd(%ebp)
      break;
c00049cc:	90                   	nop
  while (index_char) {
c00049cd:	80 7d f3 00          	cmpb   $0x0,-0xd(%ebp)
c00049d1:	75 91                	jne    c0004964 <vsprint+0x1d>
    }
  }

  return strlen(str);
c00049d3:	83 ec 0c             	sub    $0xc,%esp
c00049d6:	ff 75 08             	push   0x8(%ebp)
c00049d9:	e8 b8 db ff ff       	call   c0002596 <strlen>
c00049de:	83 c4 10             	add    $0x10,%esp
}
c00049e1:	c9                   	leave  
c00049e2:	c3                   	ret    

c00049e3 <printf>:

// 格式化format
uint32_t printf(const char *format, ...) {
c00049e3:	55                   	push   %ebp
c00049e4:	89 e5                	mov    %esp,%ebp
c00049e6:	57                   	push   %edi
c00049e7:	81 ec 14 04 00 00    	sub    $0x414,%esp
  va_list args; // args指向参数
  va_start(args, format);
c00049ed:	8d 45 08             	lea    0x8(%ebp),%eax
c00049f0:	89 45 f4             	mov    %eax,-0xc(%ebp)
  char buf[1024] = {0}; // 存储拼接后的字符串
c00049f3:	c7 85 f4 fb ff ff 00 	movl   $0x0,-0x40c(%ebp)
c00049fa:	00 00 00 
c00049fd:	8d 95 f8 fb ff ff    	lea    -0x408(%ebp),%edx
c0004a03:	b8 00 00 00 00       	mov    $0x0,%eax
c0004a08:	b9 ff 00 00 00       	mov    $0xff,%ecx
c0004a0d:	89 d7                	mov    %edx,%edi
c0004a0f:	f3 ab                	rep stos %eax,%es:(%edi)
  vsprint(buf, format, args);
c0004a11:	8b 45 08             	mov    0x8(%ebp),%eax
c0004a14:	83 ec 04             	sub    $0x4,%esp
c0004a17:	ff 75 f4             	push   -0xc(%ebp)
c0004a1a:	50                   	push   %eax
c0004a1b:	8d 85 f4 fb ff ff    	lea    -0x40c(%ebp),%eax
c0004a21:	50                   	push   %eax
c0004a22:	e8 20 ff ff ff       	call   c0004947 <vsprint>
c0004a27:	83 c4 10             	add    $0x10,%esp
  va_end(args);
c0004a2a:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%ebp)
  return write(buf);
c0004a31:	83 ec 0c             	sub    $0xc,%esp
c0004a34:	8d 85 f4 fb ff ff    	lea    -0x40c(%ebp),%eax
c0004a3a:	50                   	push   %eax
c0004a3b:	e8 ef fd ff ff       	call   c000482f <write>
c0004a40:	83 c4 10             	add    $0x10,%esp
c0004a43:	8b 7d fc             	mov    -0x4(%ebp),%edi
c0004a46:	c9                   	leave  
c0004a47:	c3                   	ret    
