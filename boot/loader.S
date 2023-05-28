%include "boot.inc"

SECTION loader vstart=LOADER_BASE_ADDR  ;0x900
LOADER_STACK_TOP equ LOADER_BASE_ADDR   ;LOADER_STACK_TOP：loader在保护模式下的栈
                                        ;LOADER_BASE_ADDR：loader在实模式下时的栈指针地址

;构建全局描述表GDT，并分两段填充内部的段描述符（dd-> 4byte）
GDT_BASE: dd 0x00000000         ;NO.0-> 不可用置0
          dd 0x00000000

CODE_DESC: dd 0x0000FFFF        ;NO.1-> 代码段描述符
           dd DESC_CODE_HIGH4

DATA_STACK_DESC: dd 0x0000FFFF  ;NO.2-> 数据段和栈段描述符
                 dd DESC_DATA_HIGH4

                                ;NO.3-> 显存段描述符
VIDEO_DESC: dd 0x80000007       ;limit=(0xbffff-0xb8000)/4k=0x7
            dd DESC_VIDEO_HIGH4 ;此时 DPL 为0

GDT_SIZE equ $ - GDT_BASE       ;GDT大小
GDT_LIMIT equ GDT_SIZE - 1      ;段界限=GDT-1
times 60 dq 0                   ;此处预留60个描述符的空位

;构建选择子
SELECTOR_CODE equ (0x0001<<3) + TI_GDT + RPL0   ; 相当于((CODE_DESC - GDT_BASE)/8)<<3) + TI_GDT + RPL0
SELECTOR_DATA equ (0x0002<<3) + TI_GDT + RPL0   ; 同上
SELECTOR_VIDEO equ (0x0003<<3) + TI_GDT + RPL0  ; 同上

; 当前偏移 loader.bin 文件头0x200字节，loader.bin的加载地址是0x900
total_mem_bytes dd 0  ;保存内存容量（内存地址0xb03）

;以下是GDT的指针，前2字节（16位）是GDT界限，后4字节（32位）是GDT起始地址
gdt_ptr dw GDT_LIMIT
        dd GDT_BASE

;人工对齐:total_mem_bytes4+gdt_ptr6+ards_buf244+ards_nr2，共 256 字节
ards_buf times 244 db 0
ards_nr dw 0          ;用于记录ards结构体数量


;------------------------------------------------------------
;INT 0x15 中断
;子功能号:0xE0820、0xE801、0x88
;------------------------------------------------------------
;-> 0x00000c00
loader_start:
    ;------ int 15h eax = 0000E820h 获取内存大小 ------
    xor ebx, ebx        ;第一次调用时，ebx值要为0（此处用异或）
    mov edx, 0x534d4150 ;edx只赋值一次，循环体中不会改变
    mov di, ards_buf    ;ards结构缓冲区(es:di)
.e820_mem_get_loop:     ;循环获取每个ards内存范围描述结构
    mov eax, 0x0000e820 ;执行int 0x15后，eax值变为0x534d4150，所以每次执行int前都要更新为子功能号
    mov ecx, 20         ;ards地址范围描述符结构大小为20字节
    int 0x15
    jc .e820_mem_get_loop ;若cf位为1则有错误发生，尝试0xE801子功能
    add di, cx          ;使di+20字节指向缓冲区中新的ards结构位置
    inc word [ards_nr]  ;记录ards数量
    cmp ebx, 0          ;若ebx为0且cf不为1,说明ards全部返回，当前已是最后一个
    jnz .e820_mem_get_loop

;在所有的ards结构中找出(base_add_low + length_low)的最大值，即内存容量
    mov cx, [ards_nr]   ;遍历每一个ards结构体，循环次数是ards的数量
    mov ebx, ards_buf
    xor edx, edx        ;edx为最大内存容量，在此先清0
.find_max_mem_area:     ;无需判断type是否为1,最大内存块一定是可被使用的
    mov eax, [ebx]      ;base_add_low
    add eax, [ebx+8]    ;length_low
    add ebx, 20         ;指向缓冲区中下一个adrs结构
    cmp edx, eax        ;冒泡排序，找出最大，edx寄存器始终是最大的内存容量
    jge .next_ards
    mov edx, eax        ;edx为总内存大小
.next_ards:
    loop .find_max_mem_area
    jmp .mem_get_ok

;------ int 15h ax = E801h 获取内存大小，最大支持 4G ------
; 返回后ax、cx值一样,KB为单位，bx、dx值一样，以64KB为单位【ax、cx寄存器：低16MB，bx、dx寄存器：16MB-4GB】
.e820_failed_so_try_e801:
    mov ax, 0xe801
    int 0x51
    jc .e801_failed_so_try88    ;若当前 e801 方法失败，就尝试 0x88 方法

    ;1、算出低15MB的内存, ax、cx的内存数量以KB为单位【要转为byte】
    mov cx, 0x400
    mul cx              ;cx=1024kb, mul结果存在ax中（转byte）
    shl edx, 16
    and eax, 0x0000FFFF
    or edx, eax         ;eax+edx=总内存大小
    add edx, 0x100000   ;加1MB
    mov esi, edx        ;备份低15MB的内存容量

    ;2、将16MB以上的内存转为byte, bx、dx中的内存数量以64KB为单位
    xor eax, eax
    mov ax, bx
    mov ecx, 0x10000   ;0x10000-> 64kb
    mul ecx            
    add esi, eax       ;0xE801只能测出4GB以内的内存，故32位eax足够了, edx肯定为0，只加eax便可
    mov edx, esi       ;edx-> 总内存大小
    jmp .mem_get_ok

;----- int 15h ah = 0x88 获取内存大小，最大支持 64MB -----
.e801_failed_so_try88:
    mov ah, 0x88
    int 0x15            ;ax存入KB为单位的内存容量
    jc .error_hlt
    and eax,0x0000FFFF

    mov cx, 0x400
    mul cx
    shl edx, 16         
    or edx, eax         ;积的低16位组合到edx
    add edx,0x100000    ;加上1MB

.error_hlt:

.mem_get_ok:
    mov [total_mem_bytes], edx  ;将内存换为byte单位后, 存入total_mem_bytes

;-------------------- 准备进入保护模式 -------------------------------
;1、打开A20
    in al, 0x92
    or al, 0000_0010B
    out 0x92, al
;2、加载GDT-> gdtr寄存器中
    lgdt [gdt_ptr]
;3、将CR0寄存器的pe位-> 置1
    mov eax, cr0
    or eax, 0x00000001
    mov cr0, eax

    jmp dword SELECTOR_CODE:p_mode_start    ; 刷新流水线


[bits 32]
p_mode_start:
    mov ax, SELECTOR_DATA
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov esp, LOADER_STACK_TOP   ;保护模式下的esp初始化
    
    mov ax, SELECTOR_VIDEO
    mov gs,ax

;-------------------- 从硬盘加载kernel到内存缓冲区中 -------------------------------
mov eax, KERNEL_START_SECTION   ;kernel.bin所在的扇区号
mov ebx, KERNEL_BIN_BASE_ADDR   ;从磁盘读出后，写入到ebx指定的地址
mov ecx, 200    ;读入的扇区数

call rd_disk_m_32

;-------------------- 启动分页三部曲 -------------------------------

call setup_page     ;创建页目录表及页表

;要将描述符表地址及偏移量写入内存gdt_ptr，一会儿用新地址重新加载
sgdt [gdt_ptr]      ;存储到原来GDT位置

;修改显存段的段描述符基址，将GDT描述符中视频段描述符中的段基址+0xc0000000
mov ebx, [gdt_ptr + 2]  ;ebx-> GDT地址
or dword [ebx + 0x18 + 4], 0xc0000000   ;视频段是第3个段描述符，每个描述符是8byte，故0x18
;段描述符的高4byte的最高位是段基址的第31-24位

;修改GDT的基址使其成为内核所在的高地址
add dword [gdt_ptr + 2], 0xc0000000

add esp, 0xc0000000   ;将栈指针同样映射到内核地址

;把页目录地址赋给cr3
mov eax, PAGE_DIR_TABLE_POS
mov cr3, eax

;打开cr0的pg位（第31位）
mov eax, cr0
or eax, 0x80000000
mov cr0, eax

;在开启分页后，用GDT新的地址重新加载
lgdt [gdt_ptr]  ;重新加载GDT

jmp SELECTOR_CODE:enter_kernel  ;强制刷新流水线，更新GDT
enter_kernel:
    call kernel_init
    mov esp, 0xc009f000
    jmp KERNEL_ENTRY_POINT  ;跳转到kernel


;-------------------- 将kernel.bin中的段（segment）拷贝到编译的虚拟地址处 -------------------------------
;原理：
;分析程序中的每个segment，如果segment类型不是PT_NULL（空程序类型），则将这段拷贝到编译的地址中
;--------------------------------------------------------------------------------------------------
kernel_init:
    xor eax, eax
    xor ebx, ebx    ;ebx-> 程序头表地址
    xor ecx, ecx    ;ecx-> 程序头表中的program header数量
    xor edx, edx    ;edx-> 一个program header大小，即e_phentsize

    mov dx, [KERNEL_BIN_BASE_ADDR + 42] ;偏移文件42字节处的属性是e_phentsize，表示一个program header（段头）大小
    mov ebx, [KERNEL_BIN_BASE_ADDR + 28];偏移文件28字节处是e_phoff，表示第一个program header在文件中的偏移量
    add ebx, KERNEL_BIN_BASE_ADDR       ;ebx-> 程序头表（由program header组成）的物理基址
    mov cx, [KERNEL_BIN_BASE_ADDR + 44] ;偏移文件44字节处是e_phnum，表示有几个program header（也就是有多少个段，一个program header对应一个段）

    ;add ebx, edx 
    ;sub cx, 1
;遍历每一个段
.each_segment:
    cmp byte [ebx + 0], PT_NULL ;p_type=PT_NULL -> 此program header未使用
    je .PTNULL

    ;为函数memcpy压入参数，参数是从右往左依次压入，函数原型类似于memcpy(dst, src, size)
    push dword [ebx + 16]   ;program header中偏移16字节处是p_filesz-> 压入函数memcpy的第三个参数：size
    mov eax, [ebx + 4]      ;距程序头偏移量为4字节处是p_offset
    add eax, KERNEL_BIN_BASE_ADDR 
    push eax                ;压入函数memcpy的第二个参数：源地址
    push dword [ebx + 8]    ;压入函数memcpy的第一个参数：目的地址，偏移程序头8字节处是p_vaddr（目的地址）
    call mem_cpy            ;调用mem_cpy完成段复制
    add esp, 12             ;清理栈中压入的三个参数
.PTNULL:
    add ebx, edx    ;段为空段类型-> 此段不处理，ebx指向下一个program header
    loop .each_segment
    ret

;-------------------- 逐字节拷贝mem_cpy(dst, src, size) -------------------------------
;输入：栈中三个参数-> dst, src, size
;输出：无
;------------------------------------------------------------------------------------
mem_cpy:
    cld
    push ebp    ;将ebp入栈备份
    mov ebp, esp
    push ecx    ;rep指令用到了ecx，但ecx对于外层段的循环还有用，所以先入栈备份
    mov edi, [ebp + 8]  ;dst
    mov esi, [ebp + 12] ;src
    mov ecx, [ebp + 16] ;size
    rep movsb   ;按照ecx中的值反复逐字节拷贝

    ;恢复环境
    pop ecx
    pop ebp
    ret

; -----------------------------------------------------------
; 在32位模式下读取硬盘n个扇区(文件) -- rd_disk_m_32
; eax=待读入LBA扇区号
; ebx=将数据写入的内存地址
; ecx=读入的扇区数
; -----------------------------------------------------------
rd_disk_m_32:
    ; eax=待读入LBA扇区号
    ; bx=将数据写入的内存地址
    ; cx=读入的扇区数
    mov esi, eax    ;备份eax
    mov di, cx      ;备份cx
;读写硬盘
;1、设置要读取的扇区数
    mov dx, 0x1f2
    mov al, cl
    out dx, al      ;读取的扇区数
    mov eax, esi    ;恢复ax

;2、将LBA地址存入0x1f3~0x1f6
    ;LBA地址7~0位写入端口0x1f3：LBA low
    mov dx, 0x1f3
    out dx, al

    ;LBA地址15~8位写入端口0x1f4：LBA mid
    mov cl, 8
    shr eax, cl     ;右移到第8位
    mov dx, 0x1f4
    out dx, al

    ;LBA地址23~16位写入端口0x1f5：LBA high
    shr eax, cl
    mov dx, 0x1f5
    out dx, al

    shr eax, cl
    and al, 0x0f    ;LBA第24~27位【与操作】
    or al, 0xe0     ;设置7~4位为1110, 表示LBA模式【或操作】
    mov dx, 0x1f6
    out dx, al

;3、向0x1f7端口写入读命令，0x20
    mov dx, 0x1f7   ;【读：Status端口  写：Command端口】
    mov al, 0x20
    out dx, al

;4、检测硬盘状态
.not_ready:
    ;同一端口，写时表示写入命令字，读时表示读入硬盘状态
    nop
    in al, dx       ;将Status值读入al寄存器
    and al, 0x88    ;第3位为1表示硬盘控制器已准备好数据传输【与操作保留第4、7位】
                    ;第 7 位为 1 表示硬盘忙
    cmp al, 0x08
    jnz .not_ready  ;若未准备好,继续等

;5、从0x1f0端口读数据
    mov ax, di      ;此时di存的是最初的cx-> 4
    mov dx, 256
    mul dx
    mov cx, ax      ;cx为循环处理次数
;di为要读取的扇区数,一个扇区有512字节,每次读入一个字
;共需 di*512/2 次,所以 di*256
    mov dx, 0x1f0

.go_on_read:
    in ax, dx       ;in读
    mov [ebx], ax    ;往bx寄存器指向的内存中写
    add ebx, 2
    loop .go_on_read
    ret

;-------------------- 创建页目录和页表 -------- -----------------------
setup_page:         ;把页目录所占内存逐一清零
    mov ecx, 4096   ;4KB
    mov esi, 0
.clean_page_dir:
    mov byte [PAGE_DIR_TABLE_POS + esi], 0
    inc esi
    loop .clean_page_dir    ;loop通过操作ecx来完成循环

;开始创建页目录项PDE【建立页目录项和页表地址的映射】
.create_pde:
    mov eax, PAGE_DIR_TABLE_POS
    add eax, 0x1000     ;eax-> 0x101000 第一个页表的位置和属性
    mov ebx, eax

    or eax, PG_US_U | PG_RW_W | PG_P        ;加上0-11属性位，or=> add操作
    ;eax：第一个页表的位置(0x101000)+属性(7)
    ;让页目录项中的0项和0xc00项(第768个)都映射同一个页表（即第一个页表：内核），这是为将地址映射为内核地址做准备
    mov [PAGE_DIR_TABLE_POS + 0x0], eax     ;第一个目录项是为了适应loader在开启分页模式前的1MB
    mov [PAGE_DIR_TABLE_POS + 0xc00], eax

    ;也就是页表的 0xc0000000～0xffffffff（1G内核） / 0x0～0xbfffffff（3G用户进程）
    sub eax, 0x1000
    mov [PAGE_DIR_TABLE_POS + 4092], eax    ; 使最后一个目录项指向页目录表自己的地址

;创建页表项PTE【建立页表项和物理页的映射】
    mov ecx, 256    ;1M低端内存/每页4KB = 256 => 映射256个物理页
    mov esi, 0
    mov edx, PG_US_U | PG_RW_W | PG_P   ;edx：物理页页表项，此时高20位为0
.create_pte:
    mov [ebx+esi*4],edx   ;ebx：0x101000（第一个页表地址）
    add edx, 4096         ;移向下一个物理页（一个物理页占 4096 byte=> 4KB）
    inc esi
    loop .create_pte

;创建内核其它页表的PDE
    mov eax, PAGE_DIR_TABLE_POS
    add eax, 0x2000     ;eax：第二个页表的位置
    or eax, PG_US_U | PG_RW_W | PG_P
    mov ebx, PAGE_DIR_TABLE_POS
    mov ecx, 254        ;目录项-第769～1022项数
    mov esi, 769
.create_kernel_pde:
    mov [ebx+esi*4], eax
    inc esi
    add eax, 0x1000
    loop .create_kernel_pde
    ret