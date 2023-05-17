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
    mov byte [gs:160], 'P'      ;往显存第80个字符的位置写P-> 1字符占2字节-> 偏移量2*80=160

    jmp $