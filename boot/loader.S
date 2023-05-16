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
;INT 0x10
;功能号:0x13-> 打印字符串
;------------------------------------------------------------
;AL=显示输出方式
; 0—字符串中只含显示字符，其显示属性在 BL 中，显示后，光标位置不变
; 1—字符串中只含显示字符，其显示属性在 BL 中，显示后，光标位置改变
; 2—字符串中含显示字符和显示属性。显示后，光标位置不变
; 3—字符串中含显示字符和显示属性。显示后，光标位置改变

loader_start:
    ;int 15h eax = 0000E820h ,edx = 534D4150h ('SMAP') 获取内存布局'
    xor ebx, ebx        ;第一次调用时，ebx值要为0


    mov sp, LOADER_BASE_ADDR
    mov bp, loadermsg   ; ES:BP = 字符串地址
    mov cx, 17          ; CX = 字符串长度
    mov ax, 0x1301      ; AH 子功能号 = 13, AL 显示输出方式 = 01h
    mov bx, 0x001f      ; 页号为0(BH = 0) 属性：蓝底粉红字(BL = 1fh)
    mov dx, 0x1800      ; (DH､ DL)=坐标(0x18<24>行也就是最后一行<文本模式下行数0-24>､ 0x00列)-> int 0x10参数
    int 0x10            ; 中断n

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