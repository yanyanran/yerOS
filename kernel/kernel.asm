; -----------------------------------------------------------
; 实现中断处理程序
; -----------------------------------------------------------
[bits 32]
%define ERROR_CODE nop  ;已压入错误码，不操作
%define ZERO push 0     ;没有压入错误码，保持栈格式统一手动压一个0
extern put_str
extern idt_table        ;C中注册的中断处理程序数组

section .data
global intr_entry_table
intr_entry_table:
    ;多行宏-> VECTOR（%1-> 中断向量号 %2-> nop/push 0的维持栈格式操作）
    %macro VECTOR 2
    section .text
    ;任务保护上下文点1（中断前的全部寄存器）
    intr%1entry:
        %2
        push ds
        push es
        push fs
        push gs
        pushad  ;压入8个32位寄存器

        ;8259A设置了手动结束中断-> 发送中断结束命令EOI（0x20）
        mov al, 0x20
        out 0xa0, al    ;发从片
        out 0x20, al    ;发主片

        push %1     ;压入中断向量号
        call [idt_table + %1*4];调用idt_table中的C版本中断处理函数
        jmp intr_exit

    section .data
        dd intr%1entry  ;存储各个中断入口程序的地址，形成intr_entry_table数组 
    %endmacro

section .text
global intr_exit
intr_exit:
    ;恢复上下文环境
    add esp, 4  ;跳过中断号
    popad
    pop gs
    pop fs
    pop es
    pop ds
    add esp, 4  ;跳过error_code
    iretd       ;中断后的执行线程到此处执行线程对应用户程序

;宏定义中断处理程序-> 预处理后，将存在33个中断处理程序
;处理器内部固定异常类型（0-19）
VECTOR 0x00, ZERO
VECTOR 0x01, ZERO
VECTOR 0x02, ZERO
VECTOR 0x03, ZERO
VECTOR 0x04, ZERO
VECTOR 0x05, ZERO
VECTOR 0x06, ZERO
VECTOR 0x07, ZERO
VECTOR 0x08, ERROR_CODE
VECTOR 0x09, ZERO
VECTOR 0x0a, ERROR_CODE
VECTOR 0x0b, ERROR_CODE
VECTOR 0x0c, ERROR_CODE
VECTOR 0x0d, ERROR_CODE
VECTOR 0x0e, ERROR_CODE
VECTOR 0x0f, ZERO
VECTOR 0x10, ZERO
VECTOR 0x11, ERROR_CODE
VECTOR 0x12, ZERO
VECTOR 0x13, ZERO
;Intel保留（20-31） 
VECTOR 0x14, ZERO
VECTOR 0x15, ZERO
VECTOR 0x16, ZERO
VECTOR 0x17, ZERO
VECTOR 0x18, ZERO
VECTOR 0x19, ZERO
VECTOR 0x1a, ZERO
VECTOR 0x1b, ZERO
VECTOR 0x1c, ZERO
VECTOR 0x1d, ZERO
VECTOR 0x1e, ERROR_CODE ;含错误码
VECTOR 0x1f, ZERO
;可用中断向量号（320->）
VECTOR 0x20, ZERO   ;时钟中断
VECTOR 0x21, ZERO   ;键盘中断
VECTOR 0x22, ZERO   ;级联用
VECTOR 0x23, ZERO   ;串口2
VECTOR 0x24, ZERO   ;串口1
VECTOR 0x25, ZERO   ;并口2
VECTOR 0x26, ZERO   ;软盘
VECTOR 0x27, ZERO   ;并口1
VECTOR 0x28, ZERO   ;实时时钟
VECTOR 0x29, ZERO   ;重定向
VECTOR 0x2a, ZERO   ;保留
VECTOR 0x2b, ZERO   ;保留
VECTOR 0x2c, ZERO   ;ps/2鼠标
VECTOR 0x2d, ZERO   ;fpu浮点单元异常
VECTOR 0x2e, ZERO   ;硬盘
VECTOR 0x2f, ZERO   ;保留

; -----------------------------------------------------------
; 0x80号中断
; -----------------------------------------------------------
[bits 32]
extern syscall_table
section .text
global syscall_handler
syscall_handler:
;1、保存上下文
    push 0      ;统一栈格式
    push ds
    push es
    push fs
    push gs
    pushad  ;压入8个32位寄存器（eax,ecx,edx,ebx,esp,ebp,esi,edi）

    push 0x80   ;统一栈格式

;2、为系统调用子功能传入参数(3-1)
    push edx
    push ecx
    push ebx

;3、调用子功能处理函数
    call [syscall_table + eax*4]
    add esp, 12 ;跨过三个参数

;4、将call调用后的返回值存入当前内核栈中eax的位置
    mov [esp+8*4], eax
    jmp intr_exit   ;intr_exit返回，恢复上下文