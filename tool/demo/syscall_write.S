section .data
str_c_lib: db "c libary says: hello world!", 0xa    ;0xa为LF（换行符）ASCII码
str_syscall: db "syscall says: hello word!", 0xa
str_c_lib_len equ $-str_c_lib
str_syscall_len equ $-str_syscall

section .text
global _start
_start:
;方式1  模拟C语言中系统调用库函数write
    push str_c_lib_len  ;参数入栈
    push str_c_lib
    push 1

    call simu_write     ;调用下面定义的smu_write
    add esp, 12         ;回收栈空间

;方式2  跨过库函数，直接进行系统调用
    mov eax, 4          ;4号子功能-> write系统调用
    mov ebx, 1
    mov ecx, str_syscall
    mov edx, str_syscall_len
    int 0x80            ;发起中断，通知Linux完成请求功能

;退出程序
    mov eax, 1          ;1号子功能-> exit
    int 0x80

;自定义simu_write来模拟C库中的系统调用函数write
simu_write:
    push ebp
    mov ebp, esp

    mov eax, 4
    mov ebx, [ebp + 8]
    mov ecx, [ebp + 12]
    mov edx, [ebp + 16]
    int 0x80
    pop ebp
    ret

