;相对近调用
call near near_proc
jmp $
addr dd 4
near_proc:
    mov ax, 0x1234
ret

section call_test vstar=0x900
mov word [addr], near_proc  ;word关键字告诉CPU一次读2字节
call [addr]     ;间接绝对近调用（内存）
mov ax, near_proc
call ax         ;间接寻址（寄存器）
jmp $
addr dd 4

;直接绝对远调用
call 0: far_proc
jmp $

;间接绝对远调用
call far [addr]
jmp $
addr dw far_proc, 0

;相对短转移
jmp short start
times 127 db 0

start:
    mov ax, 0x1234
    jmp $

near_proc:
    mov ax, 0x1234
    ret

far_proc:
    mov ax, 0x1234
    retf