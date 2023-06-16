[bits 32]
section .text
global switch_to
switch_to:
;任务保护上下文点2（保存内核环境上下文）
    push esi
    push edi
    push ebx
    push ebp
    mov eax, [esp+20]   ;得到栈中参数cur
    mov [eax], esp      ;保存栈顶指针esp到当前pcb的self_kstack中

;-------------------以上是备份当前线程环境，下面是恢复下一个线程环境---------------

    mov eax, [esp+24]   ;得到栈中参数next（next的pcb地址）
    mov esp, [eax]      ;[eax]存的是next线程的栈指针
    pop ebp
    pop ebx
    pop edi
    pop esi
    ret                 ;返回，执行函数

