SECTION code vstart=0x7c00
    mov ax,$$
    mov ax, section.code.start
    mov ax, section.data.start
    jmp ax
    mov ax, $
    mov ax,[var1]
    mov ax,[var2]
    jmp $
    
SECTION data vstart=0x900
    var1 dd 0x4
    var2 dw 0x99