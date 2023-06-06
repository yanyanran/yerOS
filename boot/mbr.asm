;主引导程序

%include "boot.inc" 
SECTION MBR vstart=0x7c00 ;指定引导程序的起始(段)地址
    mov ax,cs       ;ax:通用寄存器
    ;段寄存器
    mov ds,ax
    mov es,ax
    mov ss,ax
    mov fs,ax
    mov sp,0x7c00   ;初始化栈指针 
    mov ax, 0xb800  ;操作现显存文本的起始段地址
    mov gs, ax

; -----------------------------------------------------------
;INT 0x10
;功能号:0x06-> 上卷窗口(清屏)
;------------------------------------------------------

    mov ax, 0600h   ; AH 功能号= 0x06, AL = 上卷行数(为0表示全部)
    mov bx, 0700h   ; BH = 上卷行属性
    mov cx, 0       ; (CL,CH) = 窗口左上角的(X,Y)位置-> 左上角: (0, 0)
    mov dx, 184fh  ; (DL,DH) = 窗口右下角的(X,Y)位置-> 右下角: (80,25),
                    ; VGA 文本模式中,一行只能容纳 80 个字符,共 25 行｡
                    ; 下标从 0 开始,所以 0x18=24,0x4f=79
    int 10h

    ;输出:背景色->绿色，前景色->红色，且跳动的字符串“1 MBR”
    mov byte [gs:0x00], '1'
    mov byte [gs:0x01], 0xA4    ;A表示绿色背景闪烁， 4表示前景设红色 

    mov byte [gs:0x02], ' '
    mov byte [gs:0x03], 0xA4

    mov byte [gs:0x04], 'M'
    mov byte [gs:0x05], 0xA4

    mov byte [gs:0x06], 'B'
    mov byte [gs:0x07], 0xA4

    mov byte [gs:0x08], 'R'
    mov byte [gs:0x09], 0xA4

    mov eax, LOADER_START_SECTOR   ;起始扇区LBA地址（0x2）
    mov bx, LOADER_BASE_ADDR       ;写入的地址
    mov cx, 4                      ;待读入(加载loader.bin)的扇区数
    call rd_disk_m_16              ;以下读取程序的起始部分（一个扇区）ret回到这里继续执行

    jmp LOADER_BASE_ADDR + 0x300           ;MBR将接力棒传给loader：0x900

; -----------------------------------------------------------
; 在16位模式下读取硬盘n个扇区
; -----------------------------------------------------------
rd_disk_m_16:   ;加载loader.bin，进入保护模式
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
    mov [bx], ax    ;往bx寄存器指向的内存中写
    add bx, 2
    loop .go_on_read
    ret

    times 510-($-$$) db 0 ;用0填充本扇区除了最后两个魔数的剩余空间
    db 0x55,0xaa