TI_GDT equ 0
RPL0 equ 0
SELECTOR_VIDEO equ (0x0003<<3) + TI_GDT + RPL0
[bits 32]
section .text
;------------------------ put_char -----------------------------
;功能描述：把栈中的 1 个字符写入光标所在处（直接写显存）
;---------------------------------------------------------------
global put_char
put_char:
    pushad      ;备份32位寄存器环境
    ;需要保证gs中为正确的视频段选择子，保险起见每次打印都为gs赋值
    mov ax, SELECTOR_VIDEO  ;不能直接把立即数送入段寄存器
    mov gs, ax

;;;;;;;;; 获取当前光标位置 ;;;;;;;;;
    ;先获得高8位-> 0e
    mov dx, 0x03d4  ;往索引端口 0x03d4 处写
    mov al, 0x0e
    out dx, al
    mov dx, 0x03d5  ;通过读写数据端口 0x3d5 来获得或设置光标位置
    in al, dx       ;读光标位置的高8位
    mov ah, al

    ;再获取低8位-> 0f
    mov dx, 0x03d4
    mov al, 0x0f
    out dx, al
    mov dx, 0x03d5
    in al, dx

    ;光标存入bx
    mov bx, ax
    ;在栈中获取待打印的字符
    mov ecx, [esp + 36] ;pushad 压入 4×8＝32 字节，加上主调函数 4 字节的返回地址，故 esp+36 字节
    
    ;判断字符类型（用对应ASCII码识别：换行LF、回车CR、退格BS都设为不可用忽略字符）
    cmp cl, 0xd
    jz .is_carriage_return
    cmp cl, 0xa
    jz .is_line_feed
    cmp cl, 0x8
    jz .back_space
    jmp .put_other

.back_space:
    dec bx  ;光标坐标指向前一个字符
    shl bx, 1   ;bx左移1位-> 乘2,处理低字节处的ASCII码值
    mov byte [gs:bx], 0x20  ;将待删除字节补为0/空格
    inc bx  ;bx+1（写字符属性）
    mov byte [gs:bx], 0x07  ;属性：黑屏白字
    shr bx, 1
    jmp .set_cursor

.put_other:
    shl bx, 1
    mov [gs:bx], cl ;ASCII字符本身
    inc bx
    mov byte [gs:bx], 0x07  ;字符属性
    shr bx, 1   ;恢复老光标值
    inc bx      ;下一个光标值
    cmp bx, 2000
    jl .set_cursor  ;光标值<2000（屏幕字符数）表示没写到显存最后-> 去设置新光标值
                    ;否则-> 滚屏

;/r/n一并处理：光标值-除80的余数-> 取整
.is_line_feed: 
.is_carriage_return: 
    xor dx, dx  ;dx-> 存余数，清0
    mov ax, bx  ;ax-> bx即当前光标位置
    mov si, 80  
    div si      ;ax/bx->除后ax存结果，dx存余数
    sub bx, dx

.is_carriage_return_end:    ;回车符CR处理结束
    add bx, 80      ;光标移到行首
    cmp bx, 2000
.is_line_feed_end:
    jl .set_cursor

;;;;;;;;; 超出屏幕大小-> 滚屏 ;;;;;;;;;
;屏幕行范围是 0～24，滚屏的原理-> 屏幕的第 1～24 行搬运到第 0～23 行，再将第 24 行用空格填充
.roll_screen:
    cld
    mov ecx, 960    ;ecx-> rep重复执行次数：2000-80=1920个字符需要搬运，共1020*2=3840字节，一次需要搬4 byte，共3840/4=960次
    mov esi, 0xc00b80a0 ;esi-> 复制的起始位置：第1行行首
    mov edi, 0xc00b8000 ;edi-> 复制的目的地址：第0行行首
    rep movsd

    ;将最后一行填为空白
    mov ebx, 3840   ;最后一行首字母的第一个字节偏移=1920*2=3840
    mov ecx, 80     ;一行80个字符，需移动80次
.cls:
    mov dword [gs: ebx], 0x0720  ;0x0720-> 黑底白字空格键
    add ebx, 2
    loop .cls
    mov bx, 1920    ;将光标值重置为1920，也就是最后一行的首字符

;;;;;;;;; 设置光标为bx值 ;;;;;;;;;
.set_cursor:
    ;1、先设置高8位
    mov dx, 0x03d4
    mov al, 0x0e
    out dx, al
    mov dx, 0x03d5
    mov al, bh
    out dx, al

    ;2、再设置低8位
    mov dx, 0x03d4
    mov al, 0x0f
    out dx, al
    mov dx, 0x03d5
    mov al, bl
    out dx, al
.put_char_done:
    popad   ;环境恢复：将之前入栈的8个32位寄存器恢复到各个寄存器中
    ret