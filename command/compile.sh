#### 此脚本应该在command目录下执行

BIN="prog_arg"
CFLAGS="-Wall -c -fno-builtin -W -Wstrict-prototypes \
-Wmissing-prototypes -Wsystem-headers"
LIB="-I ../lib/ -I ../lib/user -I ../fs"
OBJS="../string.o ../syscall.o ../stdio.o ../assert.o start.o"
DD_IN=$BIN
DD_OUT="/home/yanran/github/yerOS/boot.img"

nasm -f elf ./start.asm -o ./start.o
ar rcs simplr_crt.a $OBJS start.o
gcc -m32 $CFLAGS $LIB -o $BIN".o" $BIN".c"
ld -m elf_i386 -T program.ld $BIN".o" $OBJS simplr_crt.a -o $BIN
SEC_CNT=$(ls -l $BIN|awk '{printf("%d", ($5+511)/512)}')
dd if=./$DD_IN of=$DD_OUT bs=512 count=$SEC_CNT seek=300 conv=notrunc


########## 以上核心就是下面这五条命令 ##########
#nasm -f elf ./start.S -o ./start.o
#ar rcs simple_crt.a ../build/string.o ../build/syscall.o \
#../build/stdio.o ../build/assert.o ./start.o
#gcc -Wall -c -fno-builtin -W -Wstrict-prototypes -Wmissing-prototypes \
#-Wsystem-headers -I ../lib/ -I ../lib/user -I ../fs prog_arg.c -o prog_arg.o
#ld prog_arg.o simple_crt.a -o prog_arg
#dd if=prog_arg of=/home/work/my_workspace/bochs/boot.img \
#bs=512 count=11 seek=300 conv=notrunc