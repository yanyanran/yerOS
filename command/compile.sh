#### 此脚本应该在command目录下执行

BIN="prog_no_arg"
CFLAGS="-Wall -c -fno-builtin -W -Wstrict-prototypes \
-Wmissing-prototypes -Wsystem-headers"
LIB="../lib/"
OBJS="../string.o ../syscall.o ../stdio.o ../assert.o"
DD_IN=$BIN
DD_OUT="/home/yanran/github/yerOS/boot.img"

gcc -m32 $CFLAGS -I $LIB -o $BIN".o" $BIN".c"
ld -m elf_i386 -T program.ld $BIN".o" $OBJS -o $BIN
SEC_CNT=$(ls -l $BIN|awk '{printf("%d", ($5+511)/512)}')
dd if=./$DD_IN of=$DD_OUT bs=512 count=$SEC_CNT seek=300 conv=notrunc


########## 以上核心就是下面这三条命令 ##########
#gcc -Wall -c -fno-builtin -W -Wstrict-prototypes -Wmissing-prototypes \
#-Wsystem-headers -I ../lib -o prog_no_arg.o prog_no_arg.c
#ld -e main prog_no_arg.o ../build/string.o ../build/syscall.o\
#../build/stdio.o ../build/assert.o -o prog_no_arg
#dd if=prog_no_arg of=/home/work/my_workspace/bochs/hd60M.img \
#bs=512 count=10 seek=300 conv=notrunc