mbrS = boot/mbr.asm 
mbrBin = mbr.bin
loaderS = boot/loader.asm 
loaderBin = loader.bin
kernelBin = kernel.bin
printS = lib/kernel/print.asm 
kernelS = kernel/kernel.asm
include= -I lib/ -I kernel/ -I lib/kernel/ -I device/ -I thread/ -I userprog/ -I lib/user -I fs/
GCC_FLAGS = -c -Wall -m32 -ggdb -nostdinc -fno-pic -fno-builtin -fno-stack-protector -g



# BOCHS相关参数
BOCHS_PATH=/home/happy/Documents/bochs/bin/bochs
BOCHS_PORT="target remote 127.0.0.1:1234"
BOCHS_GDB_FLAG='gdbstub:enabled=1,port=1234,text_base=0,data_base=0,bss_base=0'

build:
	nasm -I include/ -o ${mbrBin} ${mbrS} 
	nasm -I include/ -o ${loaderBin} ${loaderS} 
	nasm -f elf -o print.o ${printS}
	nasm -f elf -o kernel.o ${kernelS}
	nasm -f elf -o switch.o thread/switch.asm

image: build
	gcc ${include} ${GCC_FLAGS} -o main.o kernel/main.c
	gcc ${include} ${GCC_FLAGS} -o interrupt.o kernel/interrupt.c
	gcc ${include} ${GCC_FLAGS} -o timer.o device/timer.c
	gcc ${include} ${GCC_FLAGS} -o init.o kernel/init.c
	gcc ${include} ${GCC_FLAGS} -o debug.o kernel/debug.c
	gcc ${include} ${GCC_FLAGS} -o string.o lib/string.c
	gcc ${include} ${GCC_FLAGS} -o bitmap.o lib/kernel/bitmap.c
	gcc ${include} ${GCC_FLAGS} -o memory.o kernel/memory.c
	gcc ${include} ${GCC_FLAGS} -o thread.o thread/thread.c
	gcc ${include} ${GCC_FLAGS} -o list.o lib/kernel/list.c
	gcc ${include} ${GCC_FLAGS} -o sync.o thread/sync.c
	gcc ${include} ${GCC_FLAGS} -o console.o device/console.c
	gcc ${include} ${GCC_FLAGS} -o keyboard.o device/keyboard.c
	gcc ${include} ${GCC_FLAGS} -o ioqueue.o device/ioqueue.c
	gcc ${include} ${GCC_FLAGS} -o tss.o userprog/tss.c
	gcc ${include} ${GCC_FLAGS} -o process.o userprog/process.c
	gcc ${include} ${GCC_FLAGS} -o syscall.o lib/user/syscall.c
	gcc ${include} ${GCC_FLAGS} -o syscall_init.o userprog/syscall_init.c
	gcc ${include} ${GCC_FLAGS} -o stdio.o lib/stdio.c
	gcc ${include} ${GCC_FLAGS} -o stdio_kernel.o lib/kernel/stdio_kernel.c
	gcc ${include} ${GCC_FLAGS} -o ide.o device/ide.c
	gcc ${include} ${GCC_FLAGS} -o fs.o fs/fs.c
	gcc ${include} ${GCC_FLAGS} -o inode.o fs/inode.c
	ld -m elf_i386 -Ttext 0xc0001500 -e main -o ${kernelBin} main.o init.o interrupt.o print.o kernel.o timer.o debug.o string.o bitmap.o memory.o thread.o list.o switch.o sync.o console.o keyboard.o ioqueue.o tss.o process.o syscall.o syscall_init.o stdio.o stdio_kernel.o ide.o fs.o inode.o
	
	dd if=/dev/zero of=boot.img count=61440 bs=512
	dd if=${mbrBin} of=boot.img count=1 bs=512 conv=notrunc
	dd if=${loaderBin} of=boot.img bs=512 seek=2 conv=notrunc
	dd if=${kernelBin} of=boot.img bs=512 count=200 seek=9 conv=notrunc

run: image
	sh fdisk.sh
	${BOCHS_PATH} -f bochsrc.disk


run_gdb: image
	#sh fdisk.sh
	bochs -qf bochsrc.disk  ${BOCHS_GDB_FLAG} & 
	gdb ./kernel.bin -ex ${BOCHS_PORT}
	pkill bochs
	make  clear
clear:
	rm -rf *.bin *.out *.lock *.o 
	#*.img