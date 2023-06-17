mbrS = boot/mbr.asm 
mbrBin = mbr.bin
loaderS = boot/loader.asm 
loaderBin = loader.bin
kernelBin = kernel.bin
printS = lib/kernel/print.asm 
kernelS = kernel/kernel.asm
include= -I lib/ -I kernel/ -I lib/kernel/ -I device/ -I thread/
GCC_FLAGS = -c -Wall -m32 -ggdb -nostdinc -fno-pic -fno-builtin -fno-stack-protector

build:
	nasm -I include/ -o ${mbrBin} ${mbrS} 
	nasm -I include/ -o ${loaderBin} ${loaderS} 
	nasm -f elf -o print.o ${printS}
	nasm -f elf -o kernel.o ${kernelS}
	nasm -f elf -o switch.o thread/switch.asm

image: build
	dd if=/dev/zero of=boot.img count=61440 bs=512
	dd if=${mbrBin} of=boot.img count=1 bs=512 conv=notrunc
	dd if=${loaderBin} of=boot.img bs=512 seek=2 conv=notrunc
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
	ld -m elf_i386 -Ttext 0xc0001500 -e main -o ${kernelBin} main.o init.o interrupt.o print.o kernel.o timer.o debug.o string.o bitmap.o memory.o thread.o list.o switch.o sync.o
	dd if=${kernelBin} of=boot.img bs=512 count=200 seek=9 conv=notrunc

run: image
	bochs -f bochsrc.disk

clear:
	rm -rf *.bin *.out *.img *.lock *.o