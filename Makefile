mbrS = boot/mbr.asm 
mbrBin = mbr.bin
loaderS = boot/loader.asm 
loaderBin = loader.bin
kernelBin = kernel.bin
printS = lib/kernel/print.asm 
kernelO = kernel.o
kernelS = kernel/kernel.asm 

build:
	nasm -I include/ -o ${mbrBin} ${mbrS} 
	nasm -I include/ -o ${loaderBin} ${loaderS} 
	nasm -f elf -o print.o ${printS}
	nasm -f elf -o kernel.o ${kernelS}

image: build
	dd if=/dev/zero of=boot.img count=61440 bs=512
	dd if=${mbrBin} of=boot.img count=1 bs=512 conv=notrunc
	dd if=${loaderBin} of=boot.img bs=512 seek=2 conv=notrunc
	gcc -nostdlib -I lib/kernel -m32 -c -o main.o kernel/main.c
	gcc -nostdlib -I kernel/ -I lib/kernel -m32 -c -o interrupt.o kernel/interrupt.c
	gcc -nostdlib -I kernel/ -I lib/kernel -m32 -c -o init.o kernel/init.c
	gcc -nostdlib -I kernel/ -I lib/kernel -m32 -c -o timer.o device/timer.c
	ld -m elf_i386 -Ttext 0xc0001500 -e main -o ${kernelBin} main.o init.o interrupt.o print.o kernel.o timer.o
	dd if=${kernelBin} of=boot.img bs=512 count=200 seek=9 conv=notrunc

run: image
	bochs -f bochsrc.disk

clear:
	rm -rf *.bin *.out *.img *.lock *.o