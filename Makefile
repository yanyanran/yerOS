mbrS = boot/mbr.S 
mbrBin = mbr.bin
loaderS = boot/loader.S
loaderBin = loader.bin
kernelBin = kernel.bin

build:
	nasm -I include/ -o ${mbrBin} ${mbrS} 
	nasm -I include/ -o ${loaderBin} ${loaderS} 

image: build
	dd if=/dev/zero of=boot.img count=61440 bs=512
	dd if=${mbrBin} of=boot.img count=1 bs=512 conv=notrunc
	dd if=${loaderBin} of=boot.img bs=512 seek=2 conv=notrunc
	gcc -m32 -c -o main.o kernel/main.c 
	ld -m elf_i386 main.o -Ttext 0xc0001500 -e main -o kernel.bin
	dd if=${kernelBin} of=boot.img bs=512 count=200 seek=9 conv=notrunc

run: image
	bochs -f bochsrc.disk

clear:
	rm -rf *.bin *.out *.img *.lock