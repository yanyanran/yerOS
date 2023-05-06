obj2 = boot/mbr.S 
obj = boot.bin

build:
	nasm ${obj2} -o ${obj} 

image: build
	dd if=/dev/zero of=disk.img count=61440 bs=512
	dd if=${obj} of=boot.img count=1 bs=512
	dd if=disk.img of=boot.img count=61439 bs=512 skip=1 seek=1

run: image
	bochs -f bochsrc.disk

clear:
	rm -rf *.bin *.out *.img