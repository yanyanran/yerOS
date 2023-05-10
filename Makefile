mbrS = boot/mbr.S 
mbrBin = mbr.bin
loaderS = boot/loader.S
loaderBin = loader.bin

build:
	nasm -I include/ -o ${mbrBin} ${mbrS} 
	nasm -I include/ -o ${loaderBin} ${loaderS} 

image: build
	dd if=/dev/zero of=boot.img count=61440 bs=512
	dd if=${mbrBin} of=boot.img count=1 bs=512 conv=notrunc
	dd if=${loaderBin} of=boot.img count=1 bs=512 seek=2 conv=notrunc

run: image
	bochs -f bochsrc.disk

clear:
	rm -rf *.bin *.out *.img