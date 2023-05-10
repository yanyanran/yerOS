;配置文件

;------------- loader 和 kernel ------------- 
LOADER_BASE_ADDR equ 0x900  ;loader在内存中的位置，MBR需要把loader从硬盘读入后放在这
LOADER_START_SECTOR equ 0x2 ;loader在硬盘上的LBA（逻辑扇区）地址，宏定义为第2扇区