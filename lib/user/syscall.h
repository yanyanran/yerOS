#ifndef LIB_USER_SYSCALL
#define LIB_USER_SYSCALL

#include "stdint.h"
enum SYSCALL_NR { SYS_GETPID, SYS_WRITE }; // 枚举结构存放系统调用子功能号
uint32_t getpid(void);
uint32_t write(char *str);

#endif /* LIB_USER_SYSCALL */
