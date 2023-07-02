#ifndef LIB_USER_SYSCALL
#define LIB_USER_SYSCALL

#include "stdint.h"
enum SYSCALL_NR {
  SYS_GETPID,
  SYS_WRITE,
  SYS_MALLOC,
  SYS_FREE
}; // 枚举结构存放系统调用子功能号
uint32_t getpid(void);
uint32_t write(char *str);
void *malloc(uint32_t size);
void free(void *ptr);

#endif /* LIB_USER_SYSCALL */
