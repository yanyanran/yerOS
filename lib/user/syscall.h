#ifndef LIB_USER_SYSCALL
#define LIB_USER_SYSCALL
#include "stdint.h"
#include "thread.h"

enum SYSCALL_NR {
  SYS_GETPID,
  SYS_WRITE,
  SYS_MALLOC,
  SYS_FREE,
  SYS_FORK,
  SYS_READ,
  SYS_PUTCHAR,
  SYS_CLEAR
}; // 枚举结构存放系统调用子功能号
uint32_t getpid(void);
uint32_t write(int32_t fd, const void *buf, uint32_t count);
void *malloc(uint32_t size);
void free(void *ptr);
pid_t fork();
int32_t read(int32_t fd, void *buf, uint32_t count);
void putchar(char char_asci);
void clear(void);

#endif /* LIB_USER_SYSCALL */
