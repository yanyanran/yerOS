#ifndef LIB_STDIO
#define LIB_STDIO
#include "print.h"

typedef char *va_list; // 字符指针

#define va_start(ap, v) ap = (va_list)&v // 初始化指针ap向第一个固定参数v
#define va_arg(ap, t) *((t *)(ap += 4)) // ap指向下个参数并返回其值
#define va_end(ap) ap = NULL            // 清除ap

uint32_t printf(const char *format, ...);
uint32_t vsprintf(char *str, const char *format, va_list ap);
uint32_t sprintf(char* buf, const char* format, ...);

#endif /* LIB_STDIO */
