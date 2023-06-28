#ifndef LIB_STDIO
#define LIB_STDIO
#include "print.h"

typedef char *va_list; // 字符指针

uint32_t printf(const char *format, ...);

#endif /* LIB_STDIO */
