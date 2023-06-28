#include "stdio.h"
#include "global.h"
#include "stdint.h"
#include "string.h"
#include "syscall.h"

#define va_start(ap, v) ap = (va_list)&v // 初始化指针ap向第一个固定参数v
#define va_arg(ap, t) *((t *)(ap += 4)) // ap指向下个参数并返回其值
#define va_end(ap) ap = NULL            // 清除ap

// 整型int转字符ASCII（base：转换的进制
static void iota(uint32_t value, char **buf_ptr_addr, uint8_t base) {
  uint32_t m = value % base; // 求模（最先掉低位但最后写入缓冲区
  uint32_t i = value / base; // 取整

  if (i) {
    iota(i, buf_ptr_addr, base);
  }
  if (m < 10) {
    //将数字 0～9 转换为字符'0'～'9'
    *((*buf_ptr_addr)++) = m + '0';
  } else {
    //将数字 A～F 转换为字符'A'～'F'
    *((*buf_ptr_addr)++) = m - 10 + 'A';
  }
}

// 将参数ap按照格式format输出到字符串str，返回替换后str长度
uint32_t vsprint(char *str, const char *format, va_list ap) {
  char *buf_ptr = str;
  const char *index_ptr = format;
  char index_char = *index_ptr; // 指向format中的每个字符
  int32_t arg_int;

  while (index_char) {
    if (index_char != '%') {
      *(buf_ptr)++ = index_char;
      index_char = *(++index_ptr);
      continue;
    }
    index_char = *(++index_ptr); // 得到%后面的字符

    switch (index_char) {
    case 'x':
      arg_int = va_arg(ap, int);
      iota(arg_int, &buf_ptr, 16);
      index_char = *(++index_ptr); // 跳过格式字符并更新index_char
      break;
    }
  }

  return strlen(str);
}

// 格式化format
uint32_t printf(const char *format, ...) {
  va_list args; // args指向参数
  va_start(args, format);
  char buf[1024] = {0}; // 存储拼接后的字符串
  vsprint(buf, format, args);
  va_end(args);
  return write(buf);
}