#include "stdio.h"
#include "global.h"
#include "stdint.h"
#include "string.h"
#include "syscall.h"

// 整型int转字符ASCII（base：转换的进制
static void itoa(uint32_t value, char **buf_ptr_addr, uint8_t base) {
  uint32_t m = value % base; // 求模（最先掉低位但最后写入缓冲区
  uint32_t i = value / base; // 取整

  if (i) {
    itoa(i, buf_ptr_addr, base);
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
uint32_t vsprintf(char *str, const char *format, va_list ap) {
  char *buf_ptr = str;
  const char *index_ptr = format;
  char index_char = *index_ptr; // 指向format中的每个字符
  int32_t arg_int;
  char *arg_str;

  while (index_char) {
    if (index_char != '%') {
      *(buf_ptr++) = index_char;
      index_char = *(++index_ptr);
      continue;
    }
    index_char = *(++index_ptr); // 得到%后面的字符
    switch (index_char) {
    case 's':
      arg_str = va_arg(ap, char *);
      strcpy(buf_ptr, arg_str);
      buf_ptr += strlen(arg_str);
      index_char = *(++index_ptr);
      break;

    case 'c':
      *(buf_ptr++) = va_arg(ap, char);
      index_char = *(++index_ptr);
      break;

    case 'd':
      arg_int = va_arg(ap, int);
      if (arg_int < 0) {
        arg_int = 0 - arg_int;
        *buf_ptr++ = '-';
      }
      itoa(arg_int, &buf_ptr, 10);
      index_char = *(++index_ptr);
      break;

    case 'x':
      arg_int = va_arg(ap, int);
      itoa(arg_int, &buf_ptr, 16);
      index_char = *(++index_ptr); // 跳过格式字符并更新index_char
      break;
    }
  }

  return strlen(str);
}

// sprintf
uint32_t sprintf(char *buf, const char *format, ...) {
  va_list args;
  uint32_t retval;
  va_start(args, format);
  retval = vsprintf(buf, format, args);
  va_end(args);
  return retval;
}

// 格式化format
uint32_t printf(const char *format, ...) {
  va_list args; // args指向参数
  va_start(args, format);
  char buf[1024] = {0}; // 存储拼接后的字符串
  vsprintf(buf, format, args);
  va_end(args);
  return write(1, buf, strlen(buf));
}