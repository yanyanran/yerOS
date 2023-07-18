#include "string.h"
#include "assert.h"
#include "debug.h"
#include "global.h"

// 内存区域的数据初始化（内存分配时的数据清零）=>
// 将dst_起始的size个字节置为value
void memset(void *dst_, uint8_t value, uint32_t size) {
  assert(dst_ != NULL);
  uint8_t *dst = (uint8_t *)dst_;
  while (size-- > 0) {
    *dst++ = value;
  }
}

// 内存数据拷贝=> 终止条件：size
// 将src_起始的size个字节复制到dst_
void memcpy(void *dst_, const void *src_, uint32_t size) {
  assert(dst_ != NULL && src_ != NULL);
  uint8_t *dst = dst_;
  const uint8_t *src = src_;
  while (size-- > 0) {
    *dst++ = *src++;
  }
}

// 用于一段内存数据比较=>
// 连续比较以地址a_和b_开头的size个字节，相等返回0，a_>b_返回+1，否则返回−1
int memcmp(const void *a_, const void *b_, uint32_t size) {
  const char *a = a_;
  const char *b = b_;
  assert(a != NULL && b != NULL);
  while (size-- > 0) {
    if (*a != *b) {
      return *a > *b ? 1 : -1;
    }
    a++;
    b++;
  }
  return 0;
}

// 字符串拷贝=> 终止条件：src_处的字符‘0’
// 将字符串从src_复制到dst_
char *strcpy(char *dst_, const char *src_) {
  assert(dst_ != NULL && src_ != NULL);
  char *r = dst_; // 用来返回目的字符串dst_起始地址
  while ((*dst_++ = *src_++))
    ;
  return r;
}

// 返回字符串长度
uint32_t strlen(const char *str) {
  assert(str != NULL);
  const char *p = str;
  while (*p++)
    ;
  return (p - str - 1);
}

// 比较两个字符串，若a_中字符大于b_返回1，相等返回0，否则返回−1
uint8_t strcmp(const char *a, const char *b) {
  assert(a != NULL && b != NULL);
  while (*a != 0 && *a == *b) {
    a++;
    b++;
  }
  return *a < *b ? -1 : *a > *b;
}

// 从左到右 查找字符串str中首次出现字符ch的地址
char *strchr(const char *str, const uint8_t ch) {
  assert(str != NULL);
  while (*str != 0) {
    if (*str == ch) {
      return (char *)str;
    }
    str++;
  }
  return NULL;
}

// 从后往前 查找字符串str中最后一次出现字符ch的地址
char *strrchr(const char *str, const uint8_t ch) {
  assert(str != NULL);
  const char *last_char = NULL;
  while (*str != 0) {
    if (*str == ch) {
      last_char = str;
    }
    str++;
  }
  return (char *)last_char;
}

// 字符串拼接=>
// 将字符串src_拼接到dst_后，返回dst_地址
char *strcat(char *dst_, const char *src_) {
  assert(dst_ != NULL && src_ != NULL);
  char *str = dst_;
  while (*str++)
    ;
  --str;
  while ((*str++ = *src_++)) // 当*str被赋值0时
    ; //也就是表达式不成立，正好添加了字符串结尾的0
  return dst_;
}

// 在字符串str中查找字符ch出现的次数
uint32_t strchrs(const char *str, uint8_t ch) {
  assert(str != NULL);
  uint32_t ch_cnt = 0;
  const char *p = str;
  while (*p != 0) {
    if (*p == ch) {
      ch_cnt++;
    }
    p++;
  }
  return ch_cnt;
}
