#ifndef LIB_KERNEL_BITMAP
#define LIB_KERNEL_BITMAP
#include "global.h"
#include "stdint.h"

#define BITMAP_MASK 1

// 伪数组性质
struct bitmap {
  uint32_t btmp_bytes_len; // 位图字节长度
  uint8_t *bits;           // 位图指针（单字节）=> 记录位图地址 
};

void bitmap_init(struct bitmap *btmp);
bool bitmap_scan_test(struct bitmap *btmp, uint32_t bit_idx);
int bitmap_scan(struct bitmap *btmp, uint32_t cnt);
void bitmap_set(struct bitmap *btmp, uint32_t bit_idx, int8_t value);

#endif /* LIB_KERNEL_BITMAP */
