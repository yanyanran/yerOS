#include "bitmap.h"
#include "debug.h"
#include "interrupt.h"
#include "print.h"
#include "stdint.h"
#include "string.h"

// 初始化位图btmp
void bitmap_init(struct bitmap *btmp) {
  memset(btmp->bits, 0, btmp->btmp_bytes_len);
}

// 判断bit_idx位是否为1，为1返回true，否则返回false
bool bitmap_scan_test(struct bitmap *btmp, uint32_t bit_idx) {
  uint32_t byte_idx = bit_idx / 8; // 向下取整用于索引数组下标
  uint32_t bit_odd = bit_idx % 8;  //取余用于索引数组内的位
  return (btmp->bits[byte_idx] & (BITMAP_MASK << bit_odd));
}

// 在位图中申请cnt个位，成功返回其起始下标地址，失败返回-1
int bitmap_scan(struct bitmap *btmp, uint32_t cnt) {
  uint32_t idx_byte = 0; //用于记录空闲位所在字节索引
  //逐个字节比较
  while ((0xff == btmp->bits[idx_byte]) && (idx_byte < btmp->btmp_bytes_len)) {
    // 0xff表示该字节内已无空闲位，继续下一个字节
    idx_byte++;
  }

  ASSERT(idx_byte < btmp->btmp_bytes_len);
  if (idx_byte == btmp->btmp_bytes_len) { //该内存池已找不到空间
    return -1;
  }

  //在位图数组范围内的某字节内找到了空闲位，在该字节内逐位比对，返回空闲位的索引
  int idx_bit = 0; // 字节内的索引(范围0-7)
  while ((uint8_t)(BITMAP_MASK << idx_bit) & btmp->bits[idx_byte]) {
    idx_bit++;
  }

  int bit_idx_start = idx_byte * 8 + idx_bit; // 空闲位在位图内的下标
  if (cnt == 1) {
    return bit_idx_start;
  }

  uint32_t bit_left = (btmp->btmp_bytes_len * 8 - bit_idx_start);
  // 记录还有多少位可以判断
  uint32_t next_bit = bit_idx_start + 1;
  uint32_t count = 1; //用于记录找到的空闲位数

  bit_idx_start = -1; // 先将其置为-1，若找不到连续的位置就直接返回
  while (bit_left-- > 0) {
    if (!(bitmap_scan_test(btmp, next_bit))) { //如果next_bit为0
      count++;
    } else {
      count = 0;
    }
    if (count == cnt) { // 若找到连续的cnt个空位
      bit_idx_start = next_bit - cnt + 1;
      break;
    }
    next_bit++;
  }
  return bit_idx_start;
}

// 将位图的btmp的bit_idx位设置为value
void bitmap_set(struct bitmap *btmp, uint32_t bit_idx, int8_t value) {
  ASSERT((value == 0) || (value == 1));
  uint32_t byte_idx = bit_idx / 8; //向下取整用于索引数组下标
  uint32_t bit_odd = bit_idx % 8;  // 取余用于索引数组内的位

  // 一般用0x1这样的数对字节中的位操作，将1任意移动后再取反，或者先取反再移位，可用来对位置0操作
  if (value) { // value==1
    btmp->bits[byte_idx] |= (BITMAP_MASK << bit_odd);
  } else {
    btmp->bits[byte_idx] &= ~(BITMAP_MASK << bit_odd);
  }
}