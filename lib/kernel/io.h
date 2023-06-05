/*--------------------------机器模式：端口IO函数---------------------------------*/
#ifndef __LIB_IO_H
#define __LIB_IO_H
#include "stdint.h"

// 向端口写入1字节
static inline void outb(uint16_t port, uint8_t data) {
  asm volatile("outb %b0, %w1" ::"a"(data), "Nd"(port));
}

// 向端口写入（addr处起始的word_cnt）个字【2字节为单位】
static inline void outsw(uint16_t port, const void *addr, uint32_t word_cnt) {
  asm volatile("cld; rep outsw" : "+S"(addr), "+c"(word_cnt) : "d"(port));
}

// 从端口读1字节
static inline uint8_t inb(uint16_t port) {
  uint8_t data;
  asm volatile("inb %w1, %b0" : "=a"(data) : "Nd"(port));
  return data;
}

// 把从端口读的word_cnt个字【2字节为单位】写入addr
static inline void insw(uint16_t port, void *addr, uint32_t word_cnt) {
  asm volatile("cld; rep insw"
               : "+D"(addr), "+c"(word_cnt)
               : "d"(port)
               : "memory");
}
#endif
