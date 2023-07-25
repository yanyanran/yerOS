#include "print.h"
#include "io.h"

// VGA的显示缓冲的起点是0xB8000
static uint16_t *video_memory = (uint16_t *)0xc00b8000;

// 屏幕"光标"的坐标
static uint8_t cursor_x = 0;
static uint8_t cursor_y = 0;

static const uint8_t attribute_byte = (0 << 4) | (15 & 0x0F); // 白字黑底
static const uint16_t blank = 0x20 | (attribute_byte << 8);   // 空格

void set_cursor() {
  uint16_t cursorLocation = cursor_y * 80 + cursor_x; // 屏幕80字节宽
  // 先设置高8位
  outb(0x3d4, 0x0e);
  outb(0x3d5, cursorLocation >> 8);
  outb(0x3d4, 0x0f);
  outb(0x3d5, cursorLocation & 0xff);
}

void cls_screen() {
  int i;
  for (i = 0; i < 80 * 25; i++) {
    video_memory[i] = blank;
  }
  // 将光标重置到开头
  cursor_x = 0;
  cursor_y = 0;
  set_cursor();
}

// 屏幕滚动
static void scroll() {
  if (cursor_y >= 25) { // 超出屏幕范围
    int i;
    // 所有数据往前移动一行
    for (i = 0 * 80; i < 24 * 80; i++) {
      video_memory[i] = video_memory[i + 80];
    }
    // 最后一行使用blank进行填充
    for (i = 24 * 80; i < 25 * 80; i++) {
      video_memory[i] = blank;
    }
    // 向上移动了一行，所以cursor_y现在是24
    cursor_y = 24;
  }
}

void put_char_color(char cstr, real_color_t back, real_color_t fore) {
  uint8_t back_color = (uint8_t)back;
  uint8_t fore_color = (uint8_t)fore;

  uint8_t attribute_byte = (back_color << 4) | (fore_color & 0x0F);
  uint16_t attribute = attribute_byte << 8;

  if (cstr == 0x08 && cursor_x) { // 0x08是退格键的ASCII码
    cursor_x--;
    video_memory[cursor_y * 80 + cursor_x] = back; // 删除用空格填充
  } else if (cstr == 0x09) {                          // 0x09是tab键的ASCII码
    cursor_x =
        (cursor_x + 8) & ~(8 - 1); // 该操作是将光标移动到下一个8的整数倍处
  } else if (cstr == '\r') {
    cursor_x = 0;
    cursor_y++;
  } else if (cstr == '\n') {
    cursor_x = 0;
    cursor_y++;
  } else if (cstr >= ' ') {
    video_memory[cursor_y * 80 + cursor_x] = cstr | attribute;
    cursor_x++;
  }

  if (cursor_x >= 80) { // 每80个字符一行，满80必须换行
    cursor_x = 0;
    cursor_y++;
  }

  scroll();     // 如果需要的话滚动屏幕显示
  set_cursor(); // 移动硬件的输入光标
}

// 输出字符串(白字黑底)
void put_str(char *message) {
  while (*message) {
    put_char_color(*message++, rc_black, rc_white);
  }
}

// 屏幕输出一个十六进制的整型数
void put_int(uint32_t num) {
  if (num == 0) {
    put_char_color('0', rc_black, rc_white);
    return;
  }
  char arr[16];
  int m;
  int i = 0;
  while (num) {
    m = num % 16;
    arr[i++] = m;
    num = num / 16;
  }
  int j;
  for (j = i - 1; j >= 0; j--) {
    if (arr[j] <= 9) {
      put_char_color(arr[j] + '0', rc_black, rc_white);
    } else {
      put_char_color('A' + arr[j] - 10, rc_black, rc_white);
    }
  }
}

// 屏幕输出一个十进制的整型数
void put_int10(uint32_t num) {
  if (num == 0) {
    put_char_color('0', rc_black, rc_white);
    return;
  }
  char arr[16];
  int m;
  int i = 0;
  while (num) {
    m = num % 10;
    arr[i++] = m;
    num = num / 10;
  }
  int j;
  for (j = i - 1; j >= 0; j--) {
    put_char_color(arr[j] + '0', rc_black, rc_white);
  }
}

// 屏幕输出一个char
void put_char(uint8_t char_asci) {
  put_char_color(char_asci, rc_black, rc_white);
  return;
}