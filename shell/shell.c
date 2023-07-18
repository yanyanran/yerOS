#include "debug.h"
#include "file.h"
#include "global.h"
#include "stdint.h"
#include "stdio.h"
#include "string.h"
#include "syscall.h"

#define cmd_len 128
#define MAX_ARG_NR 16 // 加上命令名，最多支持15个参数

static char cmd_line[cmd_len] = {0}; // 存储输入命令
char cwd_cache[64] = {0}; // 当前目录缓存（每次cd时会更新此内容

// 输出提示符
void print_prompt(void) { printf("[yers@localhost %s]$ ", cwd_cache); }

static void readline(char *buf, int32_t count) {
  ASSERT(buf != NULL && count > 0);
  char *pos = buf;
  while (read(stdin_no, pos, 1) != -1 &&
         (pos - buf) < count) { // 不出错情况下，直到找到回车符才返回
    switch (*pos) {
    // 找到回车或换行符后认为键入的命令结束，直接返回
    case '\n':
    case '\r':
      *pos = 0; // 添加cmd_line终止字符0
      putchar('\n');
      return;
    case '\b':// 退格键
      if (buf[0] != '\b') { // 阻止删除非本次输入的信息
        --pos;              // 退回到缓冲区cmd_line中上一个字符
        putchar('\b');
      }
      break;
    default: // 非控制键则输出字符
      putchar(*pos);
      pos++;
    }
  }
  printf("readline: can`t find enter_key in the cmd_line, max num of char is "
         "128\n");
}

void my_shell(void) {
  cwd_cache[0] = '/';
  while (1) {
    print_prompt();
    memset(cmd_line, 0, cmd_len);
    readline(cmd_line, cmd_len);
    if (cmd_line[0] == 0) { // 若只键入了一个回车
      continue;
    }
  }
  PANIC("my_shell: should not be here");
}