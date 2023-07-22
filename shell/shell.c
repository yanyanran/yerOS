#include "shell.h"
#include "assert.h"
#include "buildin_cmd.h"
#include "debug.h"
#include "file.h"
#include "fs.h"
#include "global.h"
#include "stdint.h"
#include "stdio.h"
#include "string.h"
#include "syscall.h"

#define MAX_ARG_NR 16 // 加上命令名，最多支持15个参数
#define cmd_len 128

char final_path[MAX_PATH_LEN] = {0};
static char cmd_line[MAX_PATH_LEN] = {0}; // 存储输入命令
char cwd_cache[MAX_PATH_LEN] = {0}; // 当前目录缓存（每次cd时会更新此内容
char *argv[MAX_ARG_NR]; // 参数字符串数组（必须为全局变量，为以后exec程序可访问
int32_t argc = -1;

// 输出提示符
void print_prompt(void) { printf("[yers@localhost %s]$ ", cwd_cache); }

static void readline(char *buf, int32_t count) {
  assert(buf != NULL && count > 0);
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
    case '\b':              // 退格键
      if (buf[0] != '\b') { // 阻止删除非本次输入的信息
        --pos;              // 退回到缓冲区cmd_line中上一个字符
        putchar('\b');
      }
      break;
    case 'l' - 'a': // ctrl+l清屏
      *pos = 0;
      clear();
      print_prompt();
      printf("%s", buf);
      break;
    case 'u' - 'a': // ctrl+u清掉输入
      while (buf != pos) {
        putchar('\b');
        *(pos--) = 0;
        break;
      }
    default: // 非控制键则输出字符
      putchar(*pos);
      pos++;
    }
  }
  printf("readline: can`t find enter_key in the cmd_line, max num of char is "
         "128\n");
}

// 分析字符串cmd_str中以token为分隔符的单词，将各单词指针存入argv数组
static int32_t cmd_parse(char *cmd_str, char **argv, char token) {
  assert(cmd_str != NULL);
  int32_t arg_idx = 0;
  while (arg_idx < MAX_ARG_NR) {
    argv[arg_idx] = NULL;
    arg_idx++;
  }
  char *next = cmd_str;
  int32_t argc = 0;

  while (*next) {
    while (*next == token) { // 去除命令字或参数间的空格
      next++;
    }
    if (*next == 0) { // 处理最后一个参数后接空格的情况
      break;
    }
    argv[argc] = next;

    while (*next && *next != token) { // 在字符串结束前找单词分隔符
      next++;
    }
    if (*next) { // 如果未结束（是token字符）-> tocken变0
      *next++ =
          0; // 将token字符替换为字符串结束符0作为一个单词的结束，并将字符指针next指向下一个字符
    }

    if (argc > MAX_ARG_NR) { // 避免argv数组访问越界
      return -1;
    }
    argc++;
  }
  return argc;
}

void my_shell(void) {
  cwd_cache[0] = '/';

  while (1) {
    print_prompt();
    memset(final_path, 0, MAX_PATH_LEN);
    memset(cmd_line, 0, MAX_PATH_LEN);
    readline(cmd_line, MAX_PATH_LEN);
    if (cmd_line[0] == 0) { // 若只键入了一个回车
      continue;
    }
    argc = -1;
    argc = cmd_parse(cmd_line, argv, ' ');
    if (argc == -1) {
      printf("num of arguments exceed %d\n", MAX_ARG_NR);
      continue;
    }

    if (!strcmp("ls", argv[0])) {
      buildin_ls(argc, argv);
    } else if (!strcmp("cd", argv[0])) {
      if (buildin_cd(argc, argv) != NULL) {
        memset(cwd_cache, 0, MAX_PATH_LEN);
        strcpy(cwd_cache, final_path);
      }
    } else if (!strcmp("pwd", argv[0])) {
      buildin_pwd(argc, argv);
    } else if (!strcmp("ps", argv[0])) {
      buildin_ps(argc, argv);
    } else if (!strcmp("clear", argv[0])) {
      buildin_clear(argc, argv);
    } else if (!strcmp("mkdir", argv[0])) {
      buildin_mkdir(argc, argv);
    } else if (!strcmp("rmdir", argv[0])) {
      buildin_rmdir(argc, argv);
    } else if (!strcmp("rm", argv[0])) {
      buildin_rm(argc, argv);
    } else { // 如果是外部命令-> 需要从磁盘加载
      int32_t pid = fork();
      if (pid) { // 父进程
        int32_t status;
        int32_t child_pid = wait(&status);
        // 此时子进程若没有执行exit, my_shell会被阻塞不再响应键入命令
        if (child_pid == -1) {
          panic("my_shell: no child\n");
        }
        printf("child_pid %d, it's status: %d\n", child_pid, status);
      } else { // 子进程
        make_clear_abs_path(argv[0], final_path);
        argv[0] = final_path;
        struct stat file_stat;
        memset(&file_stat, 0, sizeof(struct stat));
        if (stat(argv[0], &file_stat) == -1) { // 判断文件是否存在
          printf("my_shell: cannot access %s: No such file or directory\n",
                 argv[0]);
          exit(-1);
        } else {
          execv(argv[0], argv);
        }
      }
    }
    int32_t arg_idx = 0;
    while (arg_idx < MAX_ARG_NR) {
      argv[arg_idx] = NULL;
      arg_idx++;
    }
  }
  PANIC("my_shell: should not be here");
}