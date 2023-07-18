#include "debug.h"
#include "dir.h"
#include "string.h"
#include "syscall.h"

// 将路径old_abs_path中的..和.转换为实际路径后存入new_abs_path
static void wash_path(char *old_abs_path, char *new_abs_path) {
  ASSERT(old_abs_path[0] == '/');
  char name[MAX_FILE_NAME_LEN] = {0}; // 存储路径中解析出来的各层目录名
  char *sub_path = old_abs_path;
  sub_path = path_parse(sub_path, name); // 将最上层路径名解析出来（类似pop

  if (name[0] == 0) { // 只键入了"/"
    new_abs_path[0] = '/';
    new_abs_path[1] = 0;
    return;
  }
  new_abs_path[0] = 0; // 避免传给new_abs_path的缓冲区不干净
  strcat(new_abs_path, "/");

  while (name[0]) {
    if (!strcmp("..", name)) { // 路径是“..”
      char *slash_ptr = strrchr(new_abs_path, '/');
      if (slash_ptr != new_abs_path) {
        /*
         * 未到new_abs_path顶层目录-> 将最右边'/'替换为0
         * 这样便去除了new_abs_path中最后一层路径，相当于到了上一级目录
         * [e.g.] new_abs_path 为“/a/b”，".."后变为“/a”
         */
        *slash_ptr = 0;
      } else { // new_abs_path中只有1个'/'-> 已到顶层目录,将下个字符置为结束符0
        *(slash_ptr + 1) = 0;
      }
    } else if (strcmp(".", name)) { // 路径不是‘.’
      if (strcmp(new_abs_path, "/")) {
        strcat(new_abs_path, "/");
      }
      strcat(new_abs_path, name);
    }
    // 路径为"."，无需处理new_abs_path

    // 继续遍历下层路径
    memset(name, 0, MAX_FILE_NAME_LEN);
    if (sub_path) {
      sub_path = path_parse(sub_path, name);
    }
  }
}

// 将path处理成绝对路径存在final_path中
void make_clear_abs_path(char *path, char *final_path) {
  char abs_path[MAX_PATH_LEN] = {0};

  if (path[0] != '/') { // 不是绝对路径
    memset(abs_path, 0, MAX_PATH_LEN);
    if (getcwd(abs_path, MAX_PATH_LEN) != NULL) {
      if (!((abs_path[0] == '/') && (abs_path[1] == 0))) {
        // 若abs_path表示的当前目录不是根目录
        strcat(abs_path, "/");
      }
    }
  }
  strcat(abs_path, path);
  wash_path(abs_path, final_path);
}