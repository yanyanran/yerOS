#ifndef LIB_USER_SYSCALL
#define LIB_USER_SYSCALL
#include "fs.h"
#include "stdint.h"

typedef int16_t pid_t;

enum SYSCALL_NR {
  SYS_GETPID,
  SYS_WRITE,
  SYS_MALLOC,
  SYS_FREE,
  SYS_FORK,
  SYS_READ,
  SYS_PUTCHAR,
  SYS_CLEAR,
  SYS_GETCWD,
  SYS_OPEN,
  SYS_CLOSE,
  SYS_LSEEK,
  SYS_UNLINK,
  SYS_MKDIR,
  SYS_OPENDIR,
  SYS_CLOSEDIR,
  SYS_CHDIR,
  SYS_RMDIR,
  SYS_READDIR,
  SYS_REWINDDIR,
  SYS_STAT,
  SYS_PS,
  SYS_EXECV,
  SYS_EXIT,
  SYS_WAIT,
  SYS_PIPE,
  SYS_REDIRECT,
  SYS_HELP
}; // 枚举结构存放系统调用子功能号

uint32_t getpid(void);
uint32_t write(int32_t fd, const void *buf, uint32_t count);
void *malloc(uint32_t size);
void free(void *ptr);
pid_t fork();
int32_t read(int32_t fd, void *buf, uint32_t count);
void putchar(char char_asci);
void clear(void);
char *getcwd(char *buf, uint32_t size);
int32_t open(char *pathname, uint8_t flag);
int32_t close(int32_t fd);
int32_t lseek(int32_t fd, int32_t offset, uint8_t whence);
int32_t unlink(const char *pathname);
int32_t mkdir(const char *pathname);
struct dir *opendir(const char *name);
int32_t closedir(struct dir *dir);
int32_t rmdir(const char *pathname);
struct dir_entry *readdir(struct dir *dir);
void rewinddir(struct dir *dir);
int32_t stat(const char *path, struct stat *buf);
int32_t chdir(const char *path);
void ps(void);
int32_t execv(const char *path, char *argv[]);
void exit(int32_t status);
pid_t wait(int32_t *status);
int32_t pipe(int32_t pipefd[2]);
void fd_redirect(uint32_t old_local_fd, uint32_t new_local_fd);
void help(void);

#endif /* LIB_USER_SYSCALL */
