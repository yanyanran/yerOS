#ifndef USERPROG_EXEC
#define USERPROG_EXEC
#include "stdint.h"

int32_t sys_execv(const char *path, const char *argv[]);

#endif /* USERPROG_EXEC */
