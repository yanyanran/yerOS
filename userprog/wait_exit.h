#ifndef USERPROG_WAIT_EXIT
#define USERPROG_WAIT_EXIT
#include "thread.h"

pid_t sys_wait(int32_t *status);
void sys_exit(int32_t status);

#endif /* USERPROG_WAIT_EXIT */
