#ifndef USERPROG_PROCESS
#define USERPROG_PROCESS
#include "thread.h"

void start_process(void *filename_);
void page_dir_activate(struct task_struct *p_thread);
void process_active(struct task_struct *p_thread);
void process_execute(void *filename, char *name);

#endif /* USERPROG_PROCESS */
