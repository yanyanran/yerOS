#ifndef DEVICE_CONSOLE
#define DEVICE_CONSOLE
#include "print.h"

void console_init();
void console_put_str(char *str);
void console_put_char(uint8_t char_asci);
void console_put_int(uint32_t num);
void sys_putchar(uint8_t char_asci);
void console_write_color(char *cstr, real_color_t back, real_color_t fore);

#endif /* DEVICE_CONSOLE */
