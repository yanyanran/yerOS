#ifndef KERNEL_INTERRUPT
#define KERNEL_INTERRUPT
typedef void *intr_handler;
void idt_init();
#endif /* KERNEL_INTERRUPT */
