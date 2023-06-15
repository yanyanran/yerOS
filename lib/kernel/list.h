#ifndef LIB_KERNEL_LIST
#define LIB_KERNEL_LIST
#include "global.h"

#define offset(struct_type, member) (int)(&((struct_type *)0)->member)
#define elem2entry(struct_type, struct_member_name, elem_ptr)                  \
  (struct_type *)((int)elem_ptr - offset(struct_type, struct_member_name))

// 链表结点
struct list_elem {
  struct list_elem *prev;
  struct list_elem *next;
};

// 链表结点，用来实现队列
struct list {
  struct list_elem head; // 第一个元素head.next
  struct list_elem tail;
};

// 自定义函数类型func，用于在list_traversal中做回调函数
typedef bool (func)(struct list_elem*, int arg);

void list_init (struct list*);
void list_insert_before(struct list_elem* before, struct list_elem* elem);
void list_push(struct list* plist, struct list_elem* elem);
void list_iterate(struct list* plist);
void list_append(struct list* plist, struct list_elem* elem);
void list_remove(struct list_elem* pelem);
struct list_elem* list_pop(struct list* plist);
bool list_empty(struct list* plist);
uint32_t list_len(struct list* plist);
struct list_elem* list_traversal(struct list* plist, func f, int arg);
bool elem_find(struct list* plist, struct list_elem* obj_elem);

#endif /* LIB_KERNEL_LIST */
