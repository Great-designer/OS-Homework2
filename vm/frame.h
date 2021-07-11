#ifndef VM_FRAME_H
#define VM_FRAME_H

#include<stdbool.h>

#include "threads/synch.h"

struct frame//一个物理帧
{
	struct lock lock;//防止同时访问
	void *base;//内核虚拟基址
	struct page *page;//映射的进程页（如果有）
};

void frame_init(void);

struct frame *frame_alloc_and_lock(struct page *);
void frame_lock(struct page *);

void frame_free(struct frame *);
void frame_unlock(struct frame *);

#endif /* vm/frame.h */
