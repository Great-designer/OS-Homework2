#include<stdio.h>

#include "devices/timer.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/page.h"

static struct frame *frames;
static size_t frame_cnt;

static struct lock scan_lock;
static size_t hand;

void frame_init(void)//初始化帧管理器
{
	void *base;
	lock_init(&scan_lock);
	frames=malloc(sizeof *frames*init_ram_pages);
	if(frames==NULL)
	{
		PANIC("out of memory allocating page frames");
	}
	while((base=palloc_get_page(PAL_USER))!=NULL) 
	{
		struct frame *f=&frames[frame_cnt++];
		lock_init(&f->lock);
		f->base=base;
		f->page=NULL;
	}
}

static struct frame *try_frame_alloc_and_lock(struct page *page)//尝试为页分配和锁定帧。成功返回帧，失败返回NULL。
{
	size_t i;
	lock_acquire(&scan_lock);
	for(i=0;i<frame_cnt;i++)//找到一个自由帧
	{
		struct frame *f=&frames[i];
		if(!lock_try_acquire(&f->lock))
		{
			continue;
		}
		if(f->page==NULL) 
		{
			f->page=page;
			lock_release(&scan_lock);
			return f;
		} 
		lock_release(&f->lock);
    }
	for(i=0;i<frame_cnt*2;i++)//没有自由帧，找到要逐出的帧
    {
		struct frame *f=&frames[hand];//找个帧
		if(++hand>=frame_cnt)
		{
			hand=0;
		}
		if(!lock_try_acquire(&f->lock))
		{
			continue;
		}
		if(f->page==NULL) 
		{
			f->page=page;
			lock_release(&scan_lock);
			return f;
		} 
		if(page_accessed_recently(f->page)) 
        {
			lock_release(&f->lock);
			continue;
        }
		lock_release(&scan_lock);
		if(!page_out(f->page))//逐出此帧
        {
			lock_release(&f->lock);
			return NULL;
		}
		f->page = page;
		return f;
	}
	lock_release(&scan_lock);
	return NULL;
}

struct frame *frame_alloc_and_lock(struct page *page)//分配和锁定帧页面。成功返回帧，失败返回NULL。
{
	size_t _try;
	for(_try=0;_try<3;_try++) 
    {
		struct frame *f=try_frame_alloc_and_lock(page);
		if(f!=NULL) 
        {
			ASSERT(lock_held_by_current_thread(&f->lock));
			return f; 
		}
		timer_msleep(1000);
	}
	return NULL;
}

void frame_lock(struct page *p)//将P的帧锁定到内存中（如果有）。返回时，p->frame将不改变，直到p被解锁。
{
	struct frame *f=p->frame;//帧可以异步删除，但不能插入
	if(f!=NULL) 
	{
		lock_acquire(&f->lock);
		if(f!=p->frame)
		{
			lock_release(&f->lock);
			ASSERT(p->frame==NULL); 
		} 
	}
}

void frame_free(struct frame *f)//释放帧F以供其他页面使用。F必须被锁定以供当前进程使用。F中的任何数据都将丢失。
{
	ASSERT(lock_held_by_current_thread(&f->lock));
	f->page=NULL;
	lock_release(&f->lock);
}

void frame_unlock(struct frame *f)//解除锁定帧F，允许它被逐出。必须锁定F才能由当前进程使用。
{
	ASSERT(lock_held_by_current_thread(&f->lock));
	lock_release(&f->lock);
}
