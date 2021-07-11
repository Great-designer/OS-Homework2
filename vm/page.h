#ifndef VM_PAGE_H
#define VM_PAGE_H

#include<hash.h>

#include "devices/block.h"
#include "filesys/off_t.h"
#include "threads/synch.h"

struct page//虚拟页面
{
//不变的成员
	void *addr;//用户虚拟地址
	bool read_only;//只读页
	struct thread *thread;//拥有线程
//仅在所属进程上下文中访问
	struct hash_elem hash_elem;//构造线程“pages”哈希元素
//仅在拥有frame->frame_lock的进程上下文中设置保留。清除仅在扫描锁定和frame->frame_lock保持的情况下
	struct frame *frame;//页面框架
//交换信息，受frame->frame_lock保护
	block_sector_t sector;//交换区的起始扇区，或-1
//内存映射文件信息，受frame->frame_lock保护
	bool private;//False写回文件，true写回swap
	struct file *file;//文件
	off_t file_offset;//文件中的偏移量
	off_t file_bytes;//要读/写的字节，1pg大小
};

void page_exit(void);

struct page *page_allocate(void *,bool read_only);
void page_deallocate(void *vaddr);

bool page_in(void *fault_addr);
bool page_out(struct page *);
bool page_accessed_recently(struct page *);

bool page_lock(const void *,bool will_write);
void page_unlock(const void *);

hash_hash_func page_hash;
hash_less_func page_less;

#endif /* vm/page.h */
