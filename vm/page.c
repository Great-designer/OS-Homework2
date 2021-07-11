#include<stdio.h>
#include<string.h>

#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"

//进程堆栈的最大大小，以字节为单位
//现在是1兆字节
#define STACK_MAX (1024 * 1024)

//销毁页，该页必须在当前进程的页表中
//用作hash_destroy()的回调
static void destroy_page(struct hash_elem *p_,void *aux UNUSED)
{
	struct page *p=hash_entry(p_,struct page,hash_elem);
	frame_lock(p);
	if(p->frame)
	{
		frame_free(p->frame);
	}
	free(p);
}

//销毁当前进程的页表
void page_exit(void)
{
	struct hash *h=thread_current()->pages;
	if(h!=NULL)
	{
		hash_destroy(h,destroy_page);
	}
}

//返回包含给定虚拟地址的页，如果不存在此类页，则返回空指针
//根据需要分配堆栈
static struct page *page_for_addr(const void *address)
{
	if(address<PHYS_BASE)
    {
		struct page p;
		struct hash_elem *e;
//查找现有页面
		p.addr=(void *)pg_round_down(address);
		e=hash_find(thread_current()->pages,&p.hash_elem);
		if(e!=NULL)
		{
			return hash_entry(e,struct page,hash_elem);
		}
//我们需要确定程序是否试图访问堆栈
//首先，我们确保地址不超出堆栈空间的界限（在本例中为1MB）
//只要用户试图在堆栈指针的32个字节（由PUSHA命令所需的空间决定）内获取地址，我们就假定该地址是有效的
//在这种情况下，我们应该相应地再分配一个堆栈页
		if((p.addr>PHYS_BASE-STACK_MAX)&&((void *)thread_current()->user_esp-32<address))
		{
			return page_allocate(p.addr,false);
		}
	}
	return NULL;
}

//锁定P页的框架并将其放入其中
//成功时返回true，失败时返回false
static bool do_page_in(struct page *p)
{
//获取页面的框架
	p->frame=frame_alloc_and_lock(p);
	if(p->frame==NULL)
	{
		return false;
	}
//将数据复制到帧中
	if(p->sector!=(block_sector_t)-1)
	{
//从交换中获取数据
		swap_in(p);
	}
	else if(p->file!=NULL)
	{
//从文件获取数据
		off_t read_bytes=file_read_at(p->file,p->frame->base,p->file_bytes,p->file_offset);
		off_t zero_bytes=PGSIZE-read_bytes;
		memset(p->frame->base+read_bytes,0,zero_bytes);
		if(read_bytes!=p->file_bytes)
		{
			printf("bytes read (%"PROTd") != bytes requested (%"PROTd")\n",read_bytes,p->file_bytes);
		}
	}
	else
	{
//提供所有零页
		memset(p->frame->base,0,PGSIZE);
	}
	return true;
}

//包含错误地址的页面中的错误
//成功时返回true，失败时返回false
bool page_in(void *fault_addr)
{
	struct page *p;
	bool success;
//没有哈希表就无法处理页面错误
	if(thread_current()->pages==NULL)
	{
		return false;
	}
	p=page_for_addr(fault_addr);
	if(p==NULL)
	{
		return false;
	}
	frame_lock(p);
	if(p->frame==NULL)
	{
		if(!do_page_in(p))
		{
			return false;
		}
	}
	ASSERT(lock_held_by_current_thread(&p->frame->lock));
//将框架安装到页表中
	success=pagedir_set_page(thread_current()->pagedir,p->addr,p->frame->base,!p->read_only);
//释放框架
	frame_unlock(p->frame);
	return success;
}

//逐出第P页
//P必须有一个锁定的框架
//如果失败则返回true
bool page_out(struct page *p)
{
	bool dirty;
	bool ok=false;
	ASSERT(p->frame!=NULL);
	ASSERT(lock_held_by_current_thread(&p->frame->lock));
//在页表中标记页不存在，强制进程访问出错
//这必须在检查脏位之前发生，以防止进程与弄脏页面的竞争
	pagedir_clear_page(p->thread->pagedir, (void *) p->addr);
//框架是否已修改
//如果帧已被修改，请将“脏”设置为true
	dirty=pagedir_is_dirty(p->thread->pagedir, (const void *) p->addr);
//如果框架不脏（和file！=NULL），我们成功地收回了该页
	if(!dirty)
	{
		ok=true;
	}
//如果文件为空，我们肯定不想将帧写入磁盘
//我们必须交换帧，并保存交换是否成功
//这可能会覆盖以前的“确定”值
	if(p->file==NULL)
	{
		ok=swap_out(p);
	}
//否则，此页存在一个文件
//如果文件内容已被修改，则必须将其写回磁盘上的文件系统，或将其换出
//这由与页面相关联的私有变量决定
	else
	{
		if(dirty)
		{
			if(p->private)
			{
				ok=swap_out(p);
			}
			else
			{
				ok=file_write_at(p->file, (const void *) p->frame->base, p->file_bytes, p->file_offset);
			}
		}
	}
//使页所持的帧无效
	if(ok)
	{
		p->frame=NULL;
	}
	return ok;
}

//如果最近访问过P页的数据，则返回true，否则返回false
//P必须在内存中锁定一个帧
bool page_accessed_recently(struct page *p)
{
	bool was_accessed;
	ASSERT(p->frame!=NULL);
	ASSERT(lock_held_by_current_thread(&p->frame->lock));
	was_accessed=pagedir_is_accessed(p->thread->pagedir,p->addr);
	if(was_accessed)
	{
		pagedir_set_accessed(p->thread->pagedir,p->addr,false);
	}
	return was_accessed;
}

//将用户虚拟地址VADDR的映射添加到页哈希表
//如果已映射VADDR或内存分配失败，则失败
struct page *page_allocate (void *vaddr,bool read_only)
{
	struct thread *t=thread_current();
	struct page *p=malloc(sizeof *p);
	if(p!=NULL)
	{
		p->addr=pg_round_down(vaddr);
		p->read_only=read_only;
		p->private=!read_only;
		p->frame=NULL;
		p->sector=(block_sector_t)-1;
		p->file=NULL;
		p->file_offset=0;
		p->file_bytes=0;
		p->thread=thread_current();
		if(hash_insert(t->pages,&p->hash_elem)!=NULL)
		{
//已经映射
			free(p);
			p=NULL;
		}
	}
	return p;
}

//逐出包含地址VADDR的页并将其从页表中删除
void page_deallocate(void *vaddr)
{
	struct page *p=page_for_addr(vaddr);
	ASSERT(p!=NULL);
	frame_lock(p);
	if(p->frame)
	{
		struct frame *f=p->frame;
		if(p->file&&!p->private)
		{
			page_out(p);
		}
		frame_free(f);
	}
	hash_delete(thread_current()->pages,&p->hash_elem);
	free(p);
}

//返回E引用的页的哈希值
unsigned page_hash(const struct hash_elem *e,void *aux UNUSED)
{
	const struct page *p=hash_entry(e,struct page,hash_elem);
	return ((uintptr_t) p->addr) >> PGBITS;
}

//如果页A在页B之前，则返回true
bool page_less(const struct hash_elem *a_,const struct hash_elem *b_,void *aux UNUSED)
{
	const struct page *a=hash_entry(a_,struct page,hash_elem);
	const struct page *b=hash_entry(b_,struct page,hash_elem);
	return a->addr<b->addr;
}

//尝试将包含ADDR的页面锁定到物理内存中。
//如果WILL_WRITE为true，则该页必须是可写的；否则它可能是只读的。
//成功时返回true，失败时返回false。
bool page_lock(const void *addr,bool will_write)
{
	struct page *p=page_for_addr(addr);
	if(p==NULL||(p->read_only&&will_write))
	{
		return false;
	}
	frame_lock(p);
	if(p->frame==NULL)
	{
		return (do_page_in(p)&& pagedir_set_page (thread_current ()->pagedir, p->addr,p->frame->base, !p->read_only));
	}
	else
	{
		return true;
	}
}

//解锁已锁定的页面page_lock()。
void page_unlock(const void *addr)
{
	struct page *p=page_for_addr(addr);
	ASSERT(p!=NULL);
	frame_unlock(p->frame);
}
