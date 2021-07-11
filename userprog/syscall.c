#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/synch.h"

#define STDIN 0
#define STDOUT 1

#define SYS_CALL_NUM 20

static void syscall_handler(struct intr_frame *);

static struct file *find_file_by_fd(int fd);
static struct fd_entry *find_fd_entry_by_fd(int fd);
static int alloc_fid(void);
static struct fd_entry *find_fd_entry_by_fd_in_process(int fd);

struct fd_entry//文件描述符
{
	int fd;
	struct file *file;
	struct list_elem elem;
	struct list_elem thread_elem;
};

static struct list file_list;

static int alloc_fid(void)//文件描述符id生成器，从2生成到所有进程。 
{
	static int fid=2;
	return fid++;
}

static struct fd_entry *find_fd_entry_by_fd_in_process(int fd)//在当前线程fd_列表中查找fd_项
{
	struct fd_entry *ret;
	struct list_elem *l;
	struct thread *t;
	t=thread_current();
	for(l=list_begin(&t->fd_list);l!=list_end(&t->fd_list);l=list_next(l))
    {
		ret=list_entry(l,struct fd_entry,thread_elem);
		if(ret->fd==fd)
		{
			return ret;
		}
    }
	return NULL;
}

static struct file *find_file_by_fd(int fd)//按fd查找文件
{
	struct fd_entry *ret;
	ret=find_fd_entry_by_fd (fd);
	if(!ret)
	{
		return NULL;
	}
	return ret->file;
}


void halt()//0停止操作系统。
{
	shutdown();
}

void exit(int status)//1以给定状态退出当前线程。
{
	struct thread *t;
	struct list_elem *l;
	t=thread_current();
	while(!list_empty(&t->fd_list))
	{
		l=list_begin(&t->fd_list);
		close(list_entry(l,struct fd_entry,thread_elem)->fd);
	}
	t->exit_status=status;
	thread_exit();
}

pid_t exec(const char *cmd_line)//2创建进程执行文件。
{
	return process_execute(cmd_line);
}

int wait(pid_t pid)//3等待子进程终止。
{
	return process_wait(pid);
}

//成功返回true。创建文件不会打开它。
bool create(const char *file,unsigned initial_size)//4创建文件。
{
    return filesys_create(file,initial_size);
}

//成功返回true。无论文件打开还是关闭，都可以删除，删除文件不会关闭它。
bool remove(const char *file)//5删除文件。
{
	return filesys_remove(file);
}

int open(const char *file)//6打开文件。
{
	struct file* f=filesys_open(file);
	if(f==NULL)//打开失败，终止进程
	{
		return -1;
	}
	//添加文件描述符
	struct fd_entry *fde=(struct fd_entry *)malloc(sizeof(struct fd_entry));
	if(fde==NULL)//malloc失败
	{
		file_close(f);
		return -1;//打开失败
	}
	struct thread *cur=thread_current();
	fde->fd=alloc_fid();
	fde->file=f;
	list_push_back(&cur->fd_list,&fde->thread_elem);
	list_push_back(&file_list,&fde->elem);
	return fde->fd;
}

int filesize(int fd)//7获取文件大小。
{
	struct file *f=find_file_by_fd(fd);
	if(f==NULL)
	{
		exit(-1);
	}
	return file_length(f);
}

int read(int fd,void *buffer,unsigned size)//8文件中读取。
{
	if(fd==STDIN)
	{
		for(unsigned int i=0;i<size;i++)
		{
			*((char **)buffer)[i]=input_getc();
		}
		return size;
	}
	else
	{
		struct file *f=find_file_by_fd(fd);
		if(f==NULL)
		{
			return -1;
		}
		return file_read(f,buffer,size);
	}
}

int write(int fd,const void *buffer,unsigned size)//9写入文件。
{
	if(fd==STDOUT)
	{
		putbuf((char *)buffer,(size_t)size);
		return (int)size;
	}
	else
	{
		struct file *f=find_file_by_fd(fd);
		if(f==NULL)
		{
			exit(-1);
		}
		return (int)file_write(f,buffer,size);
	}
}

void seek(int fd, unsigned position)//10改变文件位置。
{
	struct file *f=find_file_by_fd(fd);
	if(f==NULL)
	{
		exit(-1);
	}
	file_seek(f,position);
}

unsigned tell(int fd)//11报告文件当前位置。
{
	struct file *f=find_file_by_fd(fd);
	if(f==NULL)
	{
		exit(-1);
	}
	return file_tell(f);
}

//退出或终止进程隐式地关闭其所有打开的文件描述符，就像为每个描述符调用此函数一样。
void close(int fd)//12关闭文件。
{
	struct fd_entry *f=find_fd_entry_by_fd_in_process(fd);
	if(f==NULL)//关闭多次将失败
	{
		exit(-1);
	}
	file_close(f->file);
	list_remove(&f->elem);
	list_remove(&f->thread_elem);
	free(f);
}

void syscall_init(void) 
{
	intr_register_int(0x30,3,INTR_ON,syscall_handler,"syscall");
	lock_init(&file_lock);
	list_init(&file_list);
	process_init();
}


static int get_user(const uint8_t *uaddr)
{
	if(!is_user_vaddr((void *)uaddr))
	{
		return -1;
	}
	if(pagedir_get_page(thread_current()->pagedir,uaddr)==NULL)
	{
		return -1;
	}
	int result;
	asm ("movl $1f, %0; movzbl %1, %0; 1:": "=&a" (result) : "m" (*uaddr));
	return result;
}

static bool put_user(uint8_t *udst,uint8_t byte)
{
	if(!is_user_vaddr(udst))
	{
		return false;
	}
	int error_code;
	asm ("movl $1f, %0; movb %b2, %1; 1:": "=&a" (error_code), "=m" (*udst) : "q" (byte));
	return error_code!=-1;
}

//检查以下地址是否有效。全部有效时返回true。 
bool is_valid_pointer(void* esp,uint8_t argc)
{
	uint8_t i;
	for(i=0;i<argc;++i)
	{
		if((!is_user_vaddr(esp))||(pagedir_get_page(thread_current()->pagedir,esp)==NULL))
		{
			return false;
		}
	}
	return true;
}

//如果是有效字符串，则返回true 
bool is_valid_string(void *str)
{
	int ch=-1;
	while((ch=get_user((uint8_t*)str++))!='\0'&&ch!=-1);
	if(ch=='\0')
	{
		return true;
	}
	else
	{
		return false;
	}
}


static void syscall_handler(struct intr_frame *f)
{
	if(!is_valid_pointer(f->esp,4))
	{
		exit(-1);
		return;
	}
	int syscall_num=*(int *)f->esp;
	if(syscall_num<=0||syscall_num>=SYS_CALL_NUM)
	{
		exit(-1);
	}
	switch(syscall_num)
	{
		case SYS_HALT:
		{
			halt();
			break;
		}
		case SYS_EXIT:
		{
			if(!is_valid_pointer(f->esp+4,4))
			{
				exit(-1);
			}
			int status=*(int *)(f->esp+4);
			exit(status);
			break;
		}
		case SYS_EXEC:
		{
			if(!is_valid_pointer(f->esp+4,4)||!is_valid_string(*(char **)(f->esp+4)))
			{
				exit(-1);
			}
			char *file_name=*(char **)(f->esp+4);
			lock_acquire(&file_lock);
			f->eax=exec(file_name);
			lock_release(&file_lock);
			break;
		}
		case SYS_WAIT:
		{
			pid_t pid;
			if(!is_valid_pointer(f->esp+4,4))
			{
				exit(-1);
			}
			pid=*((int*)f->esp+1);
			f->eax=wait(pid);
			break;
		}
		case SYS_CREATE:
		{
			if(!is_valid_pointer(f->esp+4,4))
			{
				exit(-1);
			}
			char* file_name=*(char **)(f->esp+4);
			if(!is_valid_string(file_name))
			{
				exit(-1);
			}
			unsigned size=*(int *)(f->esp+8);
			f->eax=create(file_name,size);
			break;
		}
		case SYS_REMOVE:
		{
			if(!is_valid_pointer(f->esp+4,4)||!is_valid_string(*(char **)(f->esp+4)))
			{
				exit(-1);
			}
			char *file_name=*(char **)(f->esp+4);
			f->eax=remove(file_name);
			break;
		}
		case SYS_OPEN:
		{
			if(!is_valid_pointer(f->esp+4,4))
			{
				exit(-1);
			}
			if(!is_valid_string(*(char **)(f->esp+4)))
			{
				exit(-1);
			}
			char *file_name=*(char **)(f->esp+4);
			lock_acquire(&file_lock);
			f->eax=open(file_name);
			lock_release(&file_lock);
			break;
		}
		case SYS_FILESIZE:
		{
			if(!is_valid_pointer(f->esp+4,4))
			{
				exit(-1);
			}
			int fd=*(int *)(f->esp+4);
			f->eax=filesize(fd);
			break;
		}
		case SYS_READ:
		{
			if(!is_valid_pointer(f->esp+4,12))
			{
				exit(-1);
			}
			int fd=*(int *)(f->esp+4);
			void *buffer=*(char**)(f->esp+8);
			unsigned size=*(unsigned *)(f->esp+12);
			if(!is_valid_pointer(buffer,1)||!is_valid_pointer(buffer+size,1))
			{
				exit(-1);
			}
			lock_acquire(&file_lock);
			f->eax=read(fd,buffer,size);
			lock_release(&file_lock);
			break;
		}
		case SYS_WRITE:
		{
			if(!is_valid_pointer(f->esp+4,12))
			{
				exit(-1);
			}
			int fd=*(int *)(f->esp+4);
			void *buffer=*(char**)(f->esp+8);
			unsigned size=*(unsigned *)(f->esp+12);
			if(!is_valid_pointer(buffer,1)||!is_valid_pointer(buffer+size,1))
			{
				exit(-1);
			}
			lock_acquire(&file_lock);
			f->eax=write(fd,buffer,size);
			lock_release(&file_lock);
			break;
		}
		case SYS_SEEK:
		{
			if(!is_valid_pointer(f->esp+4,8))
			{
				exit(-1);
			}
			int fd=*(int *)(f->esp+4);
			unsigned pos=*(unsigned *)(f->esp+8);
			seek(fd,pos);
			break;
		}
		case SYS_TELL:
		{
			if(!is_valid_pointer(f->esp+4,4))
			{
				exit(-1);
			}
			int fd=*(int *)(f->esp+4);
			f->eax=tell(fd);
			break;
		}
		case SYS_CLOSE:
		{
			if(!is_valid_pointer(f->esp+4,4))
			{
				return exit(-1);
			}
			int fd=*(int *)(f->esp+4);
			close(fd);
			break;
		}
		default:
		{
			break;
		}
	}
}

static struct fd_entry *find_fd_entry_by_fd(int fd)
{
	struct fd_entry *ret;
	struct list_elem *l;
	for(l=list_begin(&file_list);l!=list_end(&file_list);l=list_next(l))
	{
		ret=list_entry(l,struct fd_entry,elem);
		if(ret->fd==fd)
		{
			return ret;
		}
	}
	return NULL;
}
