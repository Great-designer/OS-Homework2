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

struct fd_entry//�ļ�������
{
	int fd;
	struct file *file;
	struct list_elem elem;
	struct list_elem thread_elem;
};

static struct list file_list;

static int alloc_fid(void)//�ļ�������id����������2���ɵ����н��̡� 
{
	static int fid=2;
	return fid++;
}

static struct fd_entry *find_fd_entry_by_fd_in_process(int fd)//�ڵ�ǰ�߳�fd_�б��в���fd_��
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

static struct file *find_file_by_fd(int fd)//��fd�����ļ�
{
	struct fd_entry *ret;
	ret=find_fd_entry_by_fd (fd);
	if(!ret)
	{
		return NULL;
	}
	return ret->file;
}


void halt()//0ֹͣ����ϵͳ��
{
	shutdown();
}

void exit(int status)//1�Ը���״̬�˳���ǰ�̡߳�
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

pid_t exec(const char *cmd_line)//2��������ִ���ļ���
{
	return process_execute(cmd_line);
}

int wait(pid_t pid)//3�ȴ��ӽ�����ֹ��
{
	return process_wait(pid);
}

//�ɹ�����true�������ļ����������
bool create(const char *file,unsigned initial_size)//4�����ļ���
{
    return filesys_create(file,initial_size);
}

//�ɹ�����true�������ļ��򿪻��ǹرգ�������ɾ����ɾ���ļ�����ر�����
bool remove(const char *file)//5ɾ���ļ���
{
	return filesys_remove(file);
}

int open(const char *file)//6���ļ���
{
	struct file* f=filesys_open(file);
	if(f==NULL)//��ʧ�ܣ���ֹ����
	{
		return -1;
	}
	//����ļ�������
	struct fd_entry *fde=(struct fd_entry *)malloc(sizeof(struct fd_entry));
	if(fde==NULL)//mallocʧ��
	{
		file_close(f);
		return -1;//��ʧ��
	}
	struct thread *cur=thread_current();
	fde->fd=alloc_fid();
	fde->file=f;
	list_push_back(&cur->fd_list,&fde->thread_elem);
	list_push_back(&file_list,&fde->elem);
	return fde->fd;
}

int filesize(int fd)//7��ȡ�ļ���С��
{
	struct file *f=find_file_by_fd(fd);
	if(f==NULL)
	{
		exit(-1);
	}
	return file_length(f);
}

int read(int fd,void *buffer,unsigned size)//8�ļ��ж�ȡ��
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

int write(int fd,const void *buffer,unsigned size)//9д���ļ���
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

void seek(int fd, unsigned position)//10�ı��ļ�λ�á�
{
	struct file *f=find_file_by_fd(fd);
	if(f==NULL)
	{
		exit(-1);
	}
	file_seek(f,position);
}

unsigned tell(int fd)//11�����ļ���ǰλ�á�
{
	struct file *f=find_file_by_fd(fd);
	if(f==NULL)
	{
		exit(-1);
	}
	return file_tell(f);
}

//�˳�����ֹ������ʽ�عر������д򿪵��ļ�������������Ϊÿ�����������ô˺���һ����
void close(int fd)//12�ر��ļ���
{
	struct fd_entry *f=find_fd_entry_by_fd_in_process(fd);
	if(f==NULL)//�رն�ν�ʧ��
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

//������µ�ַ�Ƿ���Ч��ȫ����Чʱ����true�� 
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

//�������Ч�ַ������򷵻�true 
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
