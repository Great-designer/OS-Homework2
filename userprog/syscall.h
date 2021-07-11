#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

#include "threads/synch.h"

struct lock file_lock;

typedef int pid_t;

void halt(void);//0停止操作系统。
void exit(int status);//1以给定状态退出当前线程。
pid_t exec(const char *cmd_line);//2创建进程执行文件。
int wait(pid_t pid);//3等待子进程终止。
bool create(const char *file,unsigned initial_size);//4创建文件。
bool remove(const char *file);//5删除文件。
int open(const char *file);//6打开文件。
int filesize(int fd);//7获取文件大小。
int read(int fd,void *buffer,unsigned size);//8从文件中读取。
int write(int fd,const void *buffer,unsigned size);//9写入文件。
void seek(int fd,unsigned position);//10改变文件位置。
unsigned tell(int fd);//11报告文件当前位置。
void close(int fd);//12关闭文件。

#endif /* userprog/syscall.h */
