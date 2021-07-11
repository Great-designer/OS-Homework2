#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

#include "threads/synch.h"

struct lock file_lock;

typedef int pid_t;

void halt(void);//0ֹͣ����ϵͳ��
void exit(int status);//1�Ը���״̬�˳���ǰ�̡߳�
pid_t exec(const char *cmd_line);//2��������ִ���ļ���
int wait(pid_t pid);//3�ȴ��ӽ�����ֹ��
bool create(const char *file,unsigned initial_size);//4�����ļ���
bool remove(const char *file);//5ɾ���ļ���
int open(const char *file);//6���ļ���
int filesize(int fd);//7��ȡ�ļ���С��
int read(int fd,void *buffer,unsigned size);//8���ļ��ж�ȡ��
int write(int fd,const void *buffer,unsigned size);//9д���ļ���
void seek(int fd,unsigned position);//10�ı��ļ�λ�á�
unsigned tell(int fd);//11�����ļ���ǰλ�á�
void close(int fd);//12�ر��ļ���

#endif /* userprog/syscall.h */
