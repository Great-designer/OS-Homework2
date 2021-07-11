#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts. Also creates the idle thread. */
//通过启用中断启动抢占式线程调度。也会创建空闲线程。
void thread_start(void) 
{
	/* Create the idle thread. *///创建空闲线程。
	struct semaphore idle_started;
	sema_init(&idle_started,0);
	thread_create("idle",PRI_MIN,idle,&idle_started);
	/* Start preemptive thread scheduling. *///启动抢占式线程调度。
	intr_enable();
	/* Wait for the idle thread to initialize idle_thread. *///等待空闲线程初始化空闲线程。
	sema_down(&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial PRIORITY, which executes FUNCTION passing AUX as the argument, and adds it to the ready queue.  Returns the thread identifier for the new thread, or TID_ERROR if creation fails. If thread_start() has been called, then the new thread may be scheduled before thread_create() returns.  It could even exit before thread_create() returns.  Contrariwise, the original thread may run for any amount of time before the new thread is scheduled.  Use a semaphore or some other form of synchronization if you need to ensure ordering. The code provided sets the new thread's `priority' member to PRIORITY, but no actual priority scheduling is implemented. Priority scheduling is the goal of Problem 1-3. */
//使用给定的初始优先级创建名为NAME的新内核线程，该线程执行传递AUX作为参数的函数，并将其添加到就绪队列中。返回新线程的线程标识符，如果创建失败，则返回TID\u错误。如果已调用thread_start（），则可以在thread_create（）返回之前调度新线程。它甚至可以在thread_create（）返回之前退出。相反，在调度新线程之前，原始线程可以运行任意时间。如果需要确保排序，请使用信号量或其他形式的同步。提供的代码将新线程的“priority”成员设置为priority，但没有实现实际的优先级调度。优先级调度是问题1-3的目标。
tid_t thread_create(const char *name,int priority,thread_func *function,void *aux) 
{
	struct thread *t;
	struct kernel_thread_frame *kf;
	struct switch_entry_frame *ef;
	struct switch_threads_frame *sf;
	tid_t tid;
	ASSERT(function!=NULL);
/* Allocate thread. */
//分配线程。
	t=palloc_get_page(PAL_ZERO);
	if(t==NULL)
	{
		return TID_ERROR;
	}
/* Initialize thread. */
//初始化线程。
	init_thread(t,name,priority);
	tid=t->tid=allocate_tid();
/* Stack frame for kernel_thread(). */
//kernel_thread（）的堆栈帧。
	kf=alloc_frame(t,sizeof *kf);
	kf->eip=NULL;
	kf->function=function;
	kf->aux=aux;
/* Stack frame for switch_entry(). */
//开关_entry（）的堆栈帧。
	ef=alloc_frame(t,sizeof *ef);
	ef->eip=(void(*)(void))kernel_thread;
/* Stack frame for switch_threads(). */
//switch_threads（）的堆栈帧。
	sf=alloc_frame(t,sizeof *sf);
	sf->eip=switch_entry;
	sf->ebp=0;
/* Add to run queue. */
//添加到运行队列。
	thread_unblock (t);
	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled again until awoken by thread_unblock(). This function must be called with interrupts turned off.  It is usually a better idea to use one of the synchronization primitives in synch.h. */
//使当前线程休眠。在被thread_unblock（）唤醒之前，不会再次计划它。调用此函数时必须关闭中断。在synch.h中使用同步原语通常是一个更好的主意。 
void thread_block(void) 
{
	ASSERT(!intr_context());
	ASSERT(intr_get_level()==INTR_OFF);
	thread_current()->status=THREAD_BLOCKED;
	schedule();
}

/* Transitions a blocked thread T to the ready-to-run state. This is an error if T is not blocked.  (Use thread_yield() to make the running thread ready.) This function does not preempt the running thread.  This can be important: if the caller had disabled interrupts itself, it may expect that it can atomically unblock a thread and update other data. */
//将阻塞的线程T转换为准备运行状态。如果T没有被阻止，这是一个错误。（使用thread_yield（）使正在运行的线程就绪。）此函数不会抢占正在运行的线程。这一点很重要：如果调用方禁用了中断本身，它可能希望它能够自动地解除对线程的阻塞并更新其他数据。 
void thread_unblock(struct thread *t) 
{
	enum intr_level old_level;
	ASSERT(is_thread(t));
	old_level=intr_disable();
	ASSERT(t->status==THREAD_BLOCKED);
	list_push_back(&ready_list,&t->elem);
	t->status=THREAD_READY;
	intr_set_level(old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread. This is running_thread() plus a couple of sanity checks. See the big comment at the top of thread.h for details. */
struct thread *thread_current(void)//返回正在运行的线程。线程正在运行几个u（）检查。有关详细信息，请参阅thread.h顶部的大注释。 
{
	struct thread *t=running_thread();/* Make sure T is really a thread. If either of these assertions fire, then your thread may have overflowed its stack.  Each thread has less than 4 kB of stack, so a few big automatic arrays or moderate recursion can cause stack overflow. */
	ASSERT(is_thread(t));//确保T真的是一条线。如果这两个断言中的任何一个被触发，那么您的线程可能已经溢出了它的堆栈。每个线程的堆栈小于4KB，因此几个大的自动数组或适度的递归都可能导致堆栈溢出。
	ASSERT(t->status==THREAD_RUNNING);//一个断言t指针是一个线程， 一个断言这个线程处于THREAD_RUNNING状态。
	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and may be scheduled again immediately at the scheduler's whim. */
//产生CPU。当前线程没有进入睡眠状态，可能会在调度程序的突发奇想下立即重新调度。
void thread_yield(void)//把当前线程扔到就绪队列里， 然后重新schedule， 注意这里如果ready队列为空的话当前线程会继续在cpu执行。
{
	struct thread *cur=thread_current();//返回正在运行的线程。
	enum intr_level old_level;
	ASSERT(!intr_context());//断言这是个软中断。 
	old_level=intr_disable();//线程机制保证的一个原子性操作。 
	if(cur!=idle_thread)//如果当前线程不是空闲的线程。 
	{
		list_push_back(&ready_list,&cur->elem);//调用list_push_back把当前线程的元素扔到就绪队列里面。
	}
	cur->status=THREAD_READY;//把线程改成THREAD_READY状态。
	schedule();//调用schedule。 
	intr_set_level(old_level);//线程机制保证的一个原子性操作。 
}

/* Invoke function 'func' on all threads, passing along 'aux'. This function must be called with interrupts off. */
//在所有线程上调用函数“func”，传递“aux”。调用此函数时必须关闭中断。
void thread_foreach(thread_action_func *func,void *aux)
{
	struct list_elem *e;
	ASSERT(intr_get_level()==INTR_OFF);
	for(e=list_begin(&all_list);e!=list_end(&all_list);e=list_next(e))
	{
		struct thread *t=list_entry(e,struct thread,allelem);
		func(t,aux);
	}
}

/* Sets the current thread's priority to NEW_PRIORITY. */
//将当前线程的优先级设置为新的优先级。
void thread_set_priority(int new_priority) 
{
	thread_current()->priority=new_priority;
}

/* Returns the current thread's priority. */
//返回当前线程的优先级。
int thread_get_priority(void) 
{
	return thread_current()->priority;
}

/* Sets the current thread's nice value to NICE. */
//将当前线程的nice值设置为nice。
void thread_set_nice(int nice UNUSED) 
{
	/* Not yet implemented. */
}

/* Returns the current thread's nice value. */
//返回当前线程的nice值。
int thread_get_nice(void) 
{
	/* Not yet implemented. */
	return 0;
}

/* Returns 100 times the system load average. */
//返回平均系统负载的100倍。
int thread_get_load_avg(void) 
{
	/* Not yet implemented. */
	return 0;
}

/* Returns 100 times the current thread's recent_cpu value. */
//返回当前线程最近的cpu值的100倍。
int thread_get_recent_cpu(void) 
{
	/* Not yet implemented. */
	return 0;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *running_thread(void)//返回正在运行的线程。
{
	uint32_t *esp;/* Copy the CPU's stack pointer into `esp', and then round that down to the start of a page.  Because `struct thread' is always at the beginning of a page and the stack pointer is somewhere in the middle, this locates the curent thread. */
	asm ("mov %%esp, %0" : "=g" (esp));//将CPU的堆栈指针复制到“esp”中，然后向下舍入到页面的开头。因为“struct thread”总是在页的开头，堆栈指针在中间的某个地方，所以它会定位当前线程。 
	return pg_round_down(esp);//把CPU栈的指针复制到esp中， 然后调用pg_round_down（在vaddr.c中）。 返回当前线程起始指针。
}

/* Returns true if T appears to point to a valid thread. */
static bool is_thread(struct thread *t)//如果T似乎指向有效线程，则返回true。
{
	return t!=NULL&&t->magic==THREAD_MAGIC;//用于检测时候有栈溢出的这么个元素。（在thread.h中） 
}

/* Does basic initialization of T as a blocked thread named NAME. */
//将T作为名为NAME的阻塞线程进行基本初始化。
static void init_thread(struct thread *t,const char *name,int priority)
{
	enum intr_level old_level;
	ASSERT(t!=NULL);
	ASSERT(PRI_MIN<=priority&&priority<=PRI_MAX);
	ASSERT(name!=NULL);
	memset(t,0,sizeof *t);
	t->status=THREAD_BLOCKED;
	strlcpy(t->name,name,sizeof t->name);
	t->stack=(uint8_t *)t+PGSIZE;
	t->priority=priority;
	t->magic=THREAD_MAGIC;
	
#ifdef USERPROG
	list_init(&(t->fd_list));
	list_init(&t->children);
#endif
	
	old_level=intr_disable();
	list_push_back(&all_list,&t->allelem);
	intr_set_level(old_level);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should return a thread from the run queue, unless the run queue is empty.  (If the running thread can continue running, then it will be in the run queue.)  If the run queue is empty, return idle_thread. */
//选择并返回要调度的下一个线程。应该从运行队列返回一个线程，除非运行队列为空。（如果正在运行的线程可以继续运行，那么它将位于运行队列中。）如果运行队列为空，则返回idle_thread。
static struct thread *next_thread_to_run(void)
{
	if(list_empty(&ready_list))//如果就绪队列空闲直接返回一个空闲线程指针。 
	{
		return idle_thread;
	}
	else//否则拿就绪队列第一个线程出来返回。
	{
		return list_entry(list_pop_front(&ready_list),struct thread,elem);
	}
}

/* Completes a thread switch by activating the new thread's page tables, and, if the previous thread is dying, destroying it. At this function's invocation, we just switched from thread PREV, the new thread is already running, and interrupts are still disabled.  This function is normally invoked by thread_schedule() as its final action before returning, but the first time a thread is scheduled it is called by switch_entry() (see switch.S).  It's not safe to call printf() until the thread switch is complete.  In practice that means that printf()s should be added at the end of the function. After this function and its caller returns, the thread switch is complete. */
//通过激活新线程的页表来完成线程切换，如果前一个线程正在消亡，则销毁它。在这个函数的调用中，我们刚从threadprev切换过来，新线程已经在运行，中断仍然被禁用。此函数通常由thread_schedule（）调用，作为返回之前的最后一个操作，但第一次调度线程时，它由switch_entry（）调用（请参见switch.S）。在thread开关完成之前调用printf（）是不安全的。实际上，这意味着printf（）应该添加到函数的末尾。在这个函数及其调用者返回之后，线程切换就完成了。 
void thread_schedule_tail(struct thread *prev)//获取当前线程， 分配恢复之前执行的状态和现场， 如果当前线程死了就清空资源。 
{
	struct thread *cur=running_thread();//先是获得当前线程cur, 注意此时是已经切换过的线程了（或者还是之前run的线程， 因为ready队列为空）。
	ASSERT(intr_get_level()==INTR_OFF);
	cur->status=THREAD_RUNNING;/* Mark us as running. *///把我们标记为跑步。把线程状态改成THREAD_RUNNING。 
	thread_ticks=0;/* Start new time slice. *///开始新的时间片。然后thread_ticks清零开始新的线程切换时间片。
#ifdef USERPROG
	/* Activate the new address space. *///激活新地址空间。
	process_activate();//调用process_activate（process.c中）触发新的地址空间。更新页目录表，更新任务现场信息（TSS）。
#endif
/* If the thread we switched from is dying, destroy its struct thread.  This must happen late so that thread_exit() doesn't pull out the rug under itself.  (We don't free initial_thread because its memory was not obtained via palloc().) */
	if(prev!=NULL&&prev->status==THREAD_DYING&&prev!=initial_thread)//如果我们从中切换的线程正在消亡，请销毁其struct线程。在地毯下的线程不会自动退出。（我们不能释放初始的_线程，因为它的内存不是通过palloc（）获得的。）
	{
		ASSERT(prev!=cur);
		palloc_free_page(prev);//（在palloc.c中） 
	}
}

/* Schedules a new process.  At entry, interrupts must be off and the running process's state must have been changed from running to some other state.  This function finds another thread to run and switches to it. It's not safe to call printf() until thread_schedule_tail() has completed. */
//安排新流程。进入时，中断必须关闭，并且正在运行的进程的状态必须已从“运行”更改为其他状态。此函数会找到另一个要运行的线程并切换到它。在thread_schedule_tail（）完成之前调用printf（）是不安全的。 
static void schedule(void)//拿下一个线程切换过来继续run。
{
	struct thread *cur=running_thread();//首先获取当前线程cur
	struct thread *next=next_thread_to_run();//调用next_thread_to_run获取下一个要run的线程
	struct thread *prev=NULL;
	ASSERT(intr_get_level()==INTR_OFF);//确保不能被中断，当前线程是RUNNING_THREAD等。
	ASSERT(cur->status!=THREAD_RUNNING);
	ASSERT(is_thread (next));
	if(cur!=next)//如果当前线程和下一个要跑的线程不是同一个的话调用switch_threads（在switch.h中）返回给prev。
	{
		prev=switch_threads(cur,next);
	}
	thread_schedule_tail(prev);//参数prev是NULL或者在下一个线程的上下文中的当前线程指针。
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

//从所有线程列表中按tid获取线程
//如果线程不退出，则返回null
struct thread* get_thread_by_tid(tid_t id)
{
	struct list_elem *e;
	for(e=list_begin(&all_list);e!=list_end(&all_list);e=list_next(e))
	{
		struct thread *t=list_entry(e,struct thread,allelem);
		if(t->tid==id)
		{
			return t;
		}
	}
	return NULL;
}


/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);
