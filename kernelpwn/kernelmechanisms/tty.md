# TTY struct

use

```c
open("/dev/ptmx", O_RDWR)
```

to allocate a *tty* struct in kernel space. This file is a sequence file whose ioctl is define in */drivers/tty/tty_io.c* as follows

```c
long tty_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct tty_struct *tty = file_tty(file);
	struct tty_struct *real_tty;
	void __user *p = (void __user *)arg;
	int retval;
	struct tty_ldisc *ld;
	.....
        
}
```

​	It will 