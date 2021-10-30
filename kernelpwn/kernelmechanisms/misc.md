# 1. Kernel pwn tricks

## 1.Kernel Security Protection Mechanisms

### 1.1 Kernel ASLR



## 2.



# 2. Build a kernel for QEMU

​	There is a configuration called tinyconfig, which can build a tiny version of Linux kernel, use it like

```bash
make tinyconfig
```

​	Also, to make the kernel and debuging friendly there are some options we need to turn on



# 3.Bypass KPTI 

​	KPTI ( Kernel Page Table Isolation) is a kernel protection feature, which seperates the kernel-space page table and user space page table entirely.

​	When the kernel is running without KPTI, the procedure of ret2user is like retting to a stack with rop chain as follows

```c
    swapgs_ret    <-  esp
--------------
    iretq
--------------
 (target_rip)
--------------
   (user_cs)
--------------
 (user_rflags)
--------------
  (user_sp)
--------------
   (user_ss)
```

​	If the KPTI is enbled, ret2usr this way will resuling in a segment fault when accessing the user space code. To bypass this mechanism we choose to perform ret2usr by `swapgs_restore_regs_and_return_to_usermode`. It is a exported symbol in kernel to return to user space from kenrel space. The implementatino is like







## 4. find *modprobe_path*

​	When the compile option `CONFIG_KALLSYMS_ALL` is not turned on, which was defaut, the symble *modprob_path* is not exported to */proc/kallsyms*, making it impossible to get it by directly reading the file. We can get its address by setting a break to *call_usermodehelper_setup*.

​	The symbol *call_usermodehelper_setup* is exported to */proc/kallsyms* by default, so we can get it in most cases by reading */proc/kallsyms*. The implementation in kernel is like

```c
static int call_modprobe(char *module_name, int wait)
{
    .....
    info = call_usermodehelper_setup(modprobe_path, argv, envp, GFP_KERNEL,
					 NULL, free_modprobe_argv, NULL);
    .....
}
```

after we setting the break point we can trigger the execution like

```bash
echo -ne "\xff\xff\xff\xff\xff" > /tmp/dummy
chmod +x /tmp/dummy
/tmp/dummy
```

When the execution hit the break point the address of *modprobe_path* will be at `RDI` as the first argument of the function.

​	Refer to 

1. https://github.com/smallkirby/kernelpwn/blob/master/technique/modprobe_path.md
2. https://github.com/smallkirby/kernelpwn/blob/master/important_config/KALLSYMS_ALL.md



## 5. disable overwriting to *modprobe_path*

​	The kernel compile option `CONFIG_STATIC_USERMODEHELPER` can be tunned on to set *modprobe_path* as a static string, making it unable to be overwirten. The option is off by default however.



## 6. use *setxattr* to write arbitrary data to kernel

​	The implementation of *setxattr* is under *fs/xattr.c* as follows

```c
static long
setxattr(struct user_namespace *mnt_userns, struct dentry *d,
	 const char __user *name, const void __user *value, size_t size,
	 int flags)
{
	.....

	if (size) {
		if (size > XATTR_SIZE_MAX)
			return -E2BIG;
		kvalue = kvmalloc(size, GFP_KERNEL);
		if (!kvalue)
			return -ENOMEM;
		if (copy_from_user(kvalue, value, size)) {
		.....
out:
	kvfree(kvalue);

	return error;
}
```

​	The function *setxattr* allocates a chunk in kernel heap according to the parameter *size* and copy user space data at **value* to it. The two parameters are fully under user's control, allowing us to allocate an arbitrary size chunk in kernel heap then write arbitrary data to it. This can be useful if we cause a double free in kernel heap and place some struct(tty_struct, cred, all kinds of vtable,...) in the chunk. We hope to get the chunk again and write data to it to overwrite some value inside the struct.

​	*setxattr* fullfills our demand. Let's say we have put a *seq_operations* struct in the double-freed chunk and we want to overwrite a function pointers in the struct. We can invoke

```c
setxattr("/dummy_file", "dummy", start_cp_addr, 0x20, XATTR_CREATE);
```

​	The *setxattr* will allocate a `0x20` chunk from the kernel heap and we can hope the chunk is the double-freed one which is now a *seq_operations* struct. Then data at *start_cp_addr* will be copied to the kernel heap chunk, overwriting the *seq_operation*.

​	The data we want to copy to the kernel chunk should have a layout like

![setxattr](pic/setxattr.png)

this cause the kernel to stop execute when the copy reaches the uffd-registerd page, so the chunk allocated by *setxattr* will not be immediately freed. And if we set the handler to the uffd to a simply *hang()* the chunk will never be freed.



