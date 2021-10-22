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

​	KPTI ( Kernel Page Table Isolation) is a kernel protection feature, which seperates the kernel-space page table and user space page table entirely

​	When the kernel is running without KPTI, the procedure of ret2user is like retting to a stack with rop chain like

```c
    swapgs_ret    <- esp
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



​	If the KPTI is enbled, ret2usr this way will resuling in a segment fault when accessing the user space code. To 
