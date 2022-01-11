#define CMD_ADD
#define CMD_SELECT
#define CMD_DELE
#define CMD_WRITE


void* kernote_ioctl(void* d, long cmd, long arg){
    ....
    void* ptr;
    void* note[0x10];

    if(cmd == CMD_ADD){

        note[arg] = kmalloc(0x20);

    }else if(cmd == CMD_SELECT){

        ptr = note[arg];

    }else if(cmd == CMD_WRITE){

        copy_from_user(ptr, arg, 8);

    }else if(cmd == CMD_DELE){

        kfree(note[arg]);
        
    }
    .....
}