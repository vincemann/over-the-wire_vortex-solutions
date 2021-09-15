#include <unistd.h>
#include <stdio.h>
#include <libgen.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>


static void printChars(unsigned char *ptr, int size)
{
    unsigned char *p = ptr;
    int i;
    bool chars = false;
    for (i=0; i<size; i++) {
        if (isalnum(p[i])){
            chars=true;
            printf("%c", p[i]);
        } else{
            if (chars){
                printf("%s", " ");
            }
            printf("%02hhX ", p[i]);
            chars=false;
        }
    }
    printf("\n");
}



static void printBytes(void *ptr, int size)
{
    unsigned char *p = (unsigned char *)ptr;
    int i;
    for (i=0; i<size; i++) {
        printf("%02hhX ", p[i]);
    }
    printf("\n");
}

static bool isAlNum(const char * s){
    bool alnum = true;
    int len = strlen(s);
    for (int i = 0; i < len; i++) {
        if (! isalnum((int)s[i])){
            alnum= false;
            break;
        }
    }
    return alnum;
}





int main(int argc, char** argv)
{
    // char* programArgv[] = {argv[0]};
    // char* argv0 = "AAAAAAAAAAAAAAAAAAAAAAAAAAA\x08\x04\x12\x45";

    // char* base_name = basename(argv0);
    // printf("storing on stack: %s\n in hex:",base_name);
    // printBytes(base_name,strlen(base_name));

    // char* base_name = basename("/home/kali/PycharmProjects/vortex/13/vortex/AAAAAAAAAAAAAAAAAAAAAAAAAAA\x08\x04\x12\x46");
    // printf("storing on stack: %s\n in hex:",base_name);
    // printBytes(base_name,strlen(base_name));

    char* base_name = basename(argv[1]);
    printf("program name: %s\n in hex:",base_name);
    printBytes(base_name,strlen(base_name));

    // return 0x42;
    char* programArgv[] = {NULL};
    char* const envp[] = {NULL};
    execve(argv[1], programArgv, envp);
    printf("%s\n", strerror(errno));

    // this should never be called
    puts("execve failed...");
    return 0x42;
}