/* part1.c */
#include <unistd.h>
#include <stdio.h>
int main(int argc, char** argv)
{	
    char* programArgv[] = {NULL};
    // first arg is format string, second arg is env var with shellcode
    char* const envp[4] = {"AAAA", argv[2],argv[1] , NULL};
    execve(argv[3], programArgv, envp);

    // this should never be called
    puts("execve failed...");
    return 0x42;
}
