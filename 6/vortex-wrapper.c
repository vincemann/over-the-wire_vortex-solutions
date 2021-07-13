/* part1.c */
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

// ./wrapper formatstring binary 
int main(int argc, char** argv)
{	
	char* const args[2] = {argv[1],NULL};
	// does not do anything, we dont qcare about env vars
    char* const envp[4] = {"AAA", "BBB", "CCC", "DDD"};
    // last arg is program to be called
    execve(argv[1], args, envp);

    // this should never be called
    printf("Oh dear, something went wrong with execve! %s\n", strerror(errno));
    return 0x42;
}
