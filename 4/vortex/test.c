/* part1.c */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char** argv)
{	
    printf(argv[1]);
    exit(2);
    return 0x42;
}