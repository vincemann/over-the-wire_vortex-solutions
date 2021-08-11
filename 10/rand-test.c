#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

//int main(int argc, char const *argv[])
//{
//	srand(strtol(argv[1],NULL,10));
//	int j;
//    for(j=0; j<256; j++) {
//        int r = rand();
//        printf("%d\n", r);
//    }
//	return 0;
//
int main(int argc, char **argv) {
    int seed, match, i,j;
    int found = 0;
    //seed =  time(NULL);
    match = strtol(argv[1],NULL,10);
    seed = strtol(argv[2],NULL,10);
    printf("seed : %d\n", seed);
    printf("match : %d\n", match);
    for(i=-260; i< 260; i++) {
        srand(seed+i);
        for(j=0; j<260; j++) {
            int r = rand();
            if(r == match) {
                int xx = seed+i;
                printf("%c%c%c%c\n", xx&0xff, (xx>>8)&0xff,(xx>>16)&0xff,(xx>>24)&0xff);
                //printf("found seed:%d\n", xx);
                found=1;
            }
        }
    }
    if(!found){
    	printf("%s\n", "did not find match");
    }
}