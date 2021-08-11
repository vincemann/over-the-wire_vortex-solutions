#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(int argc, char const *argv[])
{
	int curr_time = time(NULL);
	printf("%d\n", curr_time);
	return 0;
}