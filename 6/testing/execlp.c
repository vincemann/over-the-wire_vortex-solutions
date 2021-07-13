#include <unistd.h>
#include <stdio.h>
// ./wrapper formatstring binary 
int main(int argc, char** argv)

{
  execlp(argv[1],argv[1],0);
  return;
}