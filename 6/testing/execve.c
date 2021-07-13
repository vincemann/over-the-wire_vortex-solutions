#include <unistd.h>
#include <stdio.h>
// ./wrapper formatstring binary 
int main(int argc, char** argv)

{
  execve("sh","sh",0);
  printf("%s\n", "failed");
  return;
}