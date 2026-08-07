int main() {
    // Clear eax, will be used as a NULL pointer
    asm("xor %eax, %eax");

    // Push the shell string string onto the stack
    // Second half (bytes 4-7): "/sh\0"
    asm("mov $0x1179623e, %ecx");
    asm("xor $0x11111111, %ecx");
    asm("push %ecx");

    // First half (bytes 0-3): "/bin"
    asm("mov $0x7f78733e, %ebx");
    asm("xor $0x11111111, %ebx");
    asm("push %ebx");

    // Set execve's first argument
    asm("mov %esp, %ebx");
    // ebx = pointer to "/bin/sh\0"

    // Create argv and set execve's second argument
    asm("push %eax");
    // argv[1] = NULL
    asm("push %ebx");
    // argv[0] = pointer to "/bin/sh\0"
    asm("mov %esp, %ecx");
    // ecx = pointer to argv

    // Set execve's third argument
    asm("xor %edx, %edx");
    // envp = NULL

    // Call execve 
    asm("mov $11, %eax");
    asm("int $0x80");

    return 0;
}
