## Level 0

Starting off level 0 we are greeted with the following:
```
  GCC stack protector support:            Enabled
  Strict user copy checks:                Disabled
  Restrict /dev/mem access:               Enabled
  Restrict /dev/kmem access:              Enabled
  grsecurity / PaX: No GRKERNSEC
  Kernel Heap Hardening: No KERNHEAP
 System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   /home/user/level0/level0
```

And running `ls -la` provides us the output:

```
level0@RainFall:~$ ls -la
total 737
dr-xr-x---+ 1 level0 level0     60 Mar  6  2016 .
dr-x--x--x  1 root   root      340 Sep 23  2015 ..
-rw-r--r--  1 level0 level0    220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level0 level0   3530 Sep 23  2015 .bashrc
-rw-r--r--  1 level0 level0    675 Apr  3  2012 .profile
-rwsr-x---+ 1 level1 users  747441 Mar  6  2016 level0
```

We see that all we are given is a level0 binary, lets try running it:
```bash
level0@RainFall:~$ ./level0 
Segmentation fault (core dumped)
```

Instantly a segfault.. Lets see what happens when we provide it with an argument:

```bash
level0@RainFall:~$ ./level0 test
No !
```

Great! We can already assume that there is something going on with the `argv`.
Now we can start looking through the binary to really dig into the meat of the executable.
We'll be using `gdb` to disassemble and run the program with breakpoints.
For those not familiar with assembly, this binary uses the cdecl calling convention, where parameters are passed to functions on the stack.  

```asm
(gdb) disass main
Dump of assembler code for function main:
   0x08048ec0 <+0>:	push   %ebp
   0x08048ec1 <+1>:	mov    %esp,%ebp
   0x08048ec3 <+3>:	and    $0xfffffff0,%esp
   0x08048ec6 <+6>:	sub    $0x20,%esp
   0x08048ec9 <+9>:	mov    0xc(%ebp),%eax
   0x08048ecc <+12>:	add    $0x4,%eax
   0x08048ecf <+15>:	mov    (%eax),%eax
   0x08048ed1 <+17>:	mov    %eax,(%esp)
   0x08048ed4 <+20>:	call   0x8049710 <atoi>
   0x08048ed9 <+25>:	cmp    $0x1a7,%eax
   0x08048ede <+30>:	jne    0x8048f58 <main+152>
   0x08048ee0 <+32>:	movl   $0x80c5348,(%esp)
   0x08048ee7 <+39>:	call   0x8050bf0 <strdup>
   0x08048eec <+44>:	mov    %eax,0x10(%esp)
   0x08048ef0 <+48>:	movl   $0x0,0x14(%esp)
   0x08048ef8 <+56>:	call   0x8054680 <getegid>
   0x08048efd <+61>:	mov    %eax,0x1c(%esp)
   0x08048f01 <+65>:	call   0x8054670 <geteuid>
   0x08048f06 <+70>:	mov    %eax,0x18(%esp)
   0x08048f0a <+74>:	mov    0x1c(%esp),%eax
   0x08048f0e <+78>:	mov    %eax,0x8(%esp)
   0x08048f12 <+82>:	mov    0x1c(%esp),%eax
   0x08048f16 <+86>:	mov    %eax,0x4(%esp)
   0x08048f1a <+90>:	mov    0x1c(%esp),%eax
   0x08048f1e <+94>:	mov    %eax,(%esp)
   0x08048f21 <+97>:	call   0x8054700 <setresgid>
   0x08048f26 <+102>:	mov    0x18(%esp),%eax
   0x08048f2a <+106>:	mov    %eax,0x8(%esp)
   0x08048f2e <+110>:	mov    0x18(%esp),%eax
   0x08048f32 <+114>:	mov    %eax,0x4(%esp)
   0x08048f36 <+118>:	mov    0x18(%esp),%eax
   0x08048f3a <+122>:	mov    %eax,(%esp)
   0x08048f3d <+125>:	call   0x8054690 <setresuid>
   0x08048f42 <+130>:	lea    0x10(%esp),%eax
   0x08048f46 <+134>:	mov    %eax,0x4(%esp)
   0x08048f4a <+138>:	movl   $0x80c5348,(%esp)
   0x08048f51 <+145>:	call   0x8054640 <execv>
   0x08048f56 <+150>:	jmp    0x8048f80 <main+192>
   0x08048f58 <+152>:	mov    0x80ee170,%eax
   0x08048f5d <+157>:	mov    %eax,%edx
   0x08048f5f <+159>:	mov    $0x80c5350,%eax
   0x08048f64 <+164>:	mov    %edx,0xc(%esp)
   0x08048f68 <+168>:	movl   $0x5,0x8(%esp)
   0x08048f70 <+176>:	movl   $0x1,0x4(%esp)
   0x08048f78 <+184>:	mov    %eax,(%esp)
   0x08048f7b <+187>:	call   0x804a230 <fwrite>
   0x08048f80 <+192>:	mov    $0x0,%eax
   0x08048f85 <+197>:	leave  
   0x08048f86 <+198>:	ret    
End of assembler dump.
```

Lets disassemble the disassembly piece by piece to see what exactly is going on.
In the first few line we can see that the stack gets aligned and that there is memory reserved on the stack for 32 (0x20) bytes:

```asm
   push   %ebp
   mov    %esp,%ebp
   and    $0xfffffff0,%esp
   sub    $0x20,%esp
```

Next up we can see an `atoi` call.
Before this happens `argv` is loaded into `%eax`, after which it is dereferenced again to access `argv[1]`.
Then the string pointer of `argv[1]` is pushed onto the stack so `atoi` can make use of it.
Notice how no checks are done to see if `argc` is valid, this causes our segfault when not providing any arguments.

```asm
   mov    0xc(%ebp),%eax   ; <argv is stored>
   add    $0x4,%eax        ; <argv[1] offset>
   mov    (%eax),%eax      ; <argv[1] stored>
   mov    %eax,(%esp)      ; <argv[1] pushed onto the stack>
   call   0x8049710 <atoi>
```

After the `atoi` call there is a compare with its return value to 423 (0x1a7).
If the value does not match there is a jump to a later location of the main.

```asm
   cmp    $0x1a7,%eax
   jne    0x8048f58 <main+152>
```

If we follow the branch where the compare has a match with 423 we will find a call to `strdup`.
The result of which gets saved on the stack, along side of a 0/null value.

```asm
   movl   $0x80c5348,(%esp)
   call   0x8050bf0 <strdup>
   mov    %eax,0x10(%esp)
   movl   $0x0,0x14(%esp)
```

We can find out which string is being copied using the following gdb commands:

```
(gdb) break main
Breakpoint 1 at 0x8048ec3

(gdb) run
Starting program: /home/user/level0/level0 

Breakpoint 1, 0x08048ec3 in main ()

(gdb) x /s 0x80c5348
0x80c5348:       "/bin/sh"
```

The `x` command will examine the memory found at the given address after which /s formats it as a string.
We see that the string value stored onto the stack is `"/bin/sh"`, the path to a shell executable.

Moving on we are hit with `getegid` and `geteuid` calls, which also get stored onto the stack:

```asm
   call   0x8054680 <getegid>
   mov    %eax,0x1c(%esp)
   call   0x8054670 <geteuid>
   mov    %eax,0x18(%esp)
```

Next up there is a bunch of moving between different parts of the stack and the `%eax` register.
We can tell that the code is not pulled through any compiler optimizations since the `%eax` register gets filled with the value found at `0x1c(%esp)` despite it not being changed in between other `mov`s.
The `setresgid` is called at the end, which requests 3 parameters, `uid_t ruid, uid_t euid, uid_t suid`.
All of the moves we see are done to set the return value of `getegid` to these parameters.

```asm
   mov    0x1c(%esp),%eax
   mov    %eax,0x8(%esp)
   mov    0x1c(%esp),%eax
   mov    %eax,0x4(%esp)
   mov    0x1c(%esp),%eax
   mov    %eax,(%esp)
   call   0x8054700 <setresgid>
```

The same is done for the `setresuid` and the return value of `geteuid`.
It also requires 3 parameters `uid_t ruid, uid_t euid, uid_t suid`.

```asm
   mov    0x18(%esp),%eax
   mov    %eax,0x8(%esp)
   mov    0x18(%esp),%eax
   mov    %eax,0x4(%esp)
   mov    0x18(%esp),%eax
   mov    %eax,(%esp)
   call   0x8054690 <setresuid>
```

After we have set our gid and uid we see a load of the address found at `0x10(%esp)` into the `%eax` register.
This was the return value of of our previous `strdup` call, followed by a NULL pointer.
The address is then stored back onto the stack with an offset of 4 bytes `0x4(%esp)`, making it the second parameter to the upcoming `execv` call.
The first parameter being `$0x80c5348` which is the same pointer given to `strdup`, the string `"/bin/sh"`. 

```asm
   lea    0x10(%esp),%eax
   mov    %eax,0x4(%esp)
   movl   $0x80c5348,(%esp)
   call   0x8054640 <execv>
```

After our execve call there is a jump to the end of main, just in case it fails. 

```asm
   jmp    0x8048f80 <main+192>
```

There still is one branch left.
The assembly we have just walked through was all related to the `atoi` call matching the value of `423`.
But what happens if the compare is not equal? The following code is ran:

```asm
   mov    0x80ee170,%eax
   mov    %eax,%edx
   mov    $0x80c5350,%eax
   mov    %edx,0xc(%esp)
   movl   $0x5,0x8(%esp)
   movl   $0x1,0x4(%esp)
   mov    %eax,(%esp)
   call   0x804a230 <fwrite>
```

A call to `fwrite`, this function expects 4 parameters `const void* buffer, size_t size, size_t count, FILE* stream`.

We can instantly tell the 2nd and 3rd parameters being `1` and `5`.
Lets try to figure out what the other parameters are.
Just like we did with `strdup` we can see what the buffer being written contains:

```
(gdb) x /s 0x80c5350
0x80c5350:       "No !\n"
```

All there is left is to figure out what the `FILE* stream` is pointing to!
Again we can make use of `gdb`:

```
(gdb) x /wx 0x80ee170
0x80ee170 <stderr>:     0x080ee7a0
```

Using the same `x` examine command, formatted to a word (w, 4 bytes) and displayed in hexadecimal (x).
Thanks to `gdb` we can instantly see that the FILE* points to the stderr.

We have now completely dissected the assembly and can rebuild it ourselves!

## Solution

After piecing everything together we can conclude that we will gain shell access if we provide the string `"423"` as input to the executable!
Lets try it and obtain our flag:

```bash
level0@RainFall:~$ ./level0 423
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

A much more readable C version of the disassembly can be found [here](source.c).
