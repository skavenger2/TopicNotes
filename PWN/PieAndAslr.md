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
