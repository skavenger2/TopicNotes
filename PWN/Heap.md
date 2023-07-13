# Heap

Stack is used for local vars.  
Dynamically allocated memory uses the heap.  
Generally used when the memory requirements depend on the users input.  

Heap grows up, where the stack grows down.  

## System Break

The "system break" is the limit of a processes memory.  
`brk()` and `sbrk()` system calls extend or reduce the limits of a processes memory.  
These are inefficient and cannot be reclaimed when not in use.  

Most heap allocators are front-ends for brk()/sbrk().  
