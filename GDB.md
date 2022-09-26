
# Debuggers 1012 - Introductory GDB
p.ost2.fyi

---

GDB command `start` is equivalent to setting a temporary breakpoint at main then running the program  

Breakpoints set with `break` or `b`  

`info breakpoints` lists all breakpoints  

Clear breakpoints with `clear main` or `clear *0xdeadbeef`  
alt `delete <breakpoint-number>` will clear a breakpoint from the `i b` command  

Examine memory with `x`  
`x/10i <addr>` prints 10 instractions following the specified address  

`watch <addr>` will set a breakpoint to break when the address is written to  

`rwatch <addr>` will set a breakpoint to break when the address is read from  

`awatch <addr>` will set a breakpoint to break when the address is written to or read from  

After `i b`, disable or enable breakpoints with `disable <number>` or `enable <number>`  

`print <address or register>` will display a register or address  

## Hardware vs Software Breakpoints on Intel Hardware

GDB can set an unlimited number of software breakpoints but only 4 hardware breakpoints  
These special purpose debug registers inform the memory management unit that it should watch for read, write, execute, or IO accesses targeted the specified addresses/IO ports  

Use `hb` the same way you would use `b` to set a hardware breakpoint  

## Format Specifiers

/FMT is the combination of the / character, followed by a number n, a format specifier f, and a unit size specifier u. Each of n, f, and u are optional, and will default to the last-used values or default initial values if left unspecified.  
Eg. `x/10i`  
n of 10, f of 'i' for instructions, with no u needed  

Common format specifiers:  

- `x` for hex
- `d` for decimal
- `u` for unsigned decimal
- `c` for ASCII
- `s` for ASCII string
- `i` for instructions

Full list [here](https://sourceware.org/gdb/onlinedocs/gdb/Output-Formats.html)  

Unit sizes for *u* are:  

- `b` for bytes
- `h` for half-words (2 bytes)
- `w` for words (4 bytes)
- `g` for giant words (8 bytes)

***Note*** *that GDB's notion of words (4 bytes) is at odds with Intel's notion of words (2 bytes)! This will be something you will just have to memorize and keep in mind.*  

## Viewing Registers

`i r` to view registers  
You can also specify registers with `i r rax rbx rsp`  

You can also use the `print` command:  

`p/x $rax`  
$11 = 0xface  

## Modifying Registers

`set $rax = 0xdeadbeeff00dface`  

## Viewing Memory

`x/8xb $rsp`  
Can also call addresses  

## Modifying Memory

Similar to registers, memory can be modified with the `set` command, also optionally specifying a C-style type in order to specify the length to write  

```gdb
(gdb) x/1xg $rsp
0x7fffffffe038:	0x00007ffff7ded0b3
(gdb) set {char}$rsp = 0xFF
(gdb) x/1xg $rsp
0x7fffffffe038:	0x00007ffff7ded0ff
(gdb) set {short}$rsp = 0xFF
(gdb) x/1xg $rsp
0x7fffffffe038:	0x00007ffff7de00ff
(gdb) set {short}$rsp = 0xFFFF
(gdb) x/1xg $rsp
0x7fffffffe038:	0x00007ffff7deffff
(gdb) set {long long}$rsp = 0x1337bee7
(gdb) x/1xg $rsp
0x7fffffffe038:	0x000000001337bee7  
```

**Note** that immediates which are smaller than the size of the specified memory write are zero-extended, not sign-extend  

## Updating Stack View

Use the `display` command with a /FMT specifier indicating the number of hex giant-words you want to display, starting with the RSP  

`display/8xg $rsp`

## Stack Backtrace

`backtrace` or `bt` provides a call stack backtrace  

## Step Into vs Step Over vs Step Out

As with other debuggers, the notion of "step over" indicates that the UI should step over call instructions - executing all instructions therein, but not showing the debugger UI as stopped until the instruction after the call instruction is reached. "Step into" on the other hand will step into call instructions. "Step out" will step until a function exit is reached.  

Step over: `ni` (`nexti`)  
Step into: `si` (`stepi`)  
Step out: `fin` (`finish`)  

## Temporary Code Breakpoints aka Run Until Address

Step forward a number of instructions without setting and deleting a breakpoint with `until <addr>`. Shortform `u <addr>`  

## Attaching to Running Userspace Processes

ptrace() perms can restrict ability to attach to non-child processes.  Run gdb as root or derestrict access with  

```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
# Remembering to re-restrict access when done via:
echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

### Attach to running processes

With sufficient perms, attach to \<process ID\> from ithin gdb with `attach <process ID>`  

## Changing Disassembly Syntax

```bash
set disassembly-flavor intel
set disassembly-flavor att
```

## GDB Commands File

Create plain text file at `~/gdbCfg`  
On separate lines, enter the commands you wish to run on GDB startup  
When you start gdb, specify the "-x" option (eg `-x ~/gdbCfg`)  

Example ~/gdbCfg:  

```bash
display/10i $rip
display/x $rbp
display/x $rsp
display/x $rax
display/x $rbx
display/x $rcx
display/x $rdx
display/x $rdi
display/x $rsi
display/x $r8
display/x $r9
display/10gx $rsp
start
```
