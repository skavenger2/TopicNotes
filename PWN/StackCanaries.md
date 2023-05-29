# Stack Canaries

The LSB of a canary is always a NUL byte.  
If you have a memory leak, you can overflow the buffer and overwrite the NUL byte  
so that the print doesn't end on a NUL.  To get the cookie, you can read the bytes  
after your input and add a NUL to the LSB.  

