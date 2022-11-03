
# JWT Checks

## None

Decode the "Header" and change the "alg" to be a variation of "none":

- None
- none
- NoNe
- NONE

Remove the signature but keep the second period.  
Tamper the payload to what you need.  

## Not checking Sig?

Decode and change the "Payload", the server may not be checking it anyway.  

## Crack with Hashcat (HMAC - HS256)

Copy the original JWT to a text file and run Hashcat against it:  

```bash
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```
