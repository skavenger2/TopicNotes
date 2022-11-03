# With the PyJTW library
# pip3 install pyjwt

# HS256

import jwt

# Fill in the header
header = {
        "alg":"HS256"
}

# Add your secret key
key = "secret1"

# Add they payload
payload = {
        "sub":"administrator",
}

print(jwt.encode(payload, key, algorithm="HS256"))


# Create keys with OpenSSL and setting 'e' and 'n'

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
