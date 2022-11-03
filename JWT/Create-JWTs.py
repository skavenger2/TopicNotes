# pip3 install pyjwt
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
