# JWK Header Injection With Burpsuite

## Burp Extensions

- JWT Editor Keys
- JSON Web Tokens

## Steps

1. With the extension loaded, in Burp's main tab bar, go to the JWT Editor Keys tab.
2. Generate a new RSA key.
3. Send a request containing a JWT to Burp Repeater.
4. In the message editor, switch to the extension-generated JSON Web Token tab and modify the token's payload however you like.
5. Click Attack, then select Embedded JWK. When prompted, select your newly generated RSA key.
6. Send the request to test how the server responds.
