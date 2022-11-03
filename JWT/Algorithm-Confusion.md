# JWT Algorithm Confusion

## Prerequisits

1. JWT is signed with RS256
2. The public key is available
3. Burpsuite extension JWT Editor Keys
4. Burpsuite extension JSON Web Tokens

## Step 1 - Obtain the server's public key

Often exposed at `/.well-known/jwks.json` or `/jwks.json`  
Copy an individual JWK, no extra characters  

## Step 2 - Convert public key to a suitable format

1. In Burp, go to the JWT Editor Keys tab in Burp's main tab bar.
2. Click New RSA Key.
3. In the dialog, make sure that the JWK option is selected, then paste the JWK that you just copied. Click OK to save the key.
4. Right-click on the entry for the key that you just created, then select Copy Public Key as PEM.
5. Use the Decoder tab to Base64 encode this PEM key, then copy the resulting string.
6. Go back to the JWT Editor Keys tab in Burp's main tab bar.
7. Click New Symmetric Key. In the dialog, click Generate to generate a new key in JWK format. Note that you don't need to select a key size as this will automatically be updated later.
8. Replace the generated value for the k property with a Base64-encoded PEM that you just created.
9. Save the key.

## Step 3 - Modify and sign the token

1. Send a request with a JWT to the repeater tab and open the JSON Web Token tab
2. In the header of the JWT, change the value of the alg parameter to HS256
3. In the payload, change what you want
4. At the bottom of the tab, click Sign, then select the symmetric key that you generated in the previous section
5. Make sure that the Don't modify header option is selected, then click OK. The modified token is now signed using the server's public key as the secret key
6. Win
