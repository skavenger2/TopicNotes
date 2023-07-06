# SAML

## Fingerprint SAML Certificates

B64 decode a SAML Response and pull out the x509 certificate.  
Place it in a cert.pem file with `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` surrounding it.  
Format the text to new line every 64 chars.  
Issue: `openssl x509 -in cert.pem -noout -fingerprint` to get the fingerprint to search for default/known keys.  

## Known Key

If you have the key in a `rsa.pem` file:  
Use `SAML Raider` in Burpsuite.  
Import `cert.pem` and click `Traditional RSA PEM...` to load the rsa.pem file.  
Go through the apps auth flow again and intercept the request with the SAML Response.  
Search for the value you want to change, change it and click `(Re-)Sign Assertion` before forwarding the request.  
This should allow impersonation.  
