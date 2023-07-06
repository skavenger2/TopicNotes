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

## Certificate Not Checked

Same steps as for `Known Key`, but provide any matching certificate and key.  

## SAMLResponse Forwarding

Decode the `SAMLResponse` to change the destination before re-encoding and submitting it to the target service provider.  
The following tools can be used to decode and re-encode:  
<https://www.samltool.com/decode.php>  
<https://www.samltool.com/encode.php>  
If those links no longer work, the steps include:  
**Decode SAMLRequest:**  

1. URL decode
2. Base64 decode
3. Inflate

**Encode SAMLRequest:**  

1. Deflate
2. Base64 encode
3. URL encode

## Comment Injection

In some cases, comments are ignored when verifying the signature, AND the comment and everything after it is removed when retreiving the NameID.  

If you want to impersonate `admin@example.com`, register an account with `admin@example.com.test.com`.  
Log in to th eidentity provider and interpcept requests with "Burp Suite" and the "SAML Raider" extension.  
Edit the `SAMLResponse` by injecting a comment in the email address field:  
`admin@example.com.test.com` becomes `admin@example.com<!--HACK-->.test.com`.  
If the service provider ignores the comment and everything after it, this should allow you to impersonate the target user.  
