
# API Testing Checklist
<https://hackanythingfor.blogspot.com/2020/07/api-testing-checklist.html>  

1. Older APIs versions tend to be more vulnerable and they lack security mechanisms.
Leverage the predictable nature of REST APIs to find old versions.
Saw a call to 'api/v3/login'? Check if 'api/v1/login' exists as well. It might be more vulnerable.

2. Never assume there’s only one way to authenticate to an API!
Modern apps have many API endpoints for AuthN: `/api/mobile/login` | `/api/v3/login` | `/api/magic_link`; etc. Find and test all of them for AuthN problems.

3. Remember how SQL Injections used to be extremely common 5-10 years ago, and you could break into almost every company? BOLA (IDOR) is the new epidemic of API security.

4. Testing a Ruby on Rails App & noticed an HTTP parameter containing a URL?
Developers sometimes use "Kernel#open" function to access URLs == Game Over.
Just send a pipe as the first character and then a shell command (Command Injection by design)

Reference Link: https://apidock.com/ruby/Kernel/open

5. Found SSRF? use it for:
- Internal port scanning
- Leverage cloud services(like 169.254.169.254)
-Use http://webhook.site to reveal IP Address & HTTP Library
-Download a very large file (Layer 7 DoS)
-Reflective SSRF? disclose local mgmt consoles

6. Mass Assignment is a real thing.
Modern frameworks encourage developers to use MA without understanding the security implications.
During exploitation, don't guess object's properties names, simply find a GET endpoint that returns all of them.

7. A company exposes an API for developers?
This is not the same API which is used by mobile / web application. Always test them separately.
Don't assume they implement the same security mechanisms.

8. Check if the API supports SOAP also.
Change the content-type to "application/xml", add a simple XML in the request body, and see how the API handles it.

9. IDs in the HTTP bodies/headers tend to be more vulnerable than IDs in URLs. Try to focus on them first.

10. Exploiting BFLA (Broken Function Level Authorization)?
Leverage the predictable nature of REST to find admin API endpoints!
E.g: you saw the following API call `GET /api/v1/users/<id>`
Give it a chance and change to DELETE / POST to create/delete users

11. The API uses Authorization header? Forget about CSRF!
If the authentication mechanism doesn't support cookies, the API is protected against CSRF by design.

12. Even if the ID is GUID or non-numeric, try to send a numeric value.
For example: "/?user_id=111" instead of "user_id=inon@traceable.ai"
Sometimes the AuthZ mechanism supports both and it's easier the brute force numbers.

13. Use Mass Assignment to bypass security mechanisms.
E.g., "enter password" mechanism:
- `POST /api/rest_pass` requires old password.
- `PUT /api/update_user` is vulnerable to MA == can be used to update pass without sending the old one (For CSRF)

14. Got stuck during an API pentest? Expand your attack surface! Find sub/sibling domains using http://Virustotal.com & http://Censys.io.
Some of these domains might expose the same APIs with different configurations/versions.

15. Static resource==photo,video,..
Web Servers(IIS, Apache) treat static resources differently when it comes to authorization.
Even if developers implemented decent authorization, there's a good chance you can access static resources of other users.

16. Even if you use another web proxy, always use Burp in the background.
The guys at @PortSwigger
 are doing a really good job at helping you manage your pentest.
Use the “tree view” (free version) feature to see all API endpoints you’ve accessed.

17. Mobile Certificate Pinning?
Before you start reverse engineering & patching the client app, check for both iOS & Android clients and older versions of them.
There's a decent chance that the pinning isn't enabled in one of them. Save time.

18. Companies & developers tend to put more resources (including security) into the main APIs.
Always look for the most niche features that nobody uses to find interesting vulnerabilities.
"POST /api/profile/upload_christmas_voice_greeting"

19. Which features do you find tend to be more vulnerable?
I'll start:
- Organization's user management
- Export to CSV/HTML/PDF
- Custom views of dashboards
- Sub user creation&management
- Object sharing (photos, posts,etc)

20. Testing AuthN APIs?
If you test in production, there's a good chance that AuthN endpoints have anti brute-force protection.
Anyhow, DevOps engineers tend to disable rate limiting in non-production environments. Don't forget to test them :)

21. Got stuck during an API pentest? Expand the attack surface!
Use http://archive.com, find old versions of the web-app and explore new API endpoints.
Can't use the client? scan the .js files for URLs. Some of them are API endpoints.

22. APIs tend to leak PII by design.
BE engineers return raw JSON objects and rely on FE engineers to filter out sensitive data.
Found a sensitive resource (e.g, "receipt")? Find all the EPs that return it: "/download_receipt","/export_receipt", etc..

23. Found a way to download arbitrary files from a web server?
Shift the test from black-box to white-box.
Download the source code of the app (DLL files: use IL-spy; Compiled Java - use Luyten)
Read the code and find new issues!

24. Remember: developers often disable security mechanisms in non-production environments (qa/staging/etc);
Leverage this fact to bypass AuthZ, AuthN, rate limiting & input validation.

25. Found an "export to PDF" feature?
There's a good chance the developers use an external library to convert HTML --> PDF behind the scenes.
Try to inject HTML elements and cause "Export Injection".

26. AuthZ bypass tricks:
* Wrap ID with an array {“id”:111} --> {“id”:[111]}
* JSON wrap {“id”:111} --> {“id”:{“id”:111}}
* Send ID twice URL?id=<LEGIT>&id=<VICTIM>
* Send wildcard {"user_id":"*"}

27. BE Servers no longer responsible for protecting against XSS.
APIs don't return HTML, but JSON instead.
If API returns XSS payload? -
E.g: {"name":"In<script>alert(21)</script>on}
That's fine! The protection always needs to be on the client side

28. Always try to send "INVALID CONTENT TYPE" you will end up getting hidden endpoints in "RESPONSE".

29. Found a GraphQL endpoint?
Send the following query to list the whole schema of the endpoint. It will list all objects and the fields they have.
{__schema{types{name,kind,description,fields{name,type{name}}}}}

PS: It doesn't work if introspection is disabled.

30. GiHub Dorks for Finding API Keys, Tokens and Passwords:  
- api_key
- "api keys"
- authorization_bearer:
- oauth
- auth
- authentication
- client_secret
- api_token:
- "api token"
- client_id
- password
- user_password
- user_pass
- passcode
- client_secret
- secret
- password hash
- OTP
- user auth
