# SpringBootOAuth2

This project is copied from https://github.com/wdkeyser02/SpringBootOAuth2.


Spring Authorization Server Endpoint:

- http://localhost:9000/.well-known/oauth-authorization-server
- http://localhost:9000/oauth2/jwks
- http://localhost:9000/oauth2/authorize
- http://localhost:9000/oauth2/device_authorization
- http://localhost:9000/oauth2/token


Tools:

- https://oauthdebugger.com/
- https://oidcdebugger.com/
- httpie
- insomnia


```bash
POST http://localhost:9000/oauth2/token
Content-Type: application/x-www-form-urlencoded
 
grant_type=authorization_code&
code=WRAJShB3Jv3kJhhuX3GFhGa9riyMccxYF3xDrvMZVfFidtnMuLZv59xe4bbELBmXxYN5O-clOHCUDtLXrMzkVs4ys0bx7T52xF71S-9iSbiH3-bHMtsciIqoQ0k_slrK&
client_id=client&
client_secret={clientSecret}&
redirect_uri=https%3A%2F%2Foauthdebugger.com%2Fdebug
```