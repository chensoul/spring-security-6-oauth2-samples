# SpringBootOAuth2

This project is copied from https://github.com/wdkeyser02/SpringBootOAuth2.

Spring Authorization Server Endpoint:

- http://localhost:9000/.well-known/oauth-authorization-server
- http://localhost:9000/oauth2/jwks
- http://localhost:9000/oauth2/authorize
- http://localhost:9000/oauth2/device_authorization
- http://localhost:9000/oauth2/token
- http://localhost:9000/oauth2/authorize

## 异常

- authorization_request_not_found：由 OAuth2LoginAuthenticationFilter 抛出异常，原因是客户端和授权服务器之间 cookie
  被覆盖，需要将客户端配置中 issuer-uri 修改为域名。