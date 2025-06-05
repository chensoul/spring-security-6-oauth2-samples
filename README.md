![Build with Maven](https://github.com/chensoul/spring-security6-oauth2-samples/actions/workflows/build.yml/badge.svg)
![Code QL](https://github.com/chensoul/spring-security6-oauth2-samples/actions/workflows/codeql.yml/badge.svg)
[![License](https://img.shields.io/badge/License-Apache%20License%202.0-brightgreen.svg)][1]

# spring-security6-oauth2-samples

![video_spider](https://socialify.git.ci/chensoul/spring-security6-oauth2-samples/image?forks=1&issues=1&language=1&name=1&owner=1&stargazers=1&theme=Light)

基于 Spring Boot 3 + Spring Authorization Server 1.5.0 使用 Maven 构建的 Spring OAuth2 授权和认证服务示例。

## 要求

运行此服务器至少需要 Java 17 运行时，因为本项目使用了 Spring Boot 3.x。

关键技术:

- Spring Boot 3.5.0
- Spring Framework 6.2.7
- Spring Security 6.5.0
- Spring Security OAuth2 Authorization Server 1.5.0
- Spring Security OAuth2 Resource Server 1.5.0

## 使用

通过运行类 _com.chensoul.AuthServerApplication_ 启动授权服务器。

从 [http://localhost:9000/.well-known/openid-configuration](http://localhost:9000/.well-known/openid-configuration) 查找
OAuth2/OIDC 配置，以配置您的客户端和资源服务器。

以下是最重要的配置设置：

| Configuration Parameter | Value                                   | 
|-------------------------|-----------------------------------------|
| issuer                  | http://localhost:9000                   |
| authorization_endpoint  | http://localhost:9000/oauth2/authorize  |
| token_endpoint          | http://localhost:9000/oauth2/token      |
| jwks_uri                | http://localhost:9000/oauth2/jwks       |
| userinfo_endpoint       | http://localhost:9000/userinfo          |
| introspection_endpoint  | http://localhost:9000/oauth2/introspect |

## 使用 OpenSSL 生成非对称密钥

如果您选择生成自己的密钥，请按照以下步骤操作：

- 进入资源目录：
  ```bash
  cd src/main/resources
  ```

- 生成密钥对：
  此行使用 OpenSSL（openssl genrsa）生成长度为 2048 位的 RSA 私钥。
  然后指定将保存生成的私钥的输出文件（-out keypair.pem）。
  其意义在于创建一个可以用于非对称密码学中的加密、解密以及数字签名的私钥。
   ```bash
   openssl genrsa -out keypair.pem 2048   
   ```
- 从私钥生成公钥：
  此命令从先前生成的私钥（openssl rsa）中提取公钥。
  它从 -in keypair.pem 指定的文件中读取私钥，并将相应的公钥（-pubout）输出到名为 publicKey.pem 的文件中。
  其意义在于从私钥中获取公钥，公钥可以公开共享，用于加密和验证，同时保持私钥安全。
   ```bash
  openssl rsa -in keypair.pem -pubout -out publicKey.pem
   ```
- 将私钥（keypair.pem）格式化为支持的格式（PKCS8 格式）：
  此行将第一步生成的私钥（keypair.pem）转换为 PKCS#8 格式，这是私钥编码（openssl pkcs8）的广泛使用的标准。
  它指定输入密钥格式为 PEM（-inform PEM），输出密钥格式也为 PEM（-outform PEM），并且不应用加密（-nocrypt）。
  生成的私钥保存在名为 private.pem 的文件中。
  其意义在于将私钥转换为可在不同的加密系统和应用程序之间互操作的标准格式。
   ```bash
   openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out privateKey.pem
   ```
  **如果您想在使用 OpenSSL 导出私钥时对其进行加密，只需在 openssl pkcs8 命令中省略 -nocrypt 选项即可。这样，OpenSSL
  就会提示您输入用于加密私钥的密码**
  **注意：加密私钥会增加一层额外的安全性，但这也意味着无论何时您想使用私钥进行加密操作，您都需要提供密码。**

- 从配置文件中添加这些密钥的引用，以便在 RSAKeyRecord 中使用。
  ```java
  @ConfigurationProperties(prefix = "jwt")
  public record RSAKeyRecord (RSAPublicKey rsaPublicKey, RSAPrivateKey rsaPrivateKey){
  
  }
  ```
- 配置文件中添加以下内容。

```yaml
  jwt:
    rsa-private-key: classpath:certs/privateKey.pem
    rsa-public-key: classpath:certs/publicKey.pem
```

## 参考资料

- Spring Authorization Server 官方示例：https://github.com/spring-projects/spring-authorization-server/blob/main/samples
- Spring Security OAuth2 (Client、Resource Server)
  官方示例：https://github.com/spring-projects/spring-security-samples/tree/main/servlet/spring-boot/java/oauth2
- Spring Security and OAuth 2.0: Step-by-Step (Workshop)：https://github.com/chensoul/oauth2-workshop
- 多租户：https://github.com/chensoul/multitenant-spring-auth-server
- https://github.com/kanezi/spring-social-2-cloud/
- https://github.com/chensoul/SpringBootOAuth2/
- 各种授权类型的测试，包括 TOKEN_EXCHANGE：https://github.com/andifalk/custom-spring-authorization-server
- 多租户、TOKEN_EXCHANGE：https://github.com/andifalk/whats-new-in-spring-security/blob/main/spring-authorization-server/
- OAuth 2.0 Authorization Code Grant Flow：https://github.com/andifalk/federated-identity-demos
- https://github.com/andifalk/spring-security-bootcamp
- https://github.com/atquil/spring-security/tree/JWT-oauth2
- 基于 K8S 的 Authorization Server：https://github.com/Kehrlann/spring-authserver-k8s/
- 使用 dex 的 OAuth2 Client 示例：https://github.com/Kehrlann/spring-oauth2-client-sample
- 自定义密码授权类型：https://github.com/wdkeyser02/SpringAuthorizationServerCustomPasswordGrantType
- 集成网关，处理 CSRF 问题：https://github.com/wdkeyser02/SpringSecurityCloudGatewayAngularCSRFTutorial/tree/main
- 集成网关，大模型：https://github.com/joshlong/bootiful-spring-boot-2024
- jdbc + spring cloud gateway：https://github.com/ProductDock/spring-authorization-server-showcase
- 无密码登录，集成 webauthn、一次性密码：https://github.com/joshlong-attic/2024-11-06-jfall-nl/tree/main/theory/security
- MFA：https://github.com/wdkeyser02/SpringMfaAuthorizationServer
- OAuth2 client 使用 JDBC：https://github.com/thingsboard
- OAuth2 client 多种客户端：https://github.com/wdkeyser02/SpringBootSpringAuthorizationServer
- RestClient + 客户端验证：https://github.com/danvega/golf-scheduler
- JTE + TailwindCSS + GitHub + Google：https://github.com/danvega/spring-boot-oauth-demo

## 工具

- https://jwt.io/
- https://www.oauth.com/playground
- https://oidcdebugger.com/debug
- https://oauthdebugger.com/debug

## License

Apache 2.0 licensed

[1]:http://www.apache.org/licenses/LICENSE-2.0.txt