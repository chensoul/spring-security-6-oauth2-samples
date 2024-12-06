![video_spider](https://socialify.git.ci/chensoul/spring-security-6-oauth2-samples/image?forks=1&issues=1&language=1&name=1&owner=1&stargazers=1&theme=Light)

# <font size="6p">spring-security-6-oauth2-samples</font> <font size="5p">  | [English Documentation](README.md)</font>

<p align="left">
	<a href="https://github.com/chensoul/spring-security-6-oauth2-samples/stargazers"><img src="https://img.shields.io/github/stars/chensoul/spring-security-6-oauth2-samples?style=flat-square&logo=GitHub"></a>
	<a href="https://github.com/chensoul/spring-security-6-oauth2-samples/network/members"><img src="https://img.shields.io/github/forks/chensoul/spring-security-6-oauth2-samples?style=flat-square&logo=GitHub"></a>
	<a href="https://github.com/chensoul/spring-security-6-oauth2-samples/watchers"><img src="https://img.shields.io/github/watchers/chensoul/spring-security-6-oauth2-samples?style=flat-square&logo=GitHub"></a>
	<a href="https://github.com/chensoul/spring-security-6-oauth2-samples/issues"><img src="https://img.shields.io/github/issues/chensoul/spring-security-6-oauth2-samples.svg?style=flat-square&logo=GitHub"></a>
	<a href="https://github.com/chensoul/spring-security-6-oauth2-samples/blob/main/LICENSE"><img src="https://img.shields.io/github/license/chensoul/spring-security-6-oauth2-samples.svg?style=flat-square"></a>
</p>

这个项目是一个 [Spring Authorization Server](https://spring.io/projects/spring-authorization-server) 示例教程的集合，基于
Spring Security 6，使用 Maven 构建。

> 💡注意：喜欢的话别忘了给项目一个star🌟哦！

## 构建项目

JDK 版本 21+。

```bash
./mvnw clean install -Dmaven.test.skip=true
```

## 笔记

### JWT

名称解释：

- JWT：JSON Web Token。包括 header、payload、signature 三部分。
- JWS：Signed JWT，签名过的 JWT。其结构就是在之前 nonsecure JWT 的基础上，在头部声明签名算法，并在最后添加上签名。创建签名，是保证
  JWT 不能被他人随意篡改。签名算法分为对称和非对称，签名的密钥或者密钥对称为 JWK。
- JWK：JWT 的密钥
- JWE：Encrypted JWT，payload 部分经过加密的 JWT。JWE 有五个部分，分别是 header、encrypted key、initialization
  vector、ciphertext、authentication tag。

区别：

1. JWS是去验证数据的，而JWE是保护数据不被第三方的人看到的。通过JWE，JWT变得更加安全。
2. JWE和JWS的公钥私钥方案不相同，JWS中，私钥持有者加密令牌，公钥持有者验证令牌。而JWE中，私钥一方应该是唯一可以解密令牌的一方。
3. 在JWE中，公钥持有可以将新的数据放入JWT中，但是JWS中，公钥持有者只能验证数据，不能引入新的数据。因此，对于公钥/私钥的方案而言，JWS和JWE是互补的。

## 参考

- https://github.com/chensoul/SpringBootOAuth2
- https://github.com/spring-projects/spring-security-samples/tree/main/servlet/spring-boot/java/oauth2
- https://github.com/sjohnr/oauth2-workshop
- https://github.com/jgrandja/multitenant-spring-auth-server
- https://github.com/wdkeyser02/SpringAuthorizationServerCustomPasswordGrantType
- 
- https://www.youtube.com/watch?v=Yh8t04NG_K4
- https://www.youtube.com/watch?v=p3aLjH2VPzU
- https://www.youtube.com/watch?v=GVsKQ4dp_pQ
- https://github.com/eazybytes/springsecurity6
- https://github.com/spring-tips/spring-security-5-oauth-client
- https://github.com/spring-tips/spring-authorization-server-book
- https://github.com/spring-tips/spring-authorization-server
- https://github.com/atquil/spring-security/tree/JWT-oauth2
- https://github.com/joshlong-attic/2024-11-06-jfall-nl/
- https://github.com/spring-projects/spring-authorization-server/tree/main/samples
- https://github.com/spring-tips/spring-authorization-server-book/
- https://github.com/joshlong/bootiful-spring-boot-2024
- https://github.com/danvega/golf-scheduler RestClient + 客户端验证
- https://github.com/wdkeyser02/SpringBootSpringAuthorizationServer
- https://github.com/wdkeyser02/SpringSecurityCloudGatewayAngularCSRFTutorial
- https://github.com/wdkeyser02/SpringBootSpringAuthorizationServer/
- https://github.com/wdkeyser02/SpringMfaAuthorizationServer
- https://github.com/wdkeyser02/SpringAuthorizationServerCustomPasswordGrantType
- https://github.com/danvega/spring-boot-oauth-demo JTE + TailwindCSS + GitHub + Google
- https://github.com/rwinch/spring-enterprise-authorization-server
- https://github.com/nguyenquangos0302git/learn-spring-security/
- https://github.com/lorchr/light-docusaurus/tree/616a7e7e2098bd6ec8a6fd0f59ee7502ae5dd394/docs/zh-cn/spring-authorization-server
- https://github.com/ProductDock/spring-authorization-server-showcase jdbc + spring cloud gateway

## 工具

- https://www.oauth.com/playground
- https://jwt.io/
- https://oidcdebugger.com/debug
- https://oauthdebugger.com/debug

