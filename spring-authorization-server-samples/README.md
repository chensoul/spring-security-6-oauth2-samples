## 测试

### 启动授权服务器

启动 ch1-auth-min 或者 ch1-auth-default

### 启动资源服务器

1. 启动 ch1-resource-jwt 并测试

```bash
export TOKEN=`curl -s -X POST credentialsClient:credentialsClient@localhost:9000/oauth2/token -d "grant_type=client_credentials" -d "scope=read" | jq -r .access_token`

echo $TOKEN

http GET localhost:8090 "Authorization: Bearer $TOKEN"
```

2. 启动 ch1-resource-opaque 并测试

```bash
export TOKEN=`curl -s -X POST introspectClient:introspectClient@localhost:9000/oauth2/token -d "grant_type=client_credentials" -d "scope=openid" | jq -r .access_token`

echo $TOKEN

http GET localhost:8091 "Authorization: Bearer $TOKEN"
```

3. 启动 ch1-resource-multi-tenant 

测试 tenantOne

```bash
export TOKEN=`curl -s -X POST credentialsClient:credentialsClient@localhost:9000/oauth2/token -d "grant_type=client_credentials" -d "scope=read" | jq -r .access_token`

echo $TOKEN

http GET localhost:8092/tenantOne/message "Authorization: Bearer $TOKEN"

http GET localhost:8092/tenantOne "Authorization: Bearer $TOKEN"

```

测试 tenantTwo

```bash
export TOKEN=`curl -s -X POST introspectClient:introspectClient@localhost:9000/oauth2/token -d "grant_type=client_credentials" -d "scope=read" | jq -r .access_token`

echo $TOKEN

http GET localhost:8092/tenantTwo/message "Authorization: Bearer $TOKEN"

http GET localhost:8092/tenantTwo "Authorization: Bearer $TOKEN"

```

