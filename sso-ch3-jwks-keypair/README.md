## 测试

### sso-ch4-auth

### 启动 sso-ch4-resource

```bash
export TOKEN=`curl -s -X POST clientCredClient:clientCredClient@localhost:9000/oauth2/token -d "grant_type=client_credentials" -d "scope=read" | jq -r .access_token`

echo $TOKEN

http GET localhost:8090 "Authorization: Bearer $TOKEN"
```
