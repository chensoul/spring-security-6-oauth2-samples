## 测试授权服务器

启动 authorization-server-01-start

### 客户端授权

```bash
export RESPONSE=`curl -s -X POST credentials-client:credentials-client@localhost:9000/oauth2/token -d "grant_type=client_credentials" -d "scope=read" | jq -r .`
echo $RESPONSE
echo $RESPONSE | jq -r .access_token
```



