## Relevant Information:

### Client Credentials Grant

```bash
curl -s -X POST -u "client:secret" -d "grant_type=client_credentials&scope=message.read" http://localhost:8080/oauth2/token | jq


curl -s http://127.0.0.1:8080/oauth2/jwks | jq
```