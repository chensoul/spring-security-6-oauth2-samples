# Spring Tips: the Spring Authorization Server: durability of data

This repository contains the code that
accompanies [Spring Tips: the Spring Authorization Server: durability of data](https://www.youtube.com/watch?v=GVsKQ4dp_pQ).

## RSA

Generate a new keystore for the authorization server:

```bash
keytool -genkeypair -alias jwk -storetype PKCS12 -keyalg RSA -keypass secret -keystore jwk.jks -storepass secret \
 -dname "CN=Spring Authorization Server,OU=Spring,O=Pivotal,L=San Francisco,ST=CA,C=US" -validity 3650
```

Export public key from the keystore:

```bash
keytool -list -rfc --keystore jwk.jks -storepass secret | openssl x509 -inform pem -pubkey > app.pub
```

Export private key from the keystore:

```bash
keytool -importkeystore -srckeystore jwk.jks -srcstorepass secret -destkeystore jwk.p12 -srcstoretype jks -deststoretype pkcs12 -deststorepass secret -destkeypass secret

openssl pkcs12 -in jwk.p12 -nodes -nocerts -out app.key
```

