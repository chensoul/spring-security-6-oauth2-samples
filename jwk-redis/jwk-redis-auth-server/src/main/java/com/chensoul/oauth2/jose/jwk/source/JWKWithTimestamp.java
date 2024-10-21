package com.chensoul.oauth2.jose.jwk.source;

import com.nimbusds.jose.jwk.JWK;
import java.util.Date;


public final class JWKWithTimestamp {
    public final JWK jwk;
    private final Date timestamp;

    public JWKWithTimestamp(JWK jwk) {
        this(jwk, new Date());
    }

    public JWKWithTimestamp(JWK jwk, Date timestamp) {
        if (jwk == null) {
            throw new IllegalArgumentException("The JWK must not be null");
        } else {
            this.jwk = jwk;
            if (timestamp == null) {
                throw new IllegalArgumentException("The timestamp must not null");
            } else {
                this.timestamp = timestamp;
            }
        }
    }

    public JWK getJwk() {
        return jwk;
    }

    public Date getDate() {
        return timestamp;
    }
}
