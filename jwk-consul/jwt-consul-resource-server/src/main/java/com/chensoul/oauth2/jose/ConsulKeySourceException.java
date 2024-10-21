package com.chensoul.oauth2.jose;

import com.nimbusds.jose.KeySourceException;


public class ConsulKeySourceException extends KeySourceException {


    public ConsulKeySourceException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
