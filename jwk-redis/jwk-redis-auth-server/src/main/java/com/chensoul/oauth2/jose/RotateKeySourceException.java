package com.chensoul.oauth2.jose;

import com.nimbusds.jose.KeySourceException;


public class RotateKeySourceException extends KeySourceException {
    public RotateKeySourceException(String message, Throwable cause) {
        super(message, cause);
    }

}
