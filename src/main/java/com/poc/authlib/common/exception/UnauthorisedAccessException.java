package com.poc.authlib.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class UnauthorisedAccessException extends AuthenticationException {

    public UnauthorisedAccessException(String message) {
        super(message);
    }

}
