package com.poc.authlib.common.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.FORBIDDEN)
@RequiredArgsConstructor
public class ForbiddenException extends RuntimeException {
    @Getter
    private final String message;
}
