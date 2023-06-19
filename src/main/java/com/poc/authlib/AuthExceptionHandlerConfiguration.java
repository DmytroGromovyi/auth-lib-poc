package com.poc.authlib;

import com.poc.authlib.common.dto.GenericErrorResponse;
import com.poc.authlib.common.exception.ForbiddenException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@Configuration
class AuthExceptionHandlerConfiguration {

    @Primary
    @RestControllerAdvice(annotations = {RestController.class, Controller.class})
    //@Conditional(SecuredCondition.class)
    class AuthExceptionHandler {

        @ResponseStatus(HttpStatus.UNAUTHORIZED)
        @ExceptionHandler(AuthenticationException.class)
        public GenericErrorResponse handleUnauthorisedAccessException(
                AuthenticationException exception) {
            return buildEntityResponseAndLogError(exception);
        }

        @ResponseStatus(HttpStatus.FORBIDDEN)
        @ExceptionHandler(ForbiddenException.class)
        public GenericErrorResponse handleForbiddenException(ForbiddenException exception) {
            return buildEntityResponseAndLogError(exception);
        }

        private GenericErrorResponse buildEntityResponseAndLogError(Exception exception) {
            var errorResponse = GenericErrorResponse.builder()
                    .errorMessage(exception.getMessage())
                    .build();
            return errorResponse;
        }
    }
}
