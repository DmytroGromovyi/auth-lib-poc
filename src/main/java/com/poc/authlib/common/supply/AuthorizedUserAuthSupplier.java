package com.poc.authlib.common.supply;

import com.poc.authlib.common.dto.AuthSystemUserDTO;
import com.poc.authlib.common.exception.AuthSystemException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

public final class AuthorizedUserAuthSupplier implements AuthorizedUserSupplier {

    @Override
    public AuthSystemUserDTO get() {
        return Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication())
                .map(Authentication::getPrincipal)
                .map(AuthSystemUserDTO.class::cast)
                .orElseThrow(() -> new AuthSystemException("Unexpected authority in security context"));
    }
}
