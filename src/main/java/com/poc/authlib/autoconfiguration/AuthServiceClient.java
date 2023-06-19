package com.poc.authlib.autoconfiguration;

import com.poc.authlib.common.dto.AuthSystemUserDTO;
import com.poc.authlib.common.exception.AuthSystemException;
import com.poc.authlib.common.exception.UnauthorisedAccessException;
import com.poc.authlib.properties.AuthServiceProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.servlet.http.HttpServletRequest;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.web.reactive.function.client.WebClientResponseException.BadRequest;
import static org.springframework.web.reactive.function.client.WebClientResponseException.Forbidden;
import static org.springframework.web.reactive.function.client.WebClientResponseException.Unauthorized;


@Slf4j
@RequiredArgsConstructor
public class AuthServiceClient {

    private final AuthServiceProperties authServiceProperties;
    private final WebClient securityServiceWebClient;

    public Authentication authorize(HttpServletRequest request) {
        var authToken = getAuthToken(request);
        var authSystemUserDto = callPermissionService(authToken);
        log.debug("User found: {}", authSystemUserDto);
        return buildAuth(authSystemUserDto);
    }

    private String getAuthToken(HttpServletRequest request) {
        return Optional.of(request)
                .map(req -> req.getHeader(AUTHORIZATION))
                .orElseThrow(() -> new UnauthorisedAccessException("No security token is present in request"));
    }

    private AuthSystemUserDTO callPermissionService(String authToken) {
        try {
            var authSystemUserDto = doCall(authToken);
            Objects.requireNonNull(authSystemUserDto, "Unexpected permission service response");
            return authSystemUserDto;
        } catch (BadRequest | Unauthorized | Forbidden e) {
            var details = e.getMessage();
            log.warn("Authorisation error in permission service response, message: {}", details, e);
            throw new UnauthorisedAccessException("Authorisation error from permission service: " + details);
        } catch (Exception e) {
            var details = e.getMessage();
            log.error("Error in permission service response, message: {}", details, e);
            throw new AuthSystemException("Cannot get response from permission service: " + details);
        }
    }

    private AuthSystemUserDTO doCall(String authToken) {
        return securityServiceWebClient.get()
                .uri(authServiceProperties.getGetUserPath())
                .header(AUTHORIZATION, authToken)
                .retrieve()
                .bodyToMono(AuthSystemUserDTO.class)
                .block();
    }

    private Authentication buildAuth(AuthSystemUserDTO currentUser) {
        return new UsernamePasswordAuthenticationToken(currentUser, null,
                toAuthorities(currentUser.getPermissions()));
    }

    private Set<GrantedAuthority> toAuthorities(String[] roles) {
        return Stream.of(roles)
                .map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toUnmodifiableSet());
    }
}

