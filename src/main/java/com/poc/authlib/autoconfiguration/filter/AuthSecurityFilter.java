package com.poc.authlib.autoconfiguration.filter;

import com.poc.authlib.autoconfiguration.AuthServiceClient;
import com.poc.authlib.properties.OpenUrlProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RequiredArgsConstructor
public final class AuthSecurityFilter extends OncePerRequestFilter {

    private final OpenUrlProperties openUrlProperties;
    private final AuthServiceClient authServiceClient;
    private final AntPathMatcher antPathMatcher;
    private final SecurityContextRepository securityContextRepository;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return openUrlProperties.getOpenUrls().stream()
                .anyMatch(u -> antPathMatcher.match(u, request.getRequestURI()));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
            try {
                authorize(request);
                filterChain.doFilter(request, response);
            } catch (Exception ex) {
                response.sendError(HttpStatus.UNAUTHORIZED.value(), ex.getMessage());
            }
    }

    private void authorize(HttpServletRequest request) {
        var authentication = authServiceClient.authorize(request);
        securityContextRepository.loadContext(request).get().setAuthentication(authentication);
    }
}
