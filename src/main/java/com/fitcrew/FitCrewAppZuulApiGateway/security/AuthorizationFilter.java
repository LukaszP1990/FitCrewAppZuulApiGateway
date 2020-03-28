package com.fitcrew.FitCrewAppZuulApiGateway.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Objects;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Jwts;

public class AuthorizationFilter extends BasicAuthenticationFilter {

    private static String TOKEN_HEADER_PREFIX = "authorization.token.header.prefix";
    private static String TOKEN_HEADER_NAME = "authorization.token.header.name";
    private static String TOKEN_SECRET = "token.secret";
    private final Environment environment;

    AuthorizationFilter(AuthenticationManager authenticationManager,
                        Environment environment) {
        super(authenticationManager);
        this.environment = environment;
    }

    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {

        if (isAuthorizationHeader(getAuthorizationTokenHeader(request))) {
            chain.doFilter(request, response);
            return;
        }
        getAuthentication(request, response, chain);
    }

    private void getAuthentication(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain chain) throws IOException, ServletException {
        SecurityContextHolder
                .getContext()
                .setAuthentication(setAuthentication(request));

        chain.doFilter(request, response);
    }

    private boolean isAuthorizationHeader(String authorizationHeader) {
        return Objects.isNull(authorizationHeader) ||
                !authorizationHeader.startsWith(
                        Objects.requireNonNull(environment.getProperty(TOKEN_HEADER_PREFIX))
                );
    }

    private String getAuthorizationTokenHeader(HttpServletRequest request) {
        return request.getHeader(environment.getProperty(TOKEN_HEADER_NAME));
    }

    private UsernamePasswordAuthenticationToken setAuthentication(HttpServletRequest request) {

       return Optional.ofNullable(getAuthorizationTokenHeader(request))
                .filter(authorizationTokenHeader ->
                        Objects.nonNull(getUserId(authorizationTokenHeader)))
                .map(this::getUserId)
                .map(userId -> new UsernamePasswordAuthenticationToken(userId, null, new ArrayList<>()))
                .orElse(null);
    }

    private String getUserId(String authorizationHeader) {
        return Jwts.parser()
                .setSigningKey(environment.getProperty(TOKEN_SECRET))
                .parseClaimsJws(getTokenWithoutPrefix(authorizationHeader))
                .getBody()
                .getSubject();
    }

    private String getTokenWithoutPrefix(String authorizationHeader) {
		return authorizationHeader.replace(
				Objects.requireNonNull(environment.getProperty(TOKEN_HEADER_PREFIX)),
				""
		);
	}
}
