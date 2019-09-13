package com.fitcrew.FitCrewAppZuulApiGateway.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Objects;

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

	private final Environment environment;

	AuthorizationFilter(AuthenticationManager authenticationManager,
						Environment environment) {
		super(authenticationManager);
		this.environment = environment;
	}

	protected void doFilterInternal(HttpServletRequest request,
									HttpServletResponse response,
									FilterChain chain) throws IOException, ServletException {

		String authorizationHeader = getAuthorizationTokenHeader(request);

		if (authorizationHeader == null ||
				!authorizationHeader.startsWith(
						Objects.requireNonNull(
								environment.getProperty("authorization.token.header.prefix")
						)
				)
		) {
			chain.doFilter(request, response);
			return;
		}

		SecurityContextHolder
				.getContext()
				.setAuthentication(getAuthentication(request));

		chain.doFilter(request, response);

	}

	private String getAuthorizationTokenHeader(HttpServletRequest request) {
		return request.getHeader(environment.getProperty("authorization.token.header.name"));
	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {

		String authorizationHeader = getAuthorizationTokenHeader(request);

		if (authorizationHeader == null) {
			return null;
		}

		String tokenWithoutPrefix = authorizationHeader.replace(
				Objects.requireNonNull(environment.getProperty("authorization.token.header.prefix")),
				""
		);

		String userId = Jwts.parser()
				.setSigningKey(environment.getProperty("token.secret"))
				.parseClaimsJws(tokenWithoutPrefix)
				.getBody()
				.getSubject();

		if (userId == null) {
			return null;
		}

		return new UsernamePasswordAuthenticationToken(userId, null, new ArrayList<>());
	}

}
