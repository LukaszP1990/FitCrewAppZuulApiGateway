package com.fitcrew.FitCrewAppZuulApiGateway.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {
	private final Environment environment;

	public WebSecurity(Environment environment) {
		this.environment = environment;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.csrf()
				.disable();

		http
				.headers()
				.frameOptions()
				.disable();
		http
				.authorizeRequests()
				.antMatchers(environment.getProperty("api.client.h2console.url.path")).permitAll()
				.antMatchers(HttpMethod.POST, environment.getProperty("api.client.registration.url.path")).permitAll()
				.antMatchers(HttpMethod.POST, environment.getProperty("api.client.login.url.path")).permitAll()
				.antMatchers(environment.getProperty("api.trainer.h2console.url.path")).permitAll()
				.antMatchers(HttpMethod.POST, environment.getProperty("api.trainer.registration.url.path")).permitAll()
				.antMatchers(HttpMethod.POST, environment.getProperty("api.trainer.login.url.path")).permitAll()
				.antMatchers( environment.getProperty("api.admin.h2console.url.path")).permitAll()
				.antMatchers(HttpMethod.POST, environment.getProperty("api.admin.registration.url.path")).permitAll()
				.antMatchers(HttpMethod.POST, environment.getProperty("api.admin.login.url.path")).permitAll()
				.antMatchers(environment.getProperty("api.training.h2console.url.path")).permitAll()
				.anyRequest().authenticated()
				.and()
				.addFilter(new AuthorizationFilter(authenticationManager(), environment));

		http
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS);

	}
}
