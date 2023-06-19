package com.poc.authlib;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.poc.authlib.autoconfiguration.AuthServiceClient;
import com.poc.authlib.autoconfiguration.condition.NotSecuredCondition;
import com.poc.authlib.autoconfiguration.condition.SecuredCondition;
import com.poc.authlib.autoconfiguration.filter.AuthEntryPoint;
import com.poc.authlib.autoconfiguration.filter.AuthSecurityFilter;
import com.poc.authlib.common.enums.Role;
import com.poc.authlib.common.exception.AuthSystemException;
import com.poc.authlib.common.supply.AuthorizedUserAuthSupplier;
import com.poc.authlib.common.supply.AuthorizedUserSupplier;
import com.poc.authlib.properties.ApiPermissionProperties;
import com.poc.authlib.properties.AuthServiceProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.springframework.boot.autoconfigure.AutoConfigureOrder;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnSingleCandidate;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

@Slf4j
@Configuration
@EnableWebSecurity
@AutoConfigureOrder(Ordered.HIGHEST_PRECEDENCE + 10)
@ConditionalOnClass({WebClient.class, ObjectMapper.class, Logger.class})
@ImportAutoConfiguration(AuthExceptionHandlerConfiguration.class)
@RequiredArgsConstructor
public class AuthSystemAutoconfiguration {

	@Bean
	@ConditionalOnMissingBean
	@Conditional(NotSecuredCondition.class)
	AuthorizedUserSupplier authorizedUserSupplier() {
		return new AuthorizedUserSupplier() {
			//default implementation of AuthorizedUserSupplier interface
		};
	}


	@Configuration
	@EnableConfigurationProperties({AuthServiceProperties.class, ApiPermissionProperties.class})
	@Conditional(SecuredCondition.class)
	class AuthSystemSecurityConfig {

		@Bean
		AuthorizedUserSupplier authorizedUserSupplier() {
			return new AuthorizedUserAuthSupplier();
		}

		@Bean
		@Primary
		AuthEntryPoint authEntryPoint(AuthServiceProperties authServiceProperties) {
			return new AuthEntryPoint(authServiceProperties);
		}

		@Bean
		@Primary
		AuthSecurityFilter securityCheckFilter(ApiPermissionProperties apiPermissionProperties,
											   AuthServiceClient buildAuthServiceClient) {
			var antPathMatcher = new AntPathMatcher();
			antPathMatcher.setCaseSensitive(false);
			return new AuthSecurityFilter(apiPermissionProperties, buildAuthServiceClient, antPathMatcher);
		}

		@Bean
		@Primary
		AuthServiceClient buildAuthSystemClient(AuthServiceProperties authServiceProperties,
												WebClient permissionServiceWebClient) {
			return new AuthServiceClient(authServiceProperties, permissionServiceWebClient);
		}

		@Bean
		@Primary
		WebClient permissionServiceWebClient(AuthServiceProperties authServiceProperties) {
			var httpClient = new ReactorClientHttpConnector(HttpClient.create()
					.responseTimeout(Duration.ofMillis(authServiceProperties.getTimeout())));

			return WebClient.builder()
					.clientConnector(httpClient)
					.baseUrl(authServiceProperties.getEndpoint())
					.build();
		}
	}

	@Configuration
	@Order(Ordered.HIGHEST_PRECEDENCE)
	@RequiredArgsConstructor
	class AuthSystemWebSecurityConfig extends WebSecurityConfigurerAdapter {

		private final AuthEntryPoint authEntryPoint;
		private final AuthSecurityFilter authSecurityFilter;
		private final ApiPermissionProperties apiPermissionProperties;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			var whitelistedEndpoints = apiPermissionProperties.getWhitelistedEndpoints().toArray(String[]::new);

			var security = http.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
					.and()
					.exceptionHandling().authenticationEntryPoint(authEntryPoint)
					.and()
					.addFilterBefore(authSecurityFilter, BasicAuthenticationFilter.class)
					.csrf().disable()
					.cors().disable()
					.formLogin().disable()
					.httpBasic().disable();

			//customizable api access rules
			applyCustomAccessRules(security);
			//common access rules

			security
					.authorizeRequests().antMatchers(whitelistedEndpoints)
					.permitAll()
					.and()
					.authorizeRequests().anyRequest()
					.authenticated();
		}

		private void applyCustomAccessRules(HttpSecurity security) {
			var permissionMapByPath = convertKeyUrl();
			permissionMapByPath.forEach((url, roles) -> grantEndpointsAccess(security, url, roles));
		}

		private void grantEndpointsAccess(HttpSecurity security, String path, List<Role> roles) {
			var roleNames = roles.stream().map(Role::getRoleName).toArray(String[]::new);
			var roleNamesString = String.join(", ", roleNames);
			try {
				security.authorizeRequests()
						.antMatchers(path)
						.hasAnyRole(roleNames)
						.and();
				log.info("Applied custom endpoint access rule: [url: {}, roles: {}]", path, roleNamesString);
			} catch (Exception ex) {
				log.error("Can't apply permissions: [{}: {}]", path, roleNamesString);
				throw new AuthSystemException("Can't apply permissions for path: " + path + ", roles: "
						+ roleNamesString);
			}
		}

		private Map<String, List<Role>> convertKeyUrl() {

			var permissionMapByPath = new TreeMap<String, List<Role>>();

			apiPermissionProperties.getPermissionMap()
					.forEach((key, value) -> value
							.forEach(url -> {
								List<Role> roles = permissionMapByPath.getOrDefault(url, new ArrayList<>());
								roles.add(key);
								permissionMapByPath.put(url, roles);
							}));

			return permissionMapByPath;
		}
	}

	@Configuration
	@Conditional(NotSecuredCondition.class)
	@ConditionalOnSingleCandidate(WebSecurityConfigurerAdapter.class)
	@RequiredArgsConstructor
	class NotSecuredWebSecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
					.and()
					.csrf().disable()
					.cors().disable()
					.formLogin().disable()
					.httpBasic().disable()
					.authorizeRequests().antMatchers("/**").permitAll();
		}
	}

}
