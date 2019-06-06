package com.training.mjunction.zuulgateway;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateCustomizer;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.client.loadbalancer.LoadBalancerInterceptor;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import brave.sampler.Sampler;

@EnableZuulProxy
@EnableDiscoveryClient
@SpringBootApplication
@EnableAutoConfiguration
public class Application extends SpringBootServletInitializer {

	@Override
	protected SpringApplicationBuilder configure(final SpringApplicationBuilder application) {
		return application.sources(Application.class);
	}

	public static void main(final String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Bean
	public Sampler defaultSampler() {
		return Sampler.ALWAYS_SAMPLE;
	}

	@Bean
	public UserInfoRestTemplateCustomizer userInfoRestTemplateCustomizer(
			final LoadBalancerInterceptor loadBalancerInterceptor) {
		return template -> {
			final List<ClientHttpRequestInterceptor> interceptors = new ArrayList<>();
			interceptors.add(loadBalancerInterceptor);
			final AccessTokenProviderChain accessTokenProviderChain = Stream
					.of(new AuthorizationCodeAccessTokenProvider(), new ImplicitAccessTokenProvider(),
							new ResourceOwnerPasswordAccessTokenProvider(), new ClientCredentialsAccessTokenProvider())
					.peek(tp -> tp.setInterceptors(interceptors))
					.collect(Collectors.collectingAndThen(Collectors.toList(), AccessTokenProviderChain::new));
			template.setAccessTokenProvider(accessTokenProviderChain);
		};
	}

	@Component
	@EnableOAuth2Sso
	@EnableResourceServer
	@Order(value = 0)
	protected static class UiApplicationConfig extends WebSecurityConfigurerAdapter {

		private static final String CSRF_COOKIE_NAME = "XSRF-TOKEN";
		private static final String CSRF_HEADER_NAME = "X-XSRF-TOKEN";

		@Autowired
		private ResourceServerTokenServices resourceServerTokenServices;

		@Bean
		@Primary
		public OAuth2ClientContextFilter dynamicOauth2ClientContextFilter() {
			return new DynamicOauth2ClientContextFilter();
		}

		@Override
		public void configure(final HttpSecurity http) throws Exception {
			http.httpBasic().disable().logout().and().antMatcher("/**").authorizeRequests()
					.antMatchers("/auth/**", "/login").permitAll()
					.antMatchers("/index.html", "/home.html", "/testing.html", "/", "/login").permitAll().anyRequest()
					.authenticated().and().csrf().csrfTokenRepository(csrfTokenRepository()).and()
					.addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
					.addFilterAfter(oAuth2AuthenticationProcessingFilter(),
							AbstractPreAuthenticatedProcessingFilter.class)
					.logout().permitAll().logoutSuccessUrl("/");
		}

		@Override
		public void configure(final WebSecurity web) throws Exception {
			web.ignoring().antMatchers("/hystrix.stream", "/actuator/**", "/js/**", "/css/**", "/*.html", "/*.htm",
					"/*.jsp", "/swagger-ui.html", "/v2/api-docs");
		}

		private OAuth2AuthenticationProcessingFilter oAuth2AuthenticationProcessingFilter() {
			final OAuth2AuthenticationProcessingFilter oAuth2AuthenticationProcessingFilter = new OAuth2AuthenticationProcessingFilter();
			oAuth2AuthenticationProcessingFilter.setAuthenticationManager(oauthAuthenticationManager());
			oAuth2AuthenticationProcessingFilter.setStateless(false);
			return oAuth2AuthenticationProcessingFilter;
		}

		private AuthenticationManager oauthAuthenticationManager() {
			final OAuth2AuthenticationManager oAuth2AuthenticationManager = new OAuth2AuthenticationManager();
			oAuth2AuthenticationManager.setResourceId("apigateway");
			oAuth2AuthenticationManager.setTokenServices(resourceServerTokenServices);
			oAuth2AuthenticationManager.setClientDetailsService(null);
			return oAuth2AuthenticationManager;
		}

		private static Filter csrfHeaderFilter() {
			return new OncePerRequestFilter() {
				@Override
				protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
						final FilterChain filterChain) throws ServletException, IOException {
					final CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
					if (csrf != null) {
						final Cookie cookie = new Cookie(CSRF_COOKIE_NAME, csrf.getToken());
						cookie.setPath("/");
						cookie.setSecure(true);
						response.addCookie(cookie);
					}
					filterChain.doFilter(request, response);
				}
			};
		}

		private static CsrfTokenRepository csrfTokenRepository() {
			final HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
			repository.setHeaderName(CSRF_HEADER_NAME);
			return repository;
		}

		private static final class DynamicOauth2ClientContextFilter extends OAuth2ClientContextFilter {

			private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

			@Override
			protected void redirectUser(final UserRedirectRequiredException e, final HttpServletRequest request,
					final HttpServletResponse response) throws IOException {

				final String redirectUri = e.getRedirectUri();
				final UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectUri);
				final Map<String, String> requestParams = e.getRequestParams();
				for (final Map.Entry<String, String> param : requestParams.entrySet()) {
					builder.queryParam(param.getKey(), param.getValue());
				}

				if (e.getStateKey() != null) {
					builder.queryParam("state", e.getStateKey());
				}

				final String url = getBaseUrl(request) + builder.build().encode().toUriString();
				redirectStrategy.sendRedirect(request, response, url);
			}

			@Override
			public void setRedirectStrategy(final RedirectStrategy redirectStrategy) {
				this.redirectStrategy = redirectStrategy;
			}

			private String getBaseUrl(final HttpServletRequest request) {
				final StringBuffer url = request.getRequestURL();
				return url.substring(0,
						url.length() - request.getRequestURI().length() + request.getContextPath().length());
			}
		}
	}

}
