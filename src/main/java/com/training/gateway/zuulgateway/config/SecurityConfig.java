package com.training.gateway.zuulgateway.config;

import java.io.IOException;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

@Configuration
@EnableOAuth2Sso
@EnableResourceServer
@Order(value = 0)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private static final String CSRF_COOKIE_NAME = "XSRF-TOKEN";
	private static final String CSRF_HEADER_NAME = "X-XSRF-TOKEN";

	@Autowired
	private ResourceServerTokenServices resourceServerTokenServices;

	/*
	 * @Bean
	 *
	 * @Primary public OAuth2ClientContextFilter dynamicOauth2ClientContextFilter()
	 * { return new DynamicOauth2ClientContextFilter(); }
	 *
	 * @Bean public UserInfoRestTemplateCustomizer userInfoRestTemplateCustomizer(
	 * final LoadBalancerInterceptor loadBalancerInterceptor) {
	 *
	 * return template -> {
	 *
	 * final List<ClientHttpRequestInterceptor> interceptors = new ArrayList<>();
	 * interceptors.add(loadBalancerInterceptor);
	 *
	 * final AccessTokenProviderChain accessTokenProviderChain = Stream .of(new
	 * AuthorizationCodeAccessTokenProvider(), new ImplicitAccessTokenProvider(),
	 * new ResourceOwnerPasswordAccessTokenProvider(), new
	 * ClientCredentialsAccessTokenProvider()) .peek(tp ->
	 * tp.setInterceptors(interceptors))
	 * .collect(Collectors.collectingAndThen(Collectors.toList(),
	 * AccessTokenProviderChain::new));
	 *
	 * template.setAccessTokenProvider(accessTokenProviderChain);
	 *
	 * };
	 *
	 * }
	 */
	@Override
	public void configure(final HttpSecurity http) throws Exception {

		http.authorizeRequests().antMatchers("/uaa/**", "/login", "/index.html", "/home.html", "/testing.html")
				.permitAll().anyRequest().authenticated().and().csrf()
				.requireCsrfProtectionMatcher(csrfRequestMatcher()).csrfTokenRepository(csrfTokenRepository()).and()
				.addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
				.addFilterAfter(oAuth2AuthenticationProcessingFilter(), AbstractPreAuthenticatedProcessingFilter.class)
				.logout().permitAll().logoutSuccessUrl("/").and().httpBasic().disable();
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

	private RequestMatcher csrfRequestMatcher() {

		return new RequestMatcher() {

			// Always allow the HTTP GET method
			private final Pattern allowedMethods = Pattern.compile("^(GET|HEAD|OPTIONS|TRACE)$");

			// Disable CSFR protection on the following urls:
			private final AntPathRequestMatcher[] requestMatchers = { new AntPathRequestMatcher("/uaa/**") };

			@Override
			public boolean matches(final HttpServletRequest request) {
				if (allowedMethods.matcher(request.getMethod()).matches()) {
					return false;
				}

				for (final AntPathRequestMatcher matcher : requestMatchers) {
					if (matcher.matches(request)) {
						return false;
					}
				}
				return true;
			}
		};
	}

	private static Filter csrfHeaderFilter() {

		return new OncePerRequestFilter() {

			@Override
			protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
					final FilterChain filterChain) throws ServletException, IOException {

				final CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());

				if (csrf != null) {

					Cookie cookie = WebUtils.getCookie(request, CSRF_COOKIE_NAME);

					final String token = csrf.getToken();

					if (cookie == null || token != null && !token.equals(cookie.getValue())) {
						cookie = new Cookie(CSRF_COOKIE_NAME, token);
						cookie.setPath("/");
						cookie.setSecure(true);
						response.addCookie(cookie);
					}
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
}
