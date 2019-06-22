
package com.training.gateway.zuulgateway.config;

import java.io.IOException;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.web.util.UriComponentsBuilder;

public class DynamicOauth2ClientContextFilter extends OAuth2ClientContextFilter {

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
		return url.substring(0, url.length() - request.getRequestURI().length() + request.getContextPath().length());
	}
}
