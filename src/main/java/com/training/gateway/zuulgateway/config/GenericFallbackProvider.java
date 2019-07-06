package com.training.gateway.zuulgateway.config;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.springframework.cloud.netflix.zuul.filters.route.FallbackProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;

import lombok.extern.log4j.Log4j2;

@Log4j2
public class GenericFallbackProvider implements FallbackProvider {

	private final String route;

	public GenericFallbackProvider(final String route) {
		this.route = route;
	}

	@Override
	public String getRoute() {
		return route;
	}

	@Override
	public ClientHttpResponse fallbackResponse(final String route, final Throwable cause) {
		return new ClientHttpResponse() {
			@Override
			public HttpStatus getStatusCode() throws IOException {
				return HttpStatus.SERVICE_UNAVAILABLE;
			}

			@Override
			public int getRawStatusCode() throws IOException {
				return HttpStatus.SERVICE_UNAVAILABLE.value();
			}

			@Override
			public String getStatusText() throws IOException {
				return HttpStatus.SERVICE_UNAVAILABLE.toString();
			}

			@Override
			public void close() {
			}

			@Override
			public InputStream getBody() throws IOException {
				log.error(() -> "Exception in zuul route :: " + route, cause);
				return new ByteArrayInputStream(
						("{\"message\":\"Sorry, Service is Down!\",\"exception\":\"" + cause.getMessage() + "\"}")
								.getBytes());
			}

			@Override
			public HttpHeaders getHeaders() {
				final HttpHeaders headers = new HttpHeaders();
				headers.setContentType(MediaType.APPLICATION_JSON);
				return headers;
			}
		};
	}
}