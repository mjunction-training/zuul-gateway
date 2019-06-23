package com.training.gateway.zuulgateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.cloud.client.circuitbreaker.EnableCircuitBreaker;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.netflix.hystrix.EnableHystrix;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.cloud.netflix.zuul.filters.route.FallbackProvider;
import org.springframework.context.annotation.Bean;

import com.training.gateway.zuulgateway.config.GenericFallbackProvider;

import brave.sampler.Sampler;

@EnableHystrix
@EnableZuulProxy
@EnableCircuitBreaker
@EnableDiscoveryClient
@SpringBootApplication
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
	public FallbackProvider uaaSvcsZuulFallbackProvider() {
		return new GenericFallbackProvider("uaa-svcs");
	}

	@Bean
	public FallbackProvider userSvcsZuulFallbackProvider() {
		return new GenericFallbackProvider("user-svcs");
	}

	@Bean
	public FallbackProvider productCatalogZuulFallbackProvider() {
		return new GenericFallbackProvider("product-catalog");
	}

	@Bean
	public FallbackProvider productCompositeZuulFallbackProvider() {
		return new GenericFallbackProvider("product-composite");
	}

	@Bean
	public FallbackProvider pricingSvcsZuulFallbackProvider() {
		return new GenericFallbackProvider("pricinf-svcs");
	}

	@Bean
	public FallbackProvider recommSvcsZuulFallbackProvider() {
		return new GenericFallbackProvider("recomm-svcs");
	}

	@Bean
	public FallbackProvider reviewSvcsZuulFallbackProvider() {
		return new GenericFallbackProvider("review-svcs");
	}

}
