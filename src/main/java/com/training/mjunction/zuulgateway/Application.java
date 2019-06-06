package com.training.mjunction.zuulgateway;

import java.util.Set;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.netflix.hystrix.EnableHystrix;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

import brave.sampler.Sampler;

@EnableHystrix
@EnableZuulProxy
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

	@Component
	// XXX While waiting for:
	// https://github.com/spring-cloud/spring-cloud-netflix/issues/944
	public class RelayTokenFilter extends ZuulFilter {
		@Override
		public Object run() {
			final RequestContext ctx = RequestContext.getCurrentContext();

			// Alter ignored headers as per:
			// https://gitter.im/spring-cloud/spring-cloud?at=56fea31f11ea211749c3ed22
			@SuppressWarnings("unchecked")
			final Set<String> headers = (Set<String>) ctx.get("ignoredHeaders");
			// We need our JWT tokens relayed to resource servers
			headers.remove("authorization");

			return null;
		}

		@Override
		public boolean shouldFilter() {
			return true;
		}

		@Override
		public String filterType() {
			return "pre";
		}

		@Override
		public int filterOrder() {
			return 10000;
		}
	}

}
