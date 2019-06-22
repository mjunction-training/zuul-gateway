
package com.training.gateway.zuulgateway.config;

import java.util.Set;

import org.springframework.stereotype.Component;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

// XXX While waiting for: //
//https://github.com/spring-cloud/spring-cloud-netflix/issues/944

@Component
public class RelayTokenFilter extends ZuulFilter {

	@Override
	public Object run() {

		final RequestContext currentContext = RequestContext.getCurrentContext();

		// currentContext.addZuulRequestHeader("host",
		// currentContext.getRequest().getHeader("host"));

		// currentContext.getZuulRequestHeaders().remove("x-forwarded-prefix");

		// Alter ignored headers as per: // //
		// https://gitter.im/spring-cloud/spring-cloud?at=56fea31f11ea211749c3ed22

		@SuppressWarnings("unchecked")
		final Set<String> headers = (Set<String>) currentContext.get("ignoredHeaders");

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
