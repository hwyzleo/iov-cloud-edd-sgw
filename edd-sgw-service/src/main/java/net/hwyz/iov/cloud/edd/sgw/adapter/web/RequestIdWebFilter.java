package net.hwyz.iov.cloud.edd.sgw.adapter.web;

import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.RequestAttributes;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * 请求ID过滤器：为每个请求分配并回写 X-Request-Id。
 *
 * @author hwyz_leo
 */
@Component
public class RequestIdWebFilter implements WebFilter, Ordered {

    private final SgwProperties properties;

    public RequestIdWebFilter(SgwProperties properties) {
        this.properties = properties;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String headerName = properties.getRuntime().getRequestIdHeader();
        String requestId = exchange.getRequest().getHeaders().getFirst(headerName);
        if (requestId == null || requestId.isBlank()) {
            requestId = UUID.randomUUID().toString();
            ServerHttpRequest request = exchange.getRequest().mutate()
                    .header(headerName, requestId)
                    .build();
            exchange = exchange.mutate().request(request).build();
        }
        exchange.getAttributes().put(RequestAttributes.REQUEST_ID, requestId);
        exchange.getResponse().getHeaders().set(headerName, requestId);
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

}
