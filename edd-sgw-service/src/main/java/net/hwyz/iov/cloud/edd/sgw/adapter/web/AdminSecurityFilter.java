package net.hwyz.iov.cloud.edd.sgw.adapter.web;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.RequestAttributes;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.security.InternalHmacVerifier;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/**
 * 管理接口内部签名过滤器。
 * <p>
 * 对 {@code /api/service/sgw/v1/**} 强制校验 HMAC 签名、时间窗与 nonce 防重放。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class AdminSecurityFilter implements WebFilter, Ordered {

    private static final String ADMIN_PREFIX = "/api/service/sgw/v1";

    private static final int MAX_CACHED_BODY_BYTES = 2 * 1024 * 1024;

    private final InternalHmacVerifier hmacVerifier;

    private final SgwProperties properties;

    private final SgwResponseWriter responseWriter;

    public AdminSecurityFilter(InternalHmacVerifier hmacVerifier, SgwProperties properties,
                               SgwResponseWriter responseWriter) {
        this.hmacVerifier = hmacVerifier;
        this.properties = properties;
        this.responseWriter = responseWriter;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        if (!path.startsWith(ADMIN_PREFIX)) {
            return chain.filter(exchange);
        }
        if (properties.getSecurity().getInternal().getClients().isEmpty()) {
            log.error("内部管理接口拒绝请求: 未配置 sgw.security.internal.clients, path={}", path);
            return responseWriter.write(exchange, SgwErrorCode.FORBIDDEN, "内部管理接口未配置认证密钥");
        }
        return DataBufferUtils.join(exchange.getRequest().getBody(), MAX_CACHED_BODY_BYTES)
                .map(buffer -> {
                    byte[] bytes = new byte[buffer.readableByteCount()];
                    buffer.read(bytes);
                    DataBufferUtils.release(buffer);
                    return bytes;
                })
                .defaultIfEmpty(new byte[0])
                .flatMap(body -> hmacVerifier.verify(exchange.getRequest(), Json.sha256(new String(body, StandardCharsets.UTF_8)))
                        .flatMap(actor -> {
                            exchange.getAttributes().put(RequestAttributes.ADM_ACTOR, actor);
                            return chain.filter(withCachedBody(exchange, body));
                        }))
                .onErrorResume(SgwException.class,
                        error -> {
                            log.warn("内部管理请求被拒绝: path={}, code={}, message={}",
                                    path, error.errorCode().code(), error.getMessage());
                            return responseWriter.write(exchange, error.errorCode(), error.getMessage());
                        })
                .onErrorResume(error -> {
                    log.error("内部管理请求处理失败: path={}", path, error);
                    return responseWriter.write(exchange, SgwErrorCode.UNAUTHORIZED);
                });
    }

    private ServerWebExchange withCachedBody(ServerWebExchange exchange, byte[] body) {
        ServerHttpRequest decorated = new ServerHttpRequestDecorator(exchange.getRequest()) {
            @Override
            public HttpHeaders getHeaders() {
                HttpHeaders headers = new HttpHeaders();
                headers.putAll(super.getHeaders());
                headers.setContentLength(body.length);
                return headers;
            }

            @Override
            public Flux<DataBuffer> getBody() {
                if (body.length == 0) {
                    return Flux.empty();
                }
                return Flux.defer(() -> Flux.just(exchange.getResponse().bufferFactory().wrap(body)));
            }
        };
        return exchange.mutate().request(decorated).build();
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 10;
    }

}
