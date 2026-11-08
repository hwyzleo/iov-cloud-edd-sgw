package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

import io.netty.channel.ChannelOption;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.sgw.api.enums.RouteTargetType;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RetryRule;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RewritePath;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteTarget;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteTransform;
import net.hwyz.iov.cloud.edd.sgw.domain.model.TrafficPolicy;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.loadbalancer.DefaultRequest;
import org.springframework.cloud.loadbalancer.support.LoadBalancerClientFactory;
import org.springframework.cloud.client.loadbalancer.Response;
import org.springframework.cloud.client.loadbalancer.reactive.ReactiveLoadBalancer;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferLimitException;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 上游转发器：负责目标解析、请求变换、超时与安全重试。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class UpstreamForwarder {

    private static final List<String> HOP_BY_HOP = List.of("connection", "keep-alive", "transfer-encoding",
            "te", "trailer", "upgrade", "proxy-authenticate", "proxy-authorization", "host", "content-length", "expect");

    private static final int MAX_BUFFERED_BODY = 1024 * 1024;

    private final LoadBalancerClientFactory loadBalancerClientFactory;

    private final SgwProperties properties;

    private final Map<String, WebClient> webClients = new ConcurrentHashMap<>();

    public UpstreamForwarder(LoadBalancerClientFactory loadBalancerClientFactory, SgwProperties properties) {
        this.loadBalancerClientFactory = loadBalancerClientFactory;
        this.properties = properties;
    }

    /**
     * 转发请求
     *
     * @param exchange  交换
     * @param route     已编译路由
     * @param target    最终目标（可能是灰度目标）
     * @param policy    流量治理策略，可空
     * @param requestId 请求ID
     * @return 完成信号
     */
    public Mono<Void> forward(ServerWebExchange exchange, CompiledRoute route, RouteTarget target,
                              TrafficPolicy policy, String requestId) {
        RetryRule retry = policy != null && policy.effective() ? policy.getRetry() : null;
        String method = exchange.getRequest().getMethod().name().toUpperCase(Locale.ROOT);
        boolean retryable = retry != null && retry.getMaxAttempts() != null && retry.getMaxAttempts() > 1
                && retry.getMethods().stream().anyMatch(item -> item.equalsIgnoreCase(method));
        if (retryable) {
            return bufferBody(exchange)
                    .flatMap(body -> attempt(exchange, route, target, policy, requestId, body, retry, 1));
        }
        return attempt(exchange, route, target, policy, requestId, null, retry, 1);
    }

    private Mono<byte[]> bufferBody(ServerWebExchange exchange) {
        return DataBufferUtils.join(exchange.getRequest().getBody(), MAX_BUFFERED_BODY)
                .map(buffer -> {
                    byte[] bytes = new byte[buffer.readableByteCount()];
                    buffer.read(bytes);
                    DataBufferUtils.release(buffer);
                    return bytes;
                })
                .defaultIfEmpty(new byte[0])
                .onErrorMap(DataBufferLimitException.class,
                        error -> new SgwException(SgwErrorCode.VALIDATION_FAILED, "请求体超过可重试缓冲上限", error));
    }

    private Mono<Void> attempt(ServerWebExchange exchange, CompiledRoute route, RouteTarget target,
                               TrafficPolicy policy, String requestId, byte[] bufferedBody,
                               RetryRule retry, int attemptNo) {
        return resolveBaseUri(exchange, target)
                .flatMap(baseUri -> {
                    String url = buildUrl(baseUri, route.getDefinition(), exchange);
                    WebClient.RequestBodySpec spec = webClient(policy)
                            .method(HttpMethod.valueOf(exchange.getRequest().getMethod().name()))
                            .uri(url)
                            .headers(headers -> applyHeaders(exchange, route.getDefinition(), headers, requestId));
                    WebClient.RequestHeadersSpec<?> headersSpec;
                    if (bufferedBody == null) {
                        headersSpec = spec.body(BodyInserters.fromDataBuffers(exchange.getRequest().getBody()));
                    } else if (bufferedBody.length == 0) {
                        headersSpec = spec;
                    } else {
                        headersSpec = spec.bodyValue(bufferedBody);
                    }
                    return headersSpec.exchangeToMono(response ->
                                    handleResponse(exchange, response, retry, attemptNo,
                                            () -> attempt(exchange, route, target, policy, requestId,
                                                    bufferedBody, retry, attemptNo + 1)))
                            .onErrorResume(error -> shouldRetry(error, retry, attemptNo)
                                    ? backoff(retry).then(Mono.defer(() -> attempt(exchange, route, target, policy,
                                    requestId, bufferedBody, retry, attemptNo + 1)))
                                    : Mono.error(mapUpstreamError(error)));
                });
    }

    private Mono<String> resolveBaseUri(ServerWebExchange exchange, RouteTarget target) {
        if (target.getType() != RouteTargetType.SERVICE) {
            return Mono.just(target.getUri());
        }
        ReactiveLoadBalancer<ServiceInstance> loadBalancer =
                loadBalancerClientFactory.getInstance(target.getServiceId());
        return Mono.from(loadBalancer.choose(new DefaultRequest<>(exchange.getRequest())))
                .flatMap(response -> {
                    ServiceInstance instance = response == null || !response.hasServer()
                            ? null : response.getServer();
                    if (instance == null) {
                        return Mono.error(new SgwException(SgwErrorCode.UPSTREAM_UNAVAILABLE,
                                "服务 " + target.getServiceId() + " 无可用实例"));
                    }
                    String scheme = instance.isSecure() ? "https" : "http";
                    int port = instance.getPort() > 0 ? instance.getPort()
                            : (instance.isSecure() ? 443 : 80);
                    return Mono.just(scheme + "://" + instance.getHost() + ":" + port);
                });
    }

    private String buildUrl(String baseUri, RouteDefinition route, ServerWebExchange exchange) {
        String path = exchange.getRequest().getPath().pathWithinApplication().value();
        RouteTransform transform = route.getTransform();
        if (transform != null && transform.getRewritePath() != null) {
            RewritePath rewritePath = transform.getRewritePath();
            path = java.util.regex.Pattern.compile(rewritePath.getPattern())
                    .matcher(path)
                    .replaceFirst(rewritePath.getReplacement());
        }
        String base = baseUri.endsWith("/") ? baseUri.substring(0, baseUri.length() - 1) : baseUri;
        String normalizedPath = path.startsWith("/") ? path : "/" + path;
        String query = exchange.getRequest().getURI().getRawQuery();
        return base + normalizedPath + (query == null || query.isEmpty() ? "" : "?" + query);
    }

    private void applyHeaders(ServerWebExchange exchange, RouteDefinition route, HttpHeaders headers,
                              String requestId) {
        exchange.getRequest().getHeaders().forEach((name, values) -> {
            if (!HOP_BY_HOP.contains(name.toLowerCase(Locale.ROOT))) {
                headers.put(name, values);
            }
        });
        RouteTransform transform = route.getTransform();
        if (transform != null) {
            for (String header : transform.getHeadersToRemove()) {
                headers.remove(header);
            }
            transform.getHeadersToAdd().forEach(headers::set);
        }
        headers.set("X-Request-Id", requestId);
    }

    private Mono<Void> handleResponse(ServerWebExchange exchange, ClientResponse response, RetryRule retry,
                                      int attemptNo, java.util.function.Supplier<Mono<Void>> retrySupplier) {
        int status = response.statusCode().value();
        boolean retryableStatus = retry != null && retry.getStatuses().contains(status)
                && attemptNo < retry.getMaxAttempts();
        if (retryableStatus) {
            return response.releaseBody()
                    .then(backoff(retry))
                    .then(Mono.defer(retrySupplier));
        }
        exchange.getAttributes().put(RequestAttributes.UPSTREAM_STATUS, status);
        exchange.getResponse().setStatusCode(response.statusCode());
        response.headers().asHttpHeaders().forEach((name, values) -> {
            if (!HOP_BY_HOP.contains(name.toLowerCase(Locale.ROOT))) {
                exchange.getResponse().getHeaders().put(name, values);
            }
        });
        Flux<DataBuffer> body = response.bodyToFlux(DataBuffer.class);
        return exchange.getResponse().writeWith(body);
    }

    private boolean shouldRetry(Throwable error, RetryRule retry, int attemptNo) {
        if (retry == null || attemptNo >= retry.getMaxAttempts()) {
            return false;
        }
        return error instanceof IOException
                || error instanceof org.springframework.web.reactive.function.client.WebClientRequestException
                || error instanceof java.util.concurrent.TimeoutException
                || error instanceof io.netty.handler.timeout.ReadTimeoutException
                || hasCause(error, IOException.class);
    }

    private boolean hasCause(Throwable error, Class<? extends Throwable> type) {
        Throwable cause = error.getCause();
        while (cause != null) {
            if (type.isInstance(cause)) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }

    private Mono<Void> backoff(RetryRule retry) {
        long backoff = retry == null || retry.getBackoffMillis() == null ? 0 : retry.getBackoffMillis();
        return backoff <= 0 ? Mono.empty() : Mono.delay(Duration.ofMillis(backoff)).then();
    }

    private Throwable mapUpstreamError(Throwable error) {
        if (error instanceof SgwException) {
            return error;
        }
        if (error instanceof java.util.concurrent.TimeoutException
                || error instanceof io.netty.handler.timeout.ReadTimeoutException
                || hasCause(error, java.util.concurrent.TimeoutException.class)
                || hasCause(error, io.netty.handler.timeout.ReadTimeoutException.class)) {
            return new SgwException(SgwErrorCode.UPSTREAM_TIMEOUT, "上游响应超时", error);
        }
        return new SgwException(SgwErrorCode.UPSTREAM_UNAVAILABLE, "上游服务不可用", error);
    }

    private WebClient webClient(TrafficPolicy policy) {
        int connectTimeout = policy != null && policy.getConnectTimeoutMillis() != null
                ? policy.getConnectTimeoutMillis()
                : properties.getRuntime().getDefaultConnectTimeoutMillis();
        int responseTimeout = policy != null && policy.getResponseTimeoutMillis() != null
                ? policy.getResponseTimeoutMillis()
                : properties.getRuntime().getDefaultResponseTimeoutMillis();
        String key = connectTimeout + ":" + responseTimeout;
        return webClients.computeIfAbsent(key, ignored -> {
            HttpClient httpClient = HttpClient.create()
                    .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, connectTimeout)
                    // 传输层超时留出余量，由策略级超时先触发，保证统一返回 504
                    .responseTimeout(Duration.ofMillis(responseTimeout + 1000L))
                    .compress(true);
            return WebClient.builder()
                    .clientConnector(new ReactorClientHttpConnector(httpClient))
                    .build();
        });
    }

}
