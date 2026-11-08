package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

import io.github.resilience4j.bulkhead.Bulkhead;
import io.github.resilience4j.bulkhead.BulkheadFullException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.reactor.bulkhead.operator.BulkheadOperator;
import net.hwyz.iov.cloud.edd.sgw.api.enums.RateLimitDimension;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RateLimitRule;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteTarget;
import net.hwyz.iov.cloud.edd.sgw.domain.model.TrafficPolicy;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.resilience.ClusterRateLimiter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.TimeoutException;

/**
 * 流量治理执行器：限流、并发隔离、熔断、超时、灰度与转发。
 *
 * @author hwyz_leo
 */
@Component
public class GovernanceHandler {

    private final ClusterRateLimiter rateLimiter;

    private final GovernanceRegistry governanceRegistry;

    private final UpstreamForwarder upstreamForwarder;

    private final CanarySelector canarySelector;

    public GovernanceHandler(ClusterRateLimiter rateLimiter, GovernanceRegistry governanceRegistry,
                             UpstreamForwarder upstreamForwarder, CanarySelector canarySelector) {
        this.rateLimiter = rateLimiter;
        this.governanceRegistry = governanceRegistry;
        this.upstreamForwarder = upstreamForwarder;
        this.canarySelector = canarySelector;
    }

    /**
     * 执行治理与转发
     *
     * @param exchange 交换
     * @param snapshot 请求级快照
     * @param route    路由
     * @param sourceIp 来源IP
     * @return 完成信号
     */
    public Mono<Void> handle(ServerWebExchange exchange, CompiledSnapshot snapshot, CompiledRoute route,
                             String sourceIp) {
        RouteDefinition definition = route.getDefinition();
        AuthenticatedIdentity identity = exchange.getAttribute(RequestAttributes.IDENTITY);
        TrafficPolicy policy = resolveTrafficPolicy(snapshot, definition);
        String requestId = String.valueOf(exchange.getAttributes().get(RequestAttributes.REQUEST_ID));

        Mono<Void> forwarding = Mono.defer(() -> {
            RouteTarget target = definition.getTarget();
            if (definition.getCanaryPolicyCode() != null) {
                CanaryPolicy canary = snapshot.getCanaryPolicies().get(definition.getCanaryPolicyCode());
                if (canary != null && canary.effective()) {
                    target = canarySelector.select(canary, definition, identity, sourceIp, exchange.getRequest())
                            .orElse(target);
                }
            }
            return upstreamForwarder.forward(exchange, route, target, policy, requestId);
        });

        Mono<Void> rateLimited = applyRateLimits(exchange, route, policy, identity, sourceIp).then(forwarding);
        return applyGovernance(rateLimited, policy, exchange);
    }

    private TrafficPolicy resolveTrafficPolicy(CompiledSnapshot snapshot, RouteDefinition definition) {
        if (definition.getTrafficPolicyCode() == null) {
            return null;
        }
        TrafficPolicy policy = snapshot.getTrafficPolicies().get(definition.getTrafficPolicyCode());
        return policy != null && policy.effective() ? policy : null;
    }

    private Mono<Void> applyRateLimits(ServerWebExchange exchange, CompiledRoute route, TrafficPolicy policy,
                                       AuthenticatedIdentity identity, String sourceIp) {
        if (policy == null || policy.getRateLimits().isEmpty()) {
            return Mono.empty();
        }
        return Flux.fromIterable(policy.getRateLimits())
                .concatMap(rule -> checkRateLimit(route, policy, rule, identity, sourceIp))
                .then();
    }

    private Mono<Void> checkRateLimit(CompiledRoute route, TrafficPolicy policy, RateLimitRule rule,
                                     AuthenticatedIdentity identity, String sourceIp) {
        String dimensionValue = dimensionValue(rule.getDimension(), route, identity, sourceIp);
        if (dimensionValue == null) {
            return Mono.empty();
        }
        String key = "sgw:rl:" + policy.getPolicyCode() + ":" + route.routeCode() + ":"
                + rule.getDimension() + ":" + dimensionValue;
        return rateLimiter.tryAcquire(key, rule.getReplenishPerSecond(), rule.getBurstCapacity(),
                        rule.getFailureMode())
                .flatMap(allowed -> allowed ? Mono.empty()
                        : Mono.error(new SgwException(SgwErrorCode.RATE_LIMITED, "触发集群限流")));
    }

    private String dimensionValue(RateLimitDimension dimension, CompiledRoute route,
                                  AuthenticatedIdentity identity, String sourceIp) {
        if (dimension == null) {
            return null;
        }
        return switch (dimension) {
            case ROUTE -> route.routeCode();
            case SOURCE_IP -> sourceIp;
            case CLIENT_TYPE -> identity == null ? null : identity.clientType();
            case CLIENT_ID -> identity == null ? null : identity.clientId();
            case AUTHENTICATED_SUBJECT -> identity == null ? null : identity.subject();
            case VEHICLE_ID -> identity == null ? null : identity.vehicleId();
        };
    }

    private Mono<Void> applyGovernance(Mono<Void> execution, TrafficPolicy policy, ServerWebExchange exchange) {
        if (policy == null) {
            return execution;
        }
        Mono<Void> result = execution;
        if (policy.getResponseTimeoutMillis() != null && policy.getResponseTimeoutMillis() > 0) {
            result = result.timeout(Duration.ofMillis(policy.getResponseTimeoutMillis()))
                    .onErrorMap(TimeoutException.class,
                            error -> new SgwException(SgwErrorCode.UPSTREAM_TIMEOUT, "上游响应超时", error));
        }
        Optional<CircuitBreaker> circuitBreaker = governanceRegistry.circuitBreaker(policy.getPolicyCode());
        if (circuitBreaker.isPresent()) {
            result = withCircuitBreaker(result, circuitBreaker.get(), exchange);
        }
        Optional<Bulkhead> bulkhead = governanceRegistry.bulkhead(policy.getPolicyCode());
        if (bulkhead.isPresent()) {
            result = result.transformDeferred(BulkheadOperator.of(bulkhead.get()))
                    .onErrorMap(BulkheadFullException.class,
                            error -> new SgwException(SgwErrorCode.CONCURRENCY_LIMITED, "并发请求过多", error));
        }
        return result;
    }

    /**
     * 熔断保护：5xx 响应与异常均记为失败，成功响应按耗时记录慢调用。
     *
     * @param execution 执行链
     * @param breaker   熔断器
     * @param exchange  交换
     * @return 受保护执行链
     */
    private Mono<Void> withCircuitBreaker(Mono<Void> execution, CircuitBreaker breaker,
                                          ServerWebExchange exchange) {
        return Mono.defer(() -> {
            if (!breaker.tryAcquirePermission()) {
                return Mono.error(new SgwException(SgwErrorCode.CIRCUIT_OPEN, "上游服务已熔断"));
            }
            long start = System.nanoTime();
            return execution
                    .doOnSuccess(ignored -> {
                        Object status = exchange.getAttributes().get(RequestAttributes.UPSTREAM_STATUS);
                        long elapsed = System.nanoTime() - start;
                        if (status instanceof Integer code && code >= 500) {
                            breaker.onError(elapsed, java.util.concurrent.TimeUnit.NANOSECONDS,
                                    new IllegalStateException("上游返回 " + code));
                        } else {
                            breaker.onSuccess(elapsed, java.util.concurrent.TimeUnit.NANOSECONDS);
                        }
                    })
                    .doOnError(error -> breaker.onError(System.nanoTime() - start,
                            java.util.concurrent.TimeUnit.NANOSECONDS, error));
        });
    }

}
