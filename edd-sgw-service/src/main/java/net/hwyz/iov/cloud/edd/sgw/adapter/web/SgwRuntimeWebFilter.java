package net.hwyz.iov.cloud.edd.sgw.adapter.web;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.CompiledRoute;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.CompiledSnapshot;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.GovernanceHandler;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.RequestAttributes;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.RouteMatcher;
import net.hwyz.iov.cloud.edd.sgw.domain.model.AuthPolicy;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.SgwRouteMetrics;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.SnapshotManager;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.SourceIpResolver;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.security.RequestAuthorizer;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;

/**
 * 网关运行时过滤器：捕获单一快照、匹配路由、认证授权、治理与转发。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class SgwRuntimeWebFilter implements WebFilter, Ordered {

    private static final List<String> EXCLUDED_PREFIXES = List.of("/api/service/sgw/v1", "/actuator", "/favicon.ico");

    private final SnapshotManager snapshotManager;

    private final RouteMatcher routeMatcher;

    private final RequestAuthorizer requestAuthorizer;

    private final GovernanceHandler governanceHandler;

    private final SourceIpResolver sourceIpResolver;

    private final SgwResponseWriter responseWriter;

    private final SgwRouteMetrics metrics;

    public SgwRuntimeWebFilter(SnapshotManager snapshotManager, RouteMatcher routeMatcher,
                               RequestAuthorizer requestAuthorizer, GovernanceHandler governanceHandler,
                               SourceIpResolver sourceIpResolver, SgwResponseWriter responseWriter,
                               SgwRouteMetrics metrics) {
        this.snapshotManager = snapshotManager;
        this.routeMatcher = routeMatcher;
        this.requestAuthorizer = requestAuthorizer;
        this.governanceHandler = governanceHandler;
        this.sourceIpResolver = sourceIpResolver;
        this.responseWriter = responseWriter;
        this.metrics = metrics;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        if (EXCLUDED_PREFIXES.stream().anyMatch(path::startsWith)) {
            return chain.filter(exchange);
        }
        CompiledSnapshot snapshot = snapshotManager.current();
        if (snapshot == null || !snapshotManager.isReady()) {
            return responseWriter.write(exchange, SgwErrorCode.UPSTREAM_UNAVAILABLE, "服务网关未就绪");
        }
        exchange.getAttributes().put(RequestAttributes.SNAPSHOT, snapshot);
        String sourceIp = sourceIpResolver.resolve(exchange.getRequest());
        if (sourceIp != null) {
            exchange.getAttributes().put(RequestAttributes.SOURCE_IP, sourceIp);
        }
        Optional<CompiledRoute> matched = routeMatcher.match(snapshot, exchange.getRequest());
        if (matched.isEmpty()) {
            metrics.routeMiss();
            return responseWriter.write(exchange, SgwErrorCode.ROUTE_NOT_FOUND);
        }
        CompiledRoute route = matched.get();
        metrics.routeHit(route.routeCode(), accessMode(snapshot, route));
        exchange.getAttributes().put(RequestAttributes.ROUTE, route);
        return requestAuthorizer.authorize(exchange, snapshot, route)
                .flatMap(result -> {
                    if (result.identity() != null) {
                        result.exchange().getAttributes().put(RequestAttributes.IDENTITY, result.identity());
                    }
                    return governanceHandler.handle(result.exchange(), snapshot, route, sourceIp);
                });
    }

    /**
     * 路由绑定的访问模式（用于指标标签；策略缺失时为 null，不影响 fail-closed 判定）
     */
    private AccessMode accessMode(CompiledSnapshot snapshot, CompiledRoute route) {
        String policyCode = route.getDefinition().getAuthPolicyCode();
        if (policyCode == null) {
            return null;
        }
        AuthPolicy policy = snapshot.getAuthPolicies().get(policyCode);
        return policy == null ? null : policy.getAccessMode();
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 100;
    }

}
