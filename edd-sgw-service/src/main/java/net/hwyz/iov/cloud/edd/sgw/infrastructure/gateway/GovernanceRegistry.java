package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

import io.github.resilience4j.bulkhead.Bulkhead;
import io.github.resilience4j.bulkhead.BulkheadConfig;
import io.github.resilience4j.bulkhead.BulkheadRegistry;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CircuitBreakerRule;
import net.hwyz.iov.cloud.edd.sgw.domain.model.SgwConfiguration;
import net.hwyz.iov.cloud.edd.sgw.domain.model.TrafficPolicy;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * 快照绑定的治理组件注册表。
 * <p>
 * 每次快照激活都重建熔断器与并发隔离器，避免跨版本共享可变全局规则。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class GovernanceRegistry {

    private volatile Map<String, CircuitBreaker> circuitBreakers = Map.of();

    private volatile Map<String, Bulkhead> bulkheads = Map.of();

    /**
     * 根据配置重建治理组件
     *
     * @param configuration 配置
     */
    public synchronized void rebuild(SgwConfiguration configuration) {
        Map<String, CircuitBreaker> newCircuitBreakers = new LinkedHashMap<>();
        Map<String, Bulkhead> newBulkheads = new LinkedHashMap<>();
        for (TrafficPolicy policy : configuration.getTrafficPolicies()) {
            if (!policy.effective()) {
                continue;
            }
            if (policy.getCircuitBreaker() != null) {
                newCircuitBreakers.put(policy.getPolicyCode(), buildCircuitBreaker(policy.getPolicyCode(),
                        policy.getCircuitBreaker()));
            }
            if (policy.getMaxConcurrentRequests() != null && policy.getMaxConcurrentRequests() > 0) {
                newBulkheads.put(policy.getPolicyCode(), buildBulkhead(policy.getPolicyCode(),
                        policy.getMaxConcurrentRequests()));
            }
        }
        this.circuitBreakers = Map.copyOf(newCircuitBreakers);
        this.bulkheads = Map.copyOf(newBulkheads);
        log.info("治理组件已随快照重建: 熔断器[{}], 并发隔离器[{}]", circuitBreakers.size(), bulkheads.size());
    }

    private CircuitBreaker buildCircuitBreaker(String policyCode, CircuitBreakerRule rule) {
        CircuitBreakerConfig.Builder builder = CircuitBreakerConfig.custom()
                .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
                .minimumNumberOfCalls(rule.getMinimumNumberOfCalls())
                .failureRateThreshold(rule.getFailureRateThreshold())
                .permittedNumberOfCallsInHalfOpenState(rule.getPermittedCallsInHalfOpenState())
                .waitDurationInOpenState(Duration.ofMillis(rule.getWaitDurationInOpenStateMillis()));
        if (rule.getSlidingWindowSize() != null) {
            builder.slidingWindowSize(rule.getSlidingWindowSize());
        }
        if (rule.getSlowCallRateThreshold() != null) {
            builder.slowCallRateThreshold(rule.getSlowCallRateThreshold());
        }
        if (rule.getSlowCallDurationMillis() != null) {
            builder.slowCallDurationThreshold(Duration.ofMillis(rule.getSlowCallDurationMillis()));
        }
        return CircuitBreakerRegistry.of(builder.build()).circuitBreaker(policyCode);
    }

    private Bulkhead buildBulkhead(String policyCode, int maxConcurrentRequests) {
        BulkheadConfig config = BulkheadConfig.custom()
                .maxConcurrentCalls(maxConcurrentRequests)
                .maxWaitDuration(Duration.ZERO)
                .build();
        return BulkheadRegistry.of(config).bulkhead(policyCode);
    }

    public Optional<CircuitBreaker> circuitBreaker(String policyCode) {
        return Optional.ofNullable(circuitBreakers.get(policyCode));
    }

    public Optional<Bulkhead> bulkhead(String policyCode) {
        return Optional.ofNullable(bulkheads.get(policyCode));
    }

    /**
     * 清空治理组件（用于失效快照）
     */
    public void clear() {
        circuitBreakers = Map.of();
        bulkheads = Map.of();
    }

}
