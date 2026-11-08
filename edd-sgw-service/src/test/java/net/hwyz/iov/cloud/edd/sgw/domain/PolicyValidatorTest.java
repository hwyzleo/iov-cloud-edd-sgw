package net.hwyz.iov.cloud.edd.sgw.domain;

import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;
import net.hwyz.iov.cloud.edd.sgw.api.enums.CanaryStableKey;
import net.hwyz.iov.cloud.edd.sgw.api.enums.RateLimitDimension;
import net.hwyz.iov.cloud.edd.sgw.api.enums.RateLimitFailureMode;
import net.hwyz.iov.cloud.edd.sgw.api.enums.RouteTargetType;
import net.hwyz.iov.cloud.edd.sgw.domain.model.AuthPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryConditions;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryRule;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryTarget;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CircuitBreakerRule;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RateLimitRule;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RetryRule;
import net.hwyz.iov.cloud.edd.sgw.domain.model.TrafficPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.PolicyValidator;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.ValidationResult;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.ValidationError;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 治理策略校验器测试。
 *
 * @author hwyz_leo
 */
class PolicyValidatorTest {

    private final PolicyValidator validator = new PolicyValidator();

    @Test
    @DisplayName("匿名策略不能声明 scope 或权限点")
    void anonymousWithScopes() {
        AuthPolicy policy = AuthPolicy.builder()
                .policyCode("public-api")
                .policyName("匿名")
                .accessMode(AccessMode.ANONYMOUS)
                .requiredScopes(List.of("vehicle.read"))
                .build();
        ValidationResult result = validator.validateAuth(policy);
        assertThat(result.errors()).extracting(ValidationError::field).contains("accessMode");
    }

    @Test
    @DisplayName("认证策略允许客户端类型、scope 与权限点")
    void authenticatedPolicy() {
        AuthPolicy policy = AuthPolicy.builder()
                .policyCode("vehicle-user")
                .policyName("车辆用户")
                .accessMode(AccessMode.AUTHENTICATED)
                .allowedClientTypes(List.of("MOBILE", "IDCM"))
                .requiredScopes(List.of("vehicle.read"))
                .requiredPermissions(List.of("edd:vehicle:read"))
                .build();
        assertThat(validator.validateAuth(policy).valid()).isTrue();
    }

    @Test
    @DisplayName("流量策略校验超时、限流、熔断与安全重试")
    void trafficPolicy() {
        TrafficPolicy invalid = TrafficPolicy.builder()
                .policyCode("bad")
                .policyName("非法")
                .connectTimeoutMillis(0)
                .responseTimeoutMillis(0)
                .maxConcurrentRequests(0)
                .rateLimits(List.of(RateLimitRule.builder()
                        .dimension(RateLimitDimension.ROUTE)
                        .replenishPerSecond(0)
                        .burstCapacity(0)
                        .failureMode(RateLimitFailureMode.FAIL_CLOSED)
                        .build()))
                .circuitBreaker(CircuitBreakerRule.builder()
                        .slidingWindowSize(10)
                        .minimumNumberOfCalls(20)
                        .failureRateThreshold(150F)
                        .slowCallRateThreshold(50F)
                        .slowCallDurationMillis(2000L)
                        .waitDurationInOpenStateMillis(30000L)
                        .permittedCallsInHalfOpenState(0)
                        .build())
                .retry(RetryRule.builder()
                        .maxAttempts(0)
                        .backoffMillis(-1L)
                        .methods(List.of("POST"))
                        .statuses(List.of(200))
                        .build())
                .build();
        ValidationResult result = validator.validateTraffic(invalid);
        assertThat(result.errors()).extracting(ValidationError::field).contains(
                "connectTimeoutMillis", "responseTimeoutMillis", "maxConcurrentRequests",
                "rateLimits[0].replenishPerSecond", "rateLimits[0].burstCapacity",
                "circuitBreaker.minimumNumberOfCalls", "circuitBreaker.failureRateThreshold",
                "retry.maxAttempts", "retry.methods[0]", "retry.statuses[0]");
    }

    @Test
    @DisplayName("灰度策略要求唯一优先级与权重合计 100")
    void canaryRules() {
        CanaryPolicy policy = CanaryPolicy.builder()
                .policyCode("vmd-canary")
                .policyName("VMD 灰度")
                .stableKey(CanaryStableKey.VEHICLE_ID)
                .rules(List.of(
                        CanaryRule.builder()
                                .priority(10)
                                .conditions(CanaryConditions.builder().clientTypes(List.of("IDCM")).build())
                                .targets(List.of(
                                        canaryTarget("edd-vmd-service-v2", 50),
                                        canaryTarget("edd-vmd-service", 40)))
                                .build(),
                        CanaryRule.builder()
                                .priority(10)
                                .conditions(CanaryConditions.builder().clientTypes(List.of("MOBILE")).build())
                                .targets(List.of(canaryTarget("edd-vmd-service", 100)))
                                .build()))
                .build();
        ValidationResult result = validator.validateCanary(policy, Set.of());
        assertThat(result.errors()).extracting(ValidationError::field)
                .contains("rules[1].priority", "rules[0].targets");
    }

    @Test
    @DisplayName("匿名访问模式下仅允许来源IP作为灰度稳定键")
    void stableKeyAvailability() {
        CanaryPolicy policy = CanaryPolicy.builder()
                .policyCode("canary")
                .policyName("灰度")
                .stableKey(CanaryStableKey.VEHICLE_ID)
                .build();
        assertThat(validator.unavailableStableKeys(policy, AccessMode.ANONYMOUS)).containsExactly("VEHICLE_ID");
        assertThat(validator.unavailableStableKeys(policy, AccessMode.AUTHENTICATED)).isEmpty();
    }

    private CanaryTarget canaryTarget(String serviceId, int weight) {
        return CanaryTarget.builder()
                .type(RouteTargetType.SERVICE)
                .serviceId(serviceId)
                .weight(weight)
                .build();
    }

}
