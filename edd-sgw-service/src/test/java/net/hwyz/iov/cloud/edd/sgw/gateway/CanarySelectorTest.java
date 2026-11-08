package net.hwyz.iov.cloud.edd.sgw.gateway;

import net.hwyz.iov.cloud.edd.sgw.api.enums.CanaryStableKey;
import net.hwyz.iov.cloud.edd.sgw.api.enums.RouteTargetType;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryConditions;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryRule;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryTarget;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteTarget;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.CanarySelector;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 灰度选择测试。
 *
 * @author hwyz_leo
 */
class CanarySelectorTest {

    private final CanarySelector selector = new CanarySelector();

    private final RouteDefinition route = RouteDefinition.builder()
            .routeCode("vehicle-profile")
            .routeName("车辆档案")
            .priority(100)
            .enabled(true)
            .target(RouteTarget.builder().type(RouteTargetType.SERVICE).serviceId("edd-vmd-service").build())
            .build();

    @Test
    @DisplayName("加权目标在 10000 次请求内接近配置权重")
    void weightedDistribution() {
        CanaryPolicy policy = policy(CanaryStableKey.SOURCE_IP, 10, 90);
        Map<String, Integer> counts = new HashMap<>();
        for (int i = 0; i < 10_000; i++) {
            RouteTarget target = selector.select(policy, route, identity(), "10.0.0." + i, request())
                    .orElseThrow();
            counts.merge(target.getServiceId(), 1, Integer::sum);
        }
        double canary = counts.getOrDefault("edd-vmd-service-v2", 0) / 100.0;
        double stable = counts.getOrDefault("edd-vmd-service", 0) / 100.0;
        assertThat(canary).isBetween(8.0, 12.0);
        assertThat(stable).isBetween(88.0, 92.0);
    }

    @Test
    @DisplayName("相同稳定键始终命中同一目标")
    void stickyRouting() {
        CanaryPolicy policy = policy(CanaryStableKey.SOURCE_IP, 50, 50);
        String first = selector.select(policy, route, identity(), "10.0.0.9", request())
                .orElseThrow().getServiceId();
        for (int i = 0; i < 100; i++) {
            assertThat(selector.select(policy, route, identity(), "10.0.0.9", request())
                    .orElseThrow().getServiceId()).isEqualTo(first);
        }
    }

    @Test
    @DisplayName("高优先级规则优先命中，无条件匹配时回退默认目标")
    void rulePriorityAndFallback() {
        CanaryPolicy policy = CanaryPolicy.builder()
                .policyCode("canary")
                .policyName("灰度")
                .stableKey(CanaryStableKey.SOURCE_IP)
                .enabled(true)
                .rules(List.of(
                        CanaryRule.builder()
                                .priority(1)
                                .conditions(CanaryConditions.builder().clientTypes(List.of("MOBILE")).build())
                                .targets(List.of(target("mobile-canary", 100)))
                                .build(),
                        CanaryRule.builder()
                                .priority(2)
                                .conditions(CanaryConditions.builder().userIds(List.of("u1")).build())
                                .targets(List.of(target("user-canary", 100)))
                                .build()))
                .build();
        net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.AuthenticatedIdentity mobile =
                new net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.AuthenticatedIdentity(
                        "u2", "c1", "MOBILE", "d1", "s1", null, List.of());
        assertThat(selector.select(policy, route, mobile, "10.0.0.1", request()))
                .get().extracting(RouteTarget::getServiceId).isEqualTo("mobile-canary");
        assertThat(selector.select(policy, route, null, "10.0.0.1", request())).isEmpty();
    }

    private CanaryPolicy policy(CanaryStableKey key, int canaryWeight, int stableWeight) {
        return CanaryPolicy.builder()
                .policyCode("vmd-canary")
                .policyName("VMD 灰度")
                .stableKey(key)
                .enabled(true)
                .rules(List.of(CanaryRule.builder()
                        .priority(10)
                        .conditions(CanaryConditions.builder().clientTypes(List.of("MOBILE")).build())
                        .targets(List.of(target("edd-vmd-service-v2", canaryWeight),
                                target("edd-vmd-service", stableWeight)))
                        .build()))
                .build();
    }

    private CanaryTarget target(String serviceId, int weight) {
        return CanaryTarget.builder()
                .type(RouteTargetType.SERVICE)
                .serviceId(serviceId)
                .weight(weight)
                .build();
    }

    private net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.AuthenticatedIdentity identity() {
        return new net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.AuthenticatedIdentity(
                "u1", "c1", "MOBILE", "d1", "s1", null, List.of());
    }

    private org.springframework.http.server.reactive.ServerHttpRequest request() {
        return MockServerHttpRequest.get("/vehicle/profile/1")
                .header("X-Client-Type", "MOBILE")
                .build();
    }

}
