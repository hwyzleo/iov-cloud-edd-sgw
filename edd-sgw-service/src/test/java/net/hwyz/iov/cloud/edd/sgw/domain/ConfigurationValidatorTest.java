package net.hwyz.iov.cloud.edd.sgw.domain;

import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;
import net.hwyz.iov.cloud.edd.sgw.api.enums.CanaryStableKey;
import net.hwyz.iov.cloud.edd.sgw.api.enums.RouteTargetType;
import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
import net.hwyz.iov.cloud.edd.sgw.domain.model.AuthPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryConditions;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryRule;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryTarget;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteMatch;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteTarget;
import net.hwyz.iov.cloud.edd.sgw.domain.model.SgwConfiguration;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.ConfigurationValidator;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.PolicyValidator;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.RouteValidator;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.ValidationError;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.ValidationResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 完整配置校验器测试。
 *
 * @author hwyz_leo
 */
class ConfigurationValidatorTest {

    private final SgwProperties properties = new SgwProperties();

    private final ConfigurationValidator validator = new ConfigurationValidator(
            new RouteValidator(), new PolicyValidator(), properties);

    @Test
    @DisplayName("重复编码与缺失引用被拒绝")
    void duplicatesAndMissingReferences() {
        RouteDefinition route = route("vehicle-profile", 100);
        route.setAuthPolicyCode("missing");
        RouteDefinition duplicate = route("vehicle-profile", 200);
        SgwConfiguration configuration = SgwConfiguration.builder()
                .routes(List.of(route, duplicate))
                .build();
        ValidationResult result = validator.validate(configuration);
        assertThat(result.errors()).extracting(ValidationError::field)
                .contains("routes", "routes[vehicle-profile].authPolicyCode");
    }

    @Test
    @DisplayName("同优先级等价匹配被视为歧义")
    void ambiguousRoutes() {
        SgwConfiguration configuration = SgwConfiguration.builder()
                .routes(List.of(route("route-a", 100), route("route-b", 100)))
                .build();
        ValidationResult result = validator.validate(configuration);
        assertThat(result.valid()).isFalse();
        assertThat(result.message()).contains("歧义");
    }

    @Test
    @DisplayName("匿名路由不得使用车辆稳定键")
    void canaryStableKeyAvailability() {
        RouteDefinition route = route("route-a", 100);
        route.setCanaryPolicyCode("canary");
        AuthPolicy authPolicy = AuthPolicy.builder()
                .policyCode("anonymous")
                .policyName("匿名")
                .accessMode(AccessMode.ANONYMOUS)
                .build();
        route.setAuthPolicyCode("anonymous");
        CanaryPolicy canaryPolicy = CanaryPolicy.builder()
                .policyCode("canary")
                .policyName("灰度")
                .stableKey(CanaryStableKey.VEHICLE_ID)
                .enabled(true)
                .rules(List.of(CanaryRule.builder()
                        .priority(1)
                        .conditions(CanaryConditions.builder().clientTypes(List.of("MOBILE")).build())
                        .targets(List.of(CanaryTarget.builder()
                                .type(RouteTargetType.SERVICE)
                                .serviceId("edd-vmd-service")
                                .weight(100)
                                .build()))
                        .build()))
                .build();
        SgwConfiguration configuration = SgwConfiguration.builder()
                .routes(List.of(route))
                .authPolicies(List.of(authPolicy))
                .canaryPolicies(List.of(canaryPolicy))
                .build();
        ValidationResult result = validator.validate(configuration);
        assertThat(result.message()).contains("灰度稳定键");
    }

    private RouteDefinition route(String code, int priority) {
        return RouteDefinition.builder()
                .routeCode(code)
                .routeName(code)
                .priority(priority)
                .enabled(true)
                .match(RouteMatch.builder()
                        .paths(List.of("/vehicle/profile/**"))
                        .methods(List.of("GET"))
                        .build())
                .target(RouteTarget.builder().type(RouteTargetType.SERVICE)
                        .serviceId("edd-vmd-service").build())
                .build();
    }

}
