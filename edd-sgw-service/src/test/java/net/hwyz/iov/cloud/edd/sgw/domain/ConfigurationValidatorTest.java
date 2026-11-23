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
                .enabled(true)
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

    @Test
    @DisplayName("路由未绑定认证授权策略时不能使用灰度策略（去匿名缺省）")
    void canaryRequiresEffectivePolicy() {
        RouteDefinition route = route("route-a", 100);
        route.setCanaryPolicyCode("canary");
        CanaryPolicy canaryPolicy = canaryPolicy();
        SgwConfiguration configuration = SgwConfiguration.builder()
                .routes(List.of(route))
                .canaryPolicies(List.of(canaryPolicy))
                .build();
        ValidationResult result = validator.validate(configuration);
        assertThat(result.valid()).isFalse();
        assertThat(result.errors()).extracting(ValidationError::field)
                .contains("routes[route-a].authPolicyCode");
        assertThat(result.message()).contains("路由未绑定有效认证授权策略");
    }

    @Test
    @DisplayName("INTERNAL 路由前缀必须在已登记清单内")
    void internalRoutePrefixWhitelist() {
        properties.getRuntime().setInternalCidrs(List.of("10.0.0.0/8"));
        RouteDefinition route = route("/api/service/activation/v1/**");
        route.setAuthPolicyCode("internal");
        SgwConfiguration configuration = SgwConfiguration.builder()
                .routes(List.of(route))
                .authPolicies(List.of(internalPolicy()))
                .build();
        assertThat(validator.validate(configuration).valid()).isTrue();

        RouteDefinition rogue = route("/api/service/unknown/v1/**");
        rogue.setAuthPolicyCode("internal");
        SgwConfiguration rogueConfiguration = SgwConfiguration.builder()
                .routes(List.of(rogue))
                .authPolicies(List.of(internalPolicy()))
                .build();
        ValidationResult result = validator.validate(rogueConfiguration);
        assertThat(result.valid()).isFalse();
        assertThat(result.errors()).extracting(ValidationError::field)
                .contains("routes[route-a].match.paths");
    }

    @Test
    @DisplayName("存在 INTERNAL 路由但未配置 internal-cidrs 时拒绝发布")
    void internalRequiresSourceCidrs() {
        RouteDefinition route = route("/api/service/activation/v1/**");
        route.setAuthPolicyCode("internal");
        SgwConfiguration configuration = SgwConfiguration.builder()
                .routes(List.of(route))
                .authPolicies(List.of(internalPolicy()))
                .build();
        ValidationResult result = validator.validate(configuration);
        assertThat(result.valid()).isFalse();
        assertThat(result.errors()).extracting(ValidationError::field).contains("sgw.runtime.internal-cidrs");
    }

    @Test
    @DisplayName("internal-cidrs 中的非法条目在发布期即被拒绝")
    void internalCidrsMustBeParsable() {
        properties.getRuntime().setInternalCidrs(List.of("10.0.0.0/33", "not-an-ip"));
        RouteDefinition route = route("/api/service/activation/v1/**");
        route.setAuthPolicyCode("internal");
        SgwConfiguration configuration = SgwConfiguration.builder()
                .routes(List.of(route))
                .authPolicies(List.of(internalPolicy()))
                .build();
        ValidationResult result = validator.validate(configuration);
        assertThat(result.errors()).extracting(ValidationError::field)
                .contains("sgw.runtime.internal-cidrs[0]", "sgw.runtime.internal-cidrs[1]");
    }

    private RouteDefinition route(String path) {
        RouteDefinition route = route("route-a", 100);
        route.setMatch(RouteMatch.builder().paths(List.of(path)).methods(List.of("GET")).build());
        return route;
    }

    private AuthPolicy internalPolicy() {
        return AuthPolicy.builder()
                .policyCode("internal")
                .policyName("内部服务域")
                .accessMode(AccessMode.INTERNAL)
                .enabled(true)
                .build()
                .normalized();
    }

    private CanaryPolicy canaryPolicy() {
        return CanaryPolicy.builder()
                .policyCode("canary")
                .policyName("灰度")
                .stableKey(CanaryStableKey.SOURCE_IP)
                .enabled(true)
                .rules(List.of(CanaryRule.builder()
                        .priority(1)
                        .conditions(CanaryConditions.builder().clientTypes(List.of("MOBILE")).build())
                        .targets(List.of(CanaryTarget.builder()
                                .type(RouteTargetType.SERVICE)
                                .serviceId("edd-vmd")
                                .weight(100)
                                .build()))
                        .build()))
                .build();
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
                .authPolicyCode("anonymous")
                .build();
    }

}
