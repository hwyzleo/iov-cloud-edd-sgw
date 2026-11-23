package net.hwyz.iov.cloud.edd.sgw.config;

import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;
import net.hwyz.iov.cloud.edd.sgw.common.Cidr;
import net.hwyz.iov.cloud.edd.sgw.domain.model.AuthPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteMatch;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.AuthPolicyRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.RouteRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * 内部服务域启动 fail-fast 测试（EDD-SGW-DSN-CR-003 R-7 / §19.3）。
 *
 * @author hwyz_leo
 */
class InternalDomainStartupValidatorTest {

    private final RouteRepository routeRepository = mock(RouteRepository.class);

    private final AuthPolicyRepository authPolicyRepository = mock(AuthPolicyRepository.class);

    @Test
    @DisplayName("存在 INTERNAL 路由但 internal-cidrs 为空时拒绝启动")
    void failsFastWithoutInternalCidrs() {
        InternalDomainStartupValidator validator = validator(new SgwProperties(), internalRoute());

        assertThatThrownBy(() -> validator.run(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("sgw.runtime.internal-cidrs")
                .hasMessageContaining("internal-route");
    }

    @Test
    @DisplayName("internal-cidrs 存在非法条目时拒绝启动")
    void failsFastWithIllegalCidr() {
        SgwProperties properties = new SgwProperties();
        properties.getRuntime().setInternalCidrs(List.of("10.0.0.0/8", "999.1.1.1"));
        InternalDomainStartupValidator validator = validator(properties, internalRoute());

        assertThatThrownBy(() -> validator.run(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("非法条目");
    }

    @Test
    @DisplayName("无 INTERNAL 路由时不要求 internal-cidrs")
    void noInternalRouteDoesNotRequireCidrs() {
        SgwProperties properties = new SgwProperties();
        RouteDefinition route = internalRoute();
        route.setAuthPolicyCode("anonymous");
        AuthPolicy anonymous = AuthPolicy.builder()
                .policyCode("anonymous").accessMode(AccessMode.ANONYMOUS).enabled(true).build().normalized();
        InternalDomainStartupValidator validator = validator(properties, route, anonymous);

        assertThatCode(() -> validator.run(null)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("配置齐备时启动通过")
    void startsWithCidrsConfigured() {
        SgwProperties properties = new SgwProperties();
        properties.getRuntime().setInternalCidrs(List.of("10.0.0.0/8", "fd00::/8"));
        InternalDomainStartupValidator validator = validator(properties, internalRoute());

        assertThatCode(() -> validator.run(null)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("R-1：internal-cidrs 含空白条目（SGW_INTERNAL_CIDRS 未设置展开出的空串）不视为非法")
    void blankCidrEntriesAreIgnored() {
        SgwProperties properties = new SgwProperties();
        properties.getRuntime().setInternalCidrs(List.of("", "  ", "10.0.0.0/8", ""));
        InternalDomainStartupValidator validator = validator(properties, internalRoute());

        assertThatCode(() -> validator.run(null)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("R-1：仅空白条目的 internal-cidrs 等价于未配置 → 严格模式（默认）仍拒绝启动")
    void blankOnlyCidrsTreatedAsMissingUnderStrictMode() {
        SgwProperties properties = new SgwProperties();
        properties.getRuntime().setInternalCidrs(List.of("", "   "));
        assertThat(properties.getRuntime().isInternalDomainStrict()).as("严格模式默认开启").isTrue();
        InternalDomainStartupValidator validator = validator(properties, internalRoute());

        assertThatThrownBy(() -> validator.run(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("sgw.runtime.internal-cidrs");
    }

    @Test
    @DisplayName("R-1：显式关闭 internal-domain-strict 时降级为 WARN 并放行启动")
    void nonStrictModeDegradesToWarning() {
        SgwProperties properties = new SgwProperties();
        properties.getRuntime().setInternalDomainStrict(false);
        InternalDomainStartupValidator validator = validator(properties, internalRoute());

        assertThatCode(() -> validator.run(null)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("R-1：非严格模式下非法条目仍拒绝启动（降级只针对缺失，不针对错误配置）")
    void nonStrictModeStillRejectsIllegalCidr() {
        SgwProperties properties = new SgwProperties();
        properties.getRuntime().setInternalDomainStrict(false);
        properties.getRuntime().setInternalCidrs(List.of("10.0.0.0/8", "999.1.1.1"));
        InternalDomainStartupValidator validator = validator(properties, internalRoute());

        assertThatThrownBy(() -> validator.run(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("非法条目");
    }

    @Test
    @DisplayName("R-2：internal-cidrs 单 IP 条目按地址语义命中（::1 对应展开形式来源）")
    void singleIpEntryMatchesEquivalentIpv6Form() {
        SgwProperties properties = new SgwProperties();
        properties.getRuntime().setInternalCidrs(List.of("::1"));
        InternalDomainStartupValidator validator = validator(properties, internalRoute());

        assertThatCode(() -> validator.run(null)).doesNotThrowAnyException();
        assertThat(Cidr.matches("::1", "0:0:0:0:0:0:0:1")).isTrue();
        assertThat(Cidr.matches("127.0.0.1", "::ffff:127.0.0.1")).isTrue();
    }

    private InternalDomainStartupValidator validator(SgwProperties properties, RouteDefinition route,
                                                     AuthPolicy... policies) {
        List<AuthPolicy> policyList = policies.length == 0 ? List.of(internalPolicy()) : List.of(policies);
        when(routeRepository.findAllValid()).thenReturn(List.of(route));
        when(authPolicyRepository.findAllValid()).thenReturn(policyList);
        return new InternalDomainStartupValidator(properties, routeRepository, authPolicyRepository);
    }

    private RouteDefinition internalRoute() {
        RouteDefinition route = RouteDefinition.builder()
                .routeCode("internal-route")
                .routeName("内部")
                .priority(900)
                .enabled(true)
                .match(RouteMatch.builder().paths(List.of("/api/service/activation/v1/**")).build())
                .authPolicyCode("internal-service")
                .build();
        return route;
    }

    private AuthPolicy internalPolicy() {
        return AuthPolicy.builder()
                .policyCode("internal-service")
                .accessMode(AccessMode.INTERNAL)
                .enabled(true)
                .build()
                .normalized();
    }

}
