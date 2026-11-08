package net.hwyz.iov.cloud.edd.sgw.domain;

import net.hwyz.iov.cloud.edd.sgw.api.enums.MatchType;
import net.hwyz.iov.cloud.edd.sgw.api.enums.RouteTargetType;
import net.hwyz.iov.cloud.edd.sgw.domain.model.HeaderMatch;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RewritePath;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteMatch;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteTarget;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteTransform;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.RouteValidator;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.ValidationResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 路由校验器测试。
 *
 * @author hwyz_leo
 */
class RouteValidatorTest {

    private final RouteValidator validator = new RouteValidator();

    @Test
    @DisplayName("合法路由通过校验")
    void validRoute() {
        ValidationResult result = validator.validate(route(RouteTargetType.SERVICE, "edd-vmd-service", null),
                Set.of("internal.local:8080"));
        assertThat(result.valid()).isTrue();
    }

    @Test
    @DisplayName("缺少路径、名称与优先级时报告字段错误")
    void missingRequiredFields() {
        RouteDefinition route = route(RouteTargetType.SERVICE, "edd-vmd-service", null);
        route.setRouteName(" ");
        route.setPriority(null);
        route.setMatch(RouteMatch.builder().paths(List.of()).build());
        ValidationResult result = validator.validate(route, Set.of());
        assertThat(result.valid()).isFalse();
        assertThat(result.errors()).extracting(net.hwyz.iov.cloud.edd.sgw.domain.validation.ValidationError::field)
                .contains("routeName", "priority", "match.paths");
    }

    @Test
    @DisplayName("serviceId 与 uri 互斥")
    void targetMutuallyExclusive() {
        RouteDefinition route = route(RouteTargetType.SERVICE, "edd-vmd-service", "http://internal.local:8080");
        ValidationResult result = validator.validate(route, Set.of("internal.local:8080"));
        assertThat(result.errors()).extracting(net.hwyz.iov.cloud.edd.sgw.domain.validation.ValidationError::field).contains("target.uri");
    }

    @Test
    @DisplayName("直连目标必须使用 HTTP/HTTPS 且在获批清单内")
    void directTargetRestrictions() {
        RouteDefinition notAllowlisted = route(RouteTargetType.HTTP, null, "http://evil.example.com:8080");
        ValidationResult result = validator.validate(notAllowlisted, Set.of("internal.local:8080"));
        assertThat(result.errors()).extracting(net.hwyz.iov.cloud.edd.sgw.domain.validation.ValidationError::field).contains("target.uri");

        RouteDefinition webSocket = route(RouteTargetType.HTTP, null, "ws://internal.local:8080");
        ValidationResult wsResult = validator.validate(webSocket, Set.of("internal.local:8080"));
        assertThat(wsResult.errors()).extracting(net.hwyz.iov.cloud.edd.sgw.domain.validation.ValidationError::field).contains("target.uri");

        RouteDefinition allowed = route(RouteTargetType.HTTPS, null, "https://api.internal.local:8443");
        ValidationResult allowedResult = validator.validate(allowed, Set.of("*.internal.local"));
        assertThat(allowedResult.valid()).isTrue();
    }

    @Test
    @DisplayName("逐跳请求头变换被拒绝")
    void hopByHopHeader() {
        RouteDefinition route = route(RouteTargetType.SERVICE, "edd-vmd-service", null);
        route.setTransform(RouteTransform.builder()
                .headersToAdd(Map.of("Connection", "close"))
                .headersToRemove(List.of("Transfer-Encoding"))
                .build());
        ValidationResult result = validator.validate(route, Set.of());
        assertThat(result.errors()).extracting(net.hwyz.iov.cloud.edd.sgw.domain.validation.ValidationError::field)
                .contains("transform.headersToAdd.Connection", "transform.headersToRemove[0]");
    }

    @Test
    @DisplayName("非法正则与未知客户端类型被拒绝")
    void invalidRegexAndClientType() {
        RouteDefinition route = route(RouteTargetType.SERVICE, "edd-vmd-service", null);
        route.getMatch().setHeaders(List.of(HeaderMatch.builder()
                .name("X-App-Version").matchType(MatchType.REGEX).value("[").build()));
        route.getMatch().setClientTypes(List.of("UNKNOWN"));
        ValidationResult result = validator.validate(route, Set.of());
        assertThat(result.errors()).extracting(net.hwyz.iov.cloud.edd.sgw.domain.validation.ValidationError::field)
                .contains("match.headers[0].value", "match.clientTypes[0]");
    }

    @Test
    @DisplayName("重写路径必须为正则且以斜杠开头")
    void rewritePathValidation() {
        RouteDefinition route = route(RouteTargetType.SERVICE, "edd-vmd-service", null);
        route.setTransform(RouteTransform.builder()
                .rewritePath(RewritePath.builder().pattern("([a-z").replacement("/x").build())
                .build());
        ValidationResult result = validator.validate(route, Set.of());
        assertThat(result.valid()).isFalse();
    }

    private RouteDefinition route(RouteTargetType type, String serviceId, String uri) {
        return RouteDefinition.builder()
                .routeCode("vehicle-profile")
                .routeName("车辆档案")
                .priority(100)
                .enabled(true)
                .match(RouteMatch.builder()
                        .paths(List.of("/vehicle/profile/**"))
                        .methods(List.of("GET"))
                        .build())
                .target(RouteTarget.builder().type(type).serviceId(serviceId).uri(uri).build())
                .build();
    }

}
