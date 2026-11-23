package net.hwyz.iov.cloud.edd.sgw.security;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
import net.hwyz.iov.cloud.edd.sgw.domain.model.AuthPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.SgwConfiguration;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.AuthenticatedIdentity;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.CompiledRoute;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.CompiledSnapshot;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.SgwRouteMetrics;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.SourceIpResolver;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.security.CiamTokenVerifier;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.security.RequestAuthorizer;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.security.SgwHeaders;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 请求认证与身份头清洗测试（EDD-SGW-DSN-CR-002 / EDD-SGW-DSN-CR-003）。
 * <p>
 * CR-003 收敛：策略缺失/禁用/未知模式 fail-closed；{@code Idempotency-Key} 透传；
 * 拒绝/身份来源写入进程内指标。【设计纠错】内部服务间不经网关，故无 {@code INTERNAL} 判定链。
 *
 * @author hwyz_leo
 */
class RequestAuthorizerTest {

    private static final String POLICY = "vehicle-user";

    private static final String ANON_POLICY = "anon-ivi-auth";

    private static final String IDEMPOTENCY_VALUE = "idem-0001";

    private final AuthenticatedIdentity identity = new AuthenticatedIdentity("user-1", "client-1", "MOBILE",
            "device-1", "session-1", "VIN1", List.of("vehicle.read", "perm:edd:vehicle:read"));

    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();

    private final SgwRouteMetrics metrics = new SgwRouteMetrics(registry);

    @Test
    @DisplayName("匿名路由透传声明型元数据并标记 DECLARED，同时删除伪造的可信身份头")
    void anonymousRouteKeepsDeclaredMetadata() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/echo-anon")
                .header("X-Client-Id", "client-declared")
                .header("X-Client-Type", "MOBILE")
                .header("X-Device-Id", "device-declared")
                .header("X-Platform", "ios")
                .header("X-Os-Version", "18.0")
                .header("X-App-Version", "1.2.3")
                .header(SgwHeaders.IDEMPOTENCY_KEY, IDEMPOTENCY_VALUE)
                .header("X-User-Id", "forged-user")
                .header("X-Username", "forged-name")
                .header("X-User-Key", "forged-key")
                .header("X-Session-Id", "forged-session")
                .header("X-Vin", "FORGED-VIN")
                .header("X-Scope", "forged.scope")
                .header("from-source", "inner")
                .header("X-Permission", "forged.permission")
                .header("X-Role", "ADMIN")
                .header("X-Internal-Client", "mpt")
                .header("X-Internal-Signature", "forged-signature")
                .header("X-Identity-Source", SgwHeaders.IDENTITY_SOURCE_CIAM)
                .build());

        RequestAuthorizer.AuthorizationResult result = authorizer(identity)
                .authorize(exchange, snapshot(anonymousPolicy()), route(ANON_POLICY)).block();

        assertThat(result).isNotNull();
        assertThat(result.identity()).isNull();
        HttpHeaders headers = result.exchange().getRequest().getHeaders();
        assertThat(headers.getFirst("X-Client-Id")).isEqualTo("client-declared");
        assertThat(headers.getFirst("X-Client-Type")).isEqualTo("MOBILE");
        assertThat(headers.getFirst("X-Device-Id")).isEqualTo("device-declared");
        assertThat(headers.getFirst("X-Platform")).isEqualTo("ios");
        assertThat(headers.getFirst("X-Os-Version")).isEqualTo("18.0");
        assertThat(headers.getFirst("X-App-Version")).isEqualTo("1.2.3");
        assertThat(headers.getFirst(SgwHeaders.IDENTITY_SOURCE)).isEqualTo(SgwHeaders.IDENTITY_SOURCE_DECLARED);
        assertThat(headers.getFirst(SgwHeaders.IDEMPOTENCY_KEY))
                .as("幂等键不得参与可信头清洗").isEqualTo(IDEMPOTENCY_VALUE);
        for (String removed : List.of("X-User-Id", "X-Username", "X-User-Key", "X-Session-Id", "X-Vin", "X-Scope",
                "from-source", "X-Permission", "X-Role", "X-Internal-Client", "X-Internal-Signature")) {
            assertThat(headers.getFirst(removed)).as("匿名路由不应转发 %s", removed).isNull();
        }
        assertThat(registry.find(SgwRouteMetrics.POLICY_ANONYMOUS)
                .tag("policy_code", ANON_POLICY).counter().count()).isEqualTo(1.0);
        assertThat(registry.find(SgwRouteMetrics.IDENTITY_SOURCE)
                .tag("source", SgwHeaders.IDENTITY_SOURCE_DECLARED).counter().count()).isEqualTo(1.0);
    }

    @Test
    @DisplayName("匿名路由不转发空白声明值")
    void anonymousRouteDropsBlankDeclaredMetadata() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/echo-anon")
                .header("X-Device-Id", "   ")
                .header("X-Client-Id", "client-declared")
                .build());

        RequestAuthorizer.AuthorizationResult result = authorizer(identity)
                .authorize(exchange, snapshot(anonymousPolicy()), route(ANON_POLICY)).block();

        assertThat(result).isNotNull();
        HttpHeaders headers = result.exchange().getRequest().getHeaders();
        assertThat(headers.getFirst("X-Device-Id")).isNull();
        assertThat(headers.getFirst("X-Client-Id")).isEqualTo("client-declared");
    }

    @Test
    @DisplayName("路由未绑定认证授权策略时 fail-closed 返回 403")
    void routeWithoutPolicyIsRejected() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/echo-anon").build());

        assertThatThrownBy(() -> authorizer(identity)
                .authorize(exchange, snapshot(anonymousPolicy()), route(null)).block())
                .isInstanceOf(SgwException.class)
                .extracting(error -> ((SgwException) error).errorCode())
                .isEqualTo(SgwErrorCode.FORBIDDEN);
        assertThat(registry.find(SgwRouteMetrics.AUTH_REJECT)
                .tag("reject_reason", "NO_POLICY").tag("route_code", "echo").counter().count()).isEqualTo(1.0);
    }

    @Test
    @DisplayName("引用的策略不存在时 fail-closed 返回 403")
    void missingPolicyReferenceIsRejected() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/echo").build());

        assertThatThrownBy(() -> authorizer(identity)
                .authorize(exchange, snapshot(anonymousPolicy()), route("absent-policy")).block())
                .isInstanceOf(SgwException.class)
                .extracting(error -> ((SgwException) error).errorCode())
                .isEqualTo(SgwErrorCode.FORBIDDEN);
    }

    @Test
    @DisplayName("策略被禁用时 fail-closed 返回 403（不再回落匿名）")
    void disabledPolicyIsRejected() {
        AuthPolicy disabled = AuthPolicy.builder()
                .policyCode(ANON_POLICY)
                .accessMode(AccessMode.ANONYMOUS)
                .enabled(false)
                .build()
                .normalized();
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/echo-anon").build());

        assertThatThrownBy(() -> authorizer(identity)
                .authorize(exchange, snapshot(disabled), route(ANON_POLICY)).block())
                .isInstanceOf(SgwException.class)
                .extracting(error -> ((SgwException) error).errorCode())
                .isEqualTo(SgwErrorCode.FORBIDDEN);
        assertThat(registry.find(SgwRouteMetrics.AUTH_REJECT)
                .tag("reject_reason", "POLICY_DISABLED").tag("route_code", "echo").counter().count()).isEqualTo(1.0);
    }

    @Test
    @DisplayName("认证路由以令牌声明覆盖同名声明头并标记 CIAM，且保留幂等键")
    void protectedRouteOverridesDeclaredMetadata() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/echo")
                .header(HttpHeaders.AUTHORIZATION, "Bearer token")
                .header(SgwHeaders.IDEMPOTENCY_KEY, IDEMPOTENCY_VALUE)
                .header("X-Client-Id", "client-1")
                .header("X-Client-Type", "MOBILE")
                .header("X-Device-Id", "device-forged")
                .header("X-User-Id", "forged-user")
                .header("X-Vin", "FORGED-VIN")
                .header("X-Scope", "forged.scope")
                .header("X-Identity-Source", SgwHeaders.IDENTITY_SOURCE_DECLARED)
                .build());

        RequestAuthorizer.AuthorizationResult result = authorizer(identity)
                .authorize(exchange, snapshot(protectedPolicy()), route(POLICY)).block();

        assertThat(result).isNotNull();
        assertThat(result.identity()).isEqualTo(identity);
        HttpHeaders headers = result.exchange().getRequest().getHeaders();
        assertThat(headers.getFirst("X-Client-Id")).isEqualTo("client-1");
        assertThat(headers.getFirst("X-Client-Type")).isEqualTo("MOBILE");
        assertThat(headers.getFirst("X-Device-Id")).isEqualTo("device-1");
        assertThat(headers.getFirst("X-User-Id")).isEqualTo("user-1");
        assertThat(headers.getFirst("X-Session-Id")).isEqualTo("session-1");
        assertThat(headers.getFirst("X-Vin")).isEqualTo("VIN1");
        assertThat(headers.getFirst("X-Scope")).contains("vehicle.read").doesNotContain("forged");
        assertThat(headers.getFirst(SgwHeaders.IDENTITY_SOURCE)).isEqualTo(SgwHeaders.IDENTITY_SOURCE_CIAM);
        assertThat(headers.getFirst(SgwHeaders.IDEMPOTENCY_KEY))
                .as("幂等键不得参与可信头清洗").isEqualTo(IDEMPOTENCY_VALUE);
    }

    @Test
    @DisplayName("车机令牌访问车辆激活域仅由令牌 vehicle_id 注入 X-Vin")
    void iviRouteInjectsVinFromToken() {
        AuthenticatedIdentity ivi = new AuthenticatedIdentity("user-2", "ivi-capp", "IVI",
                "device-ivi", "session-ivi", "LZZIVI0000000001", List.of());
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/vehicle/activation/v1/session")
                .header(HttpHeaders.AUTHORIZATION, "Bearer token")
                .header("X-Vin", "FORGED-VIN")
                .build());

        RequestAuthorizer.AuthorizationResult result = authorizer(ivi)
                .authorize(exchange, snapshot(vehiclePolicy()), route(POLICY)).block();

        assertThat(result).isNotNull();
        assertThat(result.exchange().getRequest().getHeaders().getFirst("X-Vin"))
                .isEqualTo("LZZIVI0000000001");
    }

    @Test
    @DisplayName("MOBILE 令牌访问仅允许 IVI 的车辆激活域返回 403（无 vehicle_id 不放行）")
    void mobileTokenRejectedOnVehicleRoute() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/echo")
                .header(HttpHeaders.AUTHORIZATION, "Bearer token")
                .build());

        assertThatThrownBy(() -> authorizer(identity)
                .authorize(exchange, snapshot(vehiclePolicy()), route(POLICY)).block())
                .isInstanceOf(SgwException.class)
                .extracting(error -> ((SgwException) error).errorCode())
                .isEqualTo(SgwErrorCode.FORBIDDEN);
        assertThat(registry.find(SgwRouteMetrics.AUTH_REJECT)
                .tag("reject_reason", "CLIENT_TYPE").tag("route_code", "echo").counter().count()).isEqualTo(1.0);
    }

    @Test
    @DisplayName("认证路由缺少访问令牌返回 401 语义")
    void protectedRouteWithoutTokenIsRejected() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/echo")
                .header("X-Device-Id", "device-forged")
                .build());

        assertThatThrownBy(() -> authorizer(identity)
                .authorize(exchange, snapshot(protectedPolicy()), route(POLICY)).block())
                .isInstanceOf(SgwException.class)
                .extracting(error -> ((SgwException) error).errorCode())
                .isEqualTo(SgwErrorCode.UNAUTHORIZED);
    }

    @Test
    @DisplayName("认证路由声明客户端 ID 与令牌不一致返回 401 语义")
    void protectedRouteRejectsClientIdMismatch() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/echo")
                .header(HttpHeaders.AUTHORIZATION, "Bearer token")
                .header("X-Client-Id", "client-forged")
                .build());

        assertThatThrownBy(() -> authorizer(identity)
                .authorize(exchange, snapshot(protectedPolicy()), route(POLICY)).block())
                .isInstanceOf(SgwException.class)
                .extracting(error -> ((SgwException) error).errorCode())
                .isEqualTo(SgwErrorCode.UNAUTHORIZED);
    }

    @Test
    @DisplayName("认证路由声明客户端类型与令牌不一致返回 401 语义")
    void protectedRouteRejectsClientTypeMismatch() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/echo")
                .header(HttpHeaders.AUTHORIZATION, "Bearer token")
                .header("X-Client-Type", "IVI")
                .build());

        assertThatThrownBy(() -> authorizer(identity)
                .authorize(exchange, snapshot(protectedPolicy()), route(POLICY)).block())
                .isInstanceOf(SgwException.class)
                .extracting(error -> ((SgwException) error).errorCode())
                .isEqualTo(SgwErrorCode.UNAUTHORIZED);
    }

    private RequestAuthorizer authorizer(AuthenticatedIdentity verified) {
        return new RequestAuthorizer(new StubTokenVerifier(verified), metrics,
                new SourceIpResolver(new SgwProperties()));
    }

    private CompiledSnapshot snapshot(AuthPolicy... policies) {
        return new CompiledSnapshot(1L, "checksum", SgwConfiguration.builder()
                .authPolicies(List.of(policies))
                .build().normalized(), List.of(), Instant.now());
    }

    private CompiledRoute route(String authPolicyCode) {
        return new CompiledRoute(RouteDefinition.builder()
                .routeCode("echo")
                .routeName("回显")
                .priority(100)
                .enabled(true)
                .authPolicyCode(authPolicyCode)
                .build(), List.of(), List.of(), List.of(), null);
    }

    private AuthPolicy anonymousPolicy() {
        return AuthPolicy.builder()
                .policyCode(ANON_POLICY)
                .accessMode(AccessMode.ANONYMOUS)
                .enabled(true)
                .build()
                .normalized();
    }

    private AuthPolicy protectedPolicy() {
        return AuthPolicy.builder()
                .policyCode(POLICY)
                .accessMode(AccessMode.AUTHENTICATED)
                .allowedClientTypes(List.of("MOBILE"))
                .enabled(true)
                .build()
                .normalized();
    }

    private AuthPolicy vehiclePolicy() {
        return AuthPolicy.builder()
                .policyCode(POLICY)
                .accessMode(AccessMode.AUTHENTICATED)
                .allowedClientTypes(List.of("IVI"))
                .enabled(true)
                .build()
                .normalized();
    }

    private static final class StubTokenVerifier extends CiamTokenVerifier {

        private final AuthenticatedIdentity verified;

        private StubTokenVerifier(AuthenticatedIdentity verified) {
            super(null, null);
            this.verified = verified;
        }

        @Override
        public Mono<AuthenticatedIdentity> verify(String token) {
            return Mono.just(verified);
        }

    }

}
