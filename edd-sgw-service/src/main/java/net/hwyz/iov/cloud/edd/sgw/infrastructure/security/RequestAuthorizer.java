package net.hwyz.iov.cloud.edd.sgw.infrastructure.security;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.domain.model.AuthPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.AuthenticatedIdentity;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.CompiledRoute;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.CompiledSnapshot;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.RequestAttributes;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.SgwRouteMetrics;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.SourceIpResolver;
import net.hwyz.iov.cloud.framework.common.constant.CustomHeaders;
import net.hwyz.iov.cloud.framework.common.constant.SecurityConstants;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

/**
 * 路由级认证与授权。
 * <p>
 * 入站头按两类处理（EDD-SGW-DSN-CR-002）：受信身份头一律移除，转发值只来自已验签的 CIAM 声明；
 * 声明型客户端与设备元数据在匿名请求上原样透传，在认证请求上以令牌声明覆盖，
 * 并由 {@link SgwHeaders#IDENTITY_SOURCE} 标明下游收到的身份来源。
 * <p>
 * EDD-SGW-DSN-CR-003：策略缺失 / 禁用 / 未知访问模式一律 fail-closed（{@code SGW-403001}），
 * 不再回落匿名；拒绝与身份来源写入进程内指标与脱敏审计字段（不含令牌、VIN 明文、签名原文）。
 * <p>
 * 【设计纠错】内部服务间调用经 Nacos + Feign 直连各微服务，不经过本网关，
 * 因此网关不存在「内部服务域」判定链与相应访问模式。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class RequestAuthorizer {

    private static final List<String> TRUSTED_IDENTITY_HEADERS = List.of(
            CustomHeaders.USER_ID, CustomHeaders.USERNAME, CustomHeaders.USER_KEY,
            CustomHeaders.SESSION_ID, CustomHeaders.VIN, CustomHeaders.SCOPE,
            SecurityConstants.FROM_SOURCE, "X-Permission", "X-Role", "X-Internal-Signature",
            "X-Internal-Client", "X-Internal-Timestamp", "X-Internal-Nonce", "X-Internal-Actor",
            SgwHeaders.IDENTITY_SOURCE);

    /**
     * 声明型元数据头：匿名请求原样透传，认证请求以令牌声明覆盖；网关自身不据此建立信任
     */
    private static final List<String> DECLARED_METADATA_HEADERS = List.of(
            CustomHeaders.CLIENT_ID, CustomHeaders.CLIENT_TYPE, CustomHeaders.DEVICE_ID);

    static {
        // Idempotency-Key 必须原样透传（EDD-SGW-DSN-CR-003）：不得进入可信头清洗或声明头覆盖清单
        if (TRUSTED_IDENTITY_HEADERS.contains(SgwHeaders.IDEMPOTENCY_KEY)
                || DECLARED_METADATA_HEADERS.contains(SgwHeaders.IDEMPOTENCY_KEY)) {
            throw new IllegalStateException("Idempotency-Key 不得参与可信头清洗或声明头覆盖");
        }
    }

    private final CiamTokenVerifier tokenVerifier;

    private final SgwRouteMetrics metrics;

    private final SourceIpResolver sourceIpResolver;

    public RequestAuthorizer(CiamTokenVerifier tokenVerifier, SgwRouteMetrics metrics,
                             SourceIpResolver sourceIpResolver) {
        this.tokenVerifier = tokenVerifier;
        this.metrics = metrics;
        this.sourceIpResolver = sourceIpResolver;
    }

    /**
     * 执行认证与授权
     *
     * @param exchange 交换
     * @param snapshot 快照
     * @param route    路由
     * @return 授权结果（包含身份与已清洗的交换）
     */
    public Mono<AuthorizationResult> authorize(ServerWebExchange exchange, CompiledSnapshot snapshot,
                                               CompiledRoute route) {
        RouteDefinition definition = route.getDefinition();
        String routeCode = definition.getRouteCode();
        String policyCode = definition.getAuthPolicyCode();
        AuthPolicy authPolicy = policyCode == null ? null : snapshot.getAuthPolicies().get(policyCode);
        if (authPolicy == null || authPolicy.getAccessMode() == null) {
            return reject(exchange, routeCode, policyCode, null, SgwErrorCode.FORBIDDEN,
                    RejectReason.NO_POLICY, "路由未绑定认证授权策略");
        }
        if (!authPolicy.effective()) {
            return reject(exchange, routeCode, policyCode, authPolicy.getAccessMode(),
                    SgwErrorCode.FORBIDDEN, RejectReason.POLICY_DISABLED, "认证授权策略不可用");
        }
        AccessMode mode = authPolicy.getAccessMode();
        return switch (mode) {
            case ANONYMOUS -> anonymous(exchange, authPolicy);
            case AUTHENTICATED -> authenticated(exchange, authPolicy, routeCode);
        };
    }

    private Mono<AuthorizationResult> anonymous(ServerWebExchange exchange, AuthPolicy authPolicy) {
        metrics.anonymousPolicy(authPolicy.getPolicyCode());
        metrics.identitySource(SgwHeaders.IDENTITY_SOURCE_DECLARED);
        // 匿名 ≠ 不清洗：伪造的受信身份头与内部签名头同样必须剔除（D-003-3）
        return Mono.just(new AuthorizationResult(sanitize(exchange, null, true), null));
    }

    private Mono<AuthorizationResult> authenticated(ServerWebExchange exchange, AuthPolicy authPolicy,
                                                    String routeCode) {
        String declaredClientType = exchange.getRequest().getHeaders().getFirst(CustomHeaders.CLIENT_TYPE);
        String declaredClientId = exchange.getRequest().getHeaders().getFirst(CustomHeaders.CLIENT_ID);
        String declaredDeviceId = exchange.getRequest().getHeaders().getFirst(CustomHeaders.DEVICE_ID);
        ServerWebExchange sanitized = sanitize(exchange, null, false);
        String token = bearerToken(sanitized.getRequest());
        if (token == null) {
            return reject(exchange, routeCode, authPolicy.getPolicyCode(), AccessMode.AUTHENTICATED,
                    SgwErrorCode.UNAUTHORIZED, RejectReason.NO_TOKEN, "受保护路由缺少访问令牌");
        }
        return tokenVerifier.verify(token)
                .map(identity -> {
                    checkDeclaredClientBinding(declaredClientType, declaredClientId, identity, authPolicy, routeCode);
                    checkAuthorization(authPolicy, identity, routeCode);
                    warnDeclaredDeviceMismatch(declaredDeviceId, identity);
                    metrics.identitySource(SgwHeaders.IDENTITY_SOURCE_CIAM);
                    return new AuthorizationResult(sanitize(sanitized, identity, true), identity);
                })
                .onErrorMap(SgwException.class, error -> {
                    if (error.errorCode() == SgwErrorCode.UNAUTHORIZED) {
                        metrics.authReject(RejectReason.INVALID_TOKEN, routeCode);
                    }
                    return error;
                });
    }

    private String resolveSourceIp(ServerWebExchange exchange) {
        Object attribute = exchange.getAttributes().get(RequestAttributes.SOURCE_IP);
        if (attribute instanceof String resolved && !resolved.isBlank()) {
            return resolved;
        }
        return sourceIpResolver.resolve(exchange.getRequest());
    }

    private Mono<AuthorizationResult> reject(ServerWebExchange exchange, String routeCode, String policyCode,
                                             AccessMode mode, SgwErrorCode errorCode, RejectReason reason,
                                             String message) {
        metrics.authReject(reason, routeCode);
        log.warn("event=sgw_auth_reject requestId={} routeCode={} policyCode={} accessMode={} identitySource={} "
                        + "rejectReason={} sourceIpHash={}", requestId(exchange), routeCode,
                policyCode, mode, identitySourceLabel(exchange), reason, sourceIpHash(resolveSourceIp(exchange)));
        // 拒绝路径同样先清洗受信头，保证任何响应/日志都不携带入站身份头
        return Mono.error(new SgwException(errorCode, message));
    }

    private void checkDeclaredClientBinding(String declaredClientType, String declaredClientId,
                                            AuthenticatedIdentity identity, AuthPolicy authPolicy,
                                            String routeCode) {
        if (declaredClientType != null && !declaredClientType.equalsIgnoreCase(identity.clientType())) {
            metrics.authReject(RejectReason.CLIENT_TYPE, routeCode);
            throw new SgwException(SgwErrorCode.UNAUTHORIZED, "客户端类型与令牌声明不匹配");
        }
        if (declaredClientId != null && !declaredClientId.equals(identity.clientId())) {
            metrics.authReject(RejectReason.INVALID_TOKEN, routeCode);
            throw new SgwException(SgwErrorCode.UNAUTHORIZED, "客户端ID与令牌声明不匹配");
        }
    }

    private void checkAuthorization(AuthPolicy authPolicy, AuthenticatedIdentity identity, String routeCode) {
        if (!authPolicy.getAllowedClientTypes().isEmpty()
                && authPolicy.getAllowedClientTypes().stream()
                .noneMatch(type -> type.equalsIgnoreCase(identity.clientType()))) {
            metrics.authReject(RejectReason.CLIENT_TYPE, routeCode);
            throw new SgwException(SgwErrorCode.FORBIDDEN, "客户端类型不被该路由允许");
        }
        for (String requiredScope : authPolicy.getRequiredScopes()) {
            if (!identity.scopes().contains(requiredScope)) {
                metrics.authReject(RejectReason.SCOPE, routeCode);
                throw new SgwException(SgwErrorCode.FORBIDDEN, "缺少必需 scope: " + requiredScope);
            }
        }
        for (String permission : authPolicy.getRequiredPermissions()) {
            if (!identity.scopes().contains("perm:" + permission)) {
                metrics.authReject(RejectReason.PERMISSION, routeCode);
                throw new SgwException(SgwErrorCode.FORBIDDEN, "缺少必需权限点: " + permission);
            }
        }
    }

    private ServerWebExchange sanitize(ServerWebExchange exchange, AuthenticatedIdentity identity,
                                       boolean writeIdentitySource) {
        ServerHttpRequest.Builder builder = exchange.getRequest().mutate();
        builder.headers(headers -> {
            TRUSTED_IDENTITY_HEADERS.forEach(headers::remove);
            // 幂等键属调用方业务语义（同一意图的传输重试），不参与清洗，原样透传
            // 不变式由静态初始化块强制（见 HEADER_INVARIANTS）
            if (identity == null) {
                DECLARED_METADATA_HEADERS.forEach(name -> removeIfBlank(headers, name));
                if (writeIdentitySource) {
                    headers.set(SgwHeaders.IDENTITY_SOURCE, SgwHeaders.IDENTITY_SOURCE_DECLARED);
                }
                return;
            }
            headers.set(CustomHeaders.USER_ID, nullSafe(identity.subject()));
            headers.set(CustomHeaders.CLIENT_ID, nullSafe(identity.clientId()));
            headers.set(CustomHeaders.CLIENT_TYPE, nullSafe(identity.clientType()));
            headers.set(CustomHeaders.SESSION_ID, nullSafe(identity.sessionId()));
            headers.set(CustomHeaders.DEVICE_ID, nullSafe(identity.deviceId()));
            headers.set(CustomHeaders.SCOPE, String.join(" ", identity.scopes()));
            if (identity.vehicleId() != null) {
                headers.set(CustomHeaders.VIN, identity.vehicleId());
            }
            if (writeIdentitySource) {
                headers.set(SgwHeaders.IDENTITY_SOURCE, SgwHeaders.IDENTITY_SOURCE_CIAM);
            }
        });
        return exchange.mutate().request(builder.build()).build();
    }

    private void removeIfBlank(HttpHeaders headers, String name) {
        String value = headers.getFirst(name);
        if (value != null && value.isBlank()) {
            headers.remove(name);
        }
    }

    private void warnDeclaredDeviceMismatch(String declaredDeviceId, AuthenticatedIdentity identity) {
        if (declaredDeviceId == null || declaredDeviceId.isBlank() || identity.deviceId() == null
                || declaredDeviceId.equals(identity.deviceId())) {
            return;
        }
        // 声明值与令牌不一致时以令牌为准，仅记录不含令牌内容的告警
        log.warn("客户端声明的设备标识与令牌不一致，已按令牌声明转发, clientType={}, clientId={}",
                identity.clientType(), identity.clientId());
    }

    private String bearerToken(ServerHttpRequest request) {
        String authorization = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith(SecurityConstants.BEARER_PREFIX)) {
            return null;
        }
        String token = authorization.substring(SecurityConstants.BEARER_PREFIX.length()).trim();
        return token.isEmpty() ? null : token;
    }

    private String nullSafe(String value) {
        return value == null ? "" : value;
    }

    private String requestId(ServerWebExchange exchange) {
        Object requestId = exchange.getAttributes().get(RequestAttributes.REQUEST_ID);
        return requestId == null ? "-" : String.valueOf(requestId);
    }

    private String identitySourceLabel(ServerWebExchange exchange) {
        String source = exchange.getRequest().getHeaders().getFirst(SgwHeaders.IDENTITY_SOURCE);
        return source == null || source.isBlank() ? "NONE" : source.toUpperCase(Locale.ROOT);
    }

    private String sourceIpHash(String sourceIp) {
        if (sourceIp == null || sourceIp.isBlank()) {
            return "-";
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(sourceIp.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest).substring(0, 8);
        } catch (Exception e) {
            return "-";
        }
    }

    /**
     * 授权结果
     *
     * @param exchange 已清洗并写入身份头的交换
     * @param identity 认证身份，匿名请求为 null
     */
    public record AuthorizationResult(ServerWebExchange exchange, AuthenticatedIdentity identity) {
    }

}
