package net.hwyz.iov.cloud.edd.sgw.infrastructure.security;

import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.domain.model.AuthPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.AuthenticatedIdentity;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.CompiledRoute;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.CompiledSnapshot;
import net.hwyz.iov.cloud.framework.common.constant.CustomHeaders;
import net.hwyz.iov.cloud.framework.common.constant.SecurityConstants;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Locale;

/**
 * 路由级认证与授权。
 * <p>
 * 入站身份头一律移除，转发身份只来自已验签的 CIAM 声明。
 *
 * @author hwyz_leo
 */
@Component
public class RequestAuthorizer {

    private static final List<String> IDENTITY_HEADERS = List.of(
            CustomHeaders.USER_ID, CustomHeaders.USERNAME, CustomHeaders.USER_KEY,
            CustomHeaders.SESSION_ID, CustomHeaders.CLIENT_ID, CustomHeaders.CLIENT_TYPE,
            CustomHeaders.DEVICE_ID, CustomHeaders.VIN, CustomHeaders.SCOPE,
            SecurityConstants.FROM_SOURCE, "X-Permission", "X-Role", "X-Internal-Signature",
            "X-Internal-Client", "X-Internal-Timestamp", "X-Internal-Nonce", "X-Internal-Actor");

    private final CiamTokenVerifier tokenVerifier;

    public RequestAuthorizer(CiamTokenVerifier tokenVerifier) {
        this.tokenVerifier = tokenVerifier;
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
        AuthPolicy authPolicy = definition.getAuthPolicyCode() == null
                ? null : snapshot.getAuthPolicies().get(definition.getAuthPolicyCode());
        boolean protectedRoute = authPolicy != null && authPolicy.effective()
                && authPolicy.getAccessMode() == AccessMode.AUTHENTICATED;
        String declaredClientType = exchange.getRequest().getHeaders().getFirst(CustomHeaders.CLIENT_TYPE);
        String declaredClientId = exchange.getRequest().getHeaders().getFirst(CustomHeaders.CLIENT_ID);
        ServerWebExchange sanitized = sanitize(exchange, null);
        if (!protectedRoute) {
            return Mono.just(new AuthorizationResult(sanitized, null));
        }
        String token = bearerToken(sanitized.getRequest());
        if (token == null) {
            return Mono.error(new SgwException(SgwErrorCode.UNAUTHORIZED, "受保护路由缺少访问令牌"));
        }
        return tokenVerifier.verify(token)
                .map(identity -> {
                    checkDeclaredClientBinding(declaredClientType, declaredClientId, identity);
                    checkAuthorization(authPolicy, identity);
                    return new AuthorizationResult(sanitize(sanitized, identity), identity);
                });
    }

    private void checkDeclaredClientBinding(String declaredClientType, String declaredClientId,
                                           AuthenticatedIdentity identity) {
        if (declaredClientType != null && !declaredClientType.equalsIgnoreCase(identity.clientType())) {
            throw new SgwException(SgwErrorCode.UNAUTHORIZED, "客户端类型与令牌声明不匹配");
        }
        if (declaredClientId != null && !declaredClientId.equals(identity.clientId())) {
            throw new SgwException(SgwErrorCode.UNAUTHORIZED, "客户端ID与令牌声明不匹配");
        }
    }

    private void checkAuthorization(AuthPolicy authPolicy, AuthenticatedIdentity identity) {
        if (!authPolicy.getAllowedClientTypes().isEmpty()
                && authPolicy.getAllowedClientTypes().stream()
                .noneMatch(type -> type.equalsIgnoreCase(identity.clientType()))) {
            throw new SgwException(SgwErrorCode.FORBIDDEN, "客户端类型不被该路由允许");
        }
        for (String requiredScope : authPolicy.getRequiredScopes()) {
            if (!identity.scopes().contains(requiredScope)) {
                throw new SgwException(SgwErrorCode.FORBIDDEN, "缺少必需 scope: " + requiredScope);
            }
        }
        for (String permission : authPolicy.getRequiredPermissions()) {
            if (!identity.scopes().contains("perm:" + permission)) {
                throw new SgwException(SgwErrorCode.FORBIDDEN, "缺少必需权限点: " + permission);
            }
        }
    }

    private ServerWebExchange sanitize(ServerWebExchange exchange, AuthenticatedIdentity identity) {
        ServerHttpRequest.Builder builder = exchange.getRequest().mutate();
        builder.headers(headers -> {
            IDENTITY_HEADERS.forEach(headers::remove);
            if (identity != null) {
                headers.set(CustomHeaders.USER_ID, nullSafe(identity.subject()));
                headers.set(CustomHeaders.CLIENT_ID, nullSafe(identity.clientId()));
                headers.set(CustomHeaders.CLIENT_TYPE, nullSafe(identity.clientType()));
                headers.set(CustomHeaders.SESSION_ID, nullSafe(identity.sessionId()));
                headers.set(CustomHeaders.DEVICE_ID, nullSafe(identity.deviceId()));
                headers.set(CustomHeaders.SCOPE, String.join(" ", identity.scopes()));
                if (identity.vehicleId() != null) {
                    headers.set(CustomHeaders.VIN, identity.vehicleId());
                }
            }
        });
        return exchange.mutate().request(builder.build()).build();
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

    /**
     * 授权结果
     *
     * @param exchange 已清洗并写入身份头的交换
     * @param identity 认证身份，匿名请求为 null
     */
    public record AuthorizationResult(ServerWebExchange exchange, AuthenticatedIdentity identity) {
    }

}
