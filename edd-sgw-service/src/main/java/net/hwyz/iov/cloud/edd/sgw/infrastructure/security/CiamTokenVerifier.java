package net.hwyz.iov.cloud.edd.sgw.infrastructure.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.AuthenticatedIdentity;
import net.hwyz.iov.cloud.framework.common.enums.ClientType;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * CIAM 令牌本地验签器。
 * <p>
 * 仅接受 RS256 签名与配置的签发者；客户端类型与车辆身份一律取自已验签声明。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class CiamTokenVerifier {

    private static final List<String> VEHICLE_CLIENT_TYPES = List.of("TBOX", "IDCM", "ADCM");

    private final SgwProperties properties;

    private final JwksKeyStore jwksKeyStore;

    public CiamTokenVerifier(SgwProperties properties, JwksKeyStore jwksKeyStore) {
        this.properties = properties;
        this.jwksKeyStore = jwksKeyStore;
    }

    /**
     * 校验令牌并建立认证身份
     *
     * @param token 访问令牌
     * @return 认证身份
     */
    public Mono<AuthenticatedIdentity> verify(String token) {
        return Mono.defer(() -> {
            TokenHeader header = parseHeader(token);
            if (!"RS256".equals(header.algorithm())) {
                return Mono.error(new SgwException(SgwErrorCode.UNAUTHORIZED, "不支持的令牌签名算法"));
            }
            if (header.kid() == null || header.kid().isBlank()) {
                return Mono.error(new SgwException(SgwErrorCode.UNAUTHORIZED, "令牌缺少签名密钥标识"));
            }
            return jwksKeyStore.getKey(header.kid())
                    .flatMap(key -> parseClaims(token, key))
                    .onErrorResume(error -> Mono.error(error instanceof SgwException sgwException
                            ? sgwException : new SgwException(SgwErrorCode.UNAUTHORIZED, "令牌校验失败", error)));
        });
    }

    private Mono<AuthenticatedIdentity> parseClaims(String token, RSAPublicKey key) {
        return Mono.fromCallable(() -> {
            Claims claims = Jwts.parser()
                    .verifyWith(key)
                    .requireIssuer(properties.getSecurity().getCiam().getIssuer())
                    .clockSkewSeconds(properties.getSecurity().getCiam().getClockSkewSeconds())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return toIdentity(claims);
        });
    }

    private AuthenticatedIdentity toIdentity(Claims claims) {
        String subject = required(claims, "sub");
        String clientId = required(claims, "client_id");
        String clientType = required(claims, "client_type");
        String deviceId = required(claims, "device_id");
        String sessionId = required(claims, "session_id");
        String normalizedClientType = clientType.toUpperCase(Locale.ROOT);
        try {
            ClientType.valueOf(normalizedClientType);
        } catch (IllegalArgumentException e) {
            throw new SgwException(SgwErrorCode.UNAUTHORIZED, "未知客户端类型");
        }
        String vehicleId = optional(claims, "vehicle_id");
        if (VEHICLE_CLIENT_TYPES.contains(normalizedClientType) && (vehicleId == null || vehicleId.isBlank())) {
            throw new SgwException(SgwErrorCode.UNAUTHORIZED, "车辆会话缺少车辆标识");
        }
        List<String> scopes = new ArrayList<>();
        String scope = optional(claims, "scope");
        if (scope != null) {
            for (String entry : scope.trim().split("\\s+")) {
                if (!entry.isBlank()) {
                    scopes.add(entry);
                }
            }
        }
        return new AuthenticatedIdentity(subject, clientId, normalizedClientType, deviceId, sessionId, vehicleId, scopes);
    }

    private String required(Claims claims, String name) {
        String value = optional(claims, name);
        if (value == null || value.isBlank()) {
            throw new SgwException(SgwErrorCode.UNAUTHORIZED, "令牌缺少必需声明: " + name);
        }
        return value;
    }

    private String optional(Claims claims, String name) {
        String value = claims.get(name, String.class);
        return value == null ? null : value.trim();
    }

    private TokenHeader parseHeader(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new SgwException(SgwErrorCode.UNAUTHORIZED, "令牌格式非法");
        }
        try {
            byte[] headerBytes = Base64.getUrlDecoder().decode(parts[0].getBytes(StandardCharsets.UTF_8));
            @SuppressWarnings("unchecked")
            Map<String, Object> header = Json.read(new String(headerBytes, StandardCharsets.UTF_8), Map.class);
            Object alg = header.get("alg");
            Object kid = header.get("kid");
            return new TokenHeader(alg == null ? null : alg.toString(), kid == null ? null : kid.toString());
        } catch (RuntimeException e) {
            throw new SgwException(SgwErrorCode.UNAUTHORIZED, "令牌头解析失败");
        }
    }

    private record TokenHeader(String algorithm, String kid) {
    }

}
