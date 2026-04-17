package net.hwyz.iov.cloud.edd.sgw.filter;

import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.common.constant.CustomHeaders;
import net.hwyz.iov.cloud.framework.common.constant.SecurityConstants;
import net.hwyz.iov.cloud.framework.common.enums.ClientType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
public class AuthenticationGatewayFilterFactory extends AbstractGatewayFilterFactory<AuthenticationGatewayFilterFactory.Config> {

    @Autowired
    @LoadBalanced
    private WebClient.Builder webClientBuilder;

    public AuthenticationGatewayFilterFactory() {
        super(Config.class);
    }

    private static final String JWKS_URI = "lb://sec-ciam/api/open/v1/oidc/jwks";
    private static final String ISSUER = "https://account.openiov.com";

    private RSAPublicKey cachedPublicKey;
    private final Map<String, Object> jwksCache = new ConcurrentHashMap<>();

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String clientType = exchange.getRequest().getHeaders().getFirst(CustomHeaders.CLIENT_TYPE);
            String clientId = exchange.getRequest().getHeaders().getFirst(CustomHeaders.CLIENT_ID);
            if (StrUtil.isBlank(clientType) || StrUtil.isBlank(clientId)) {
                log.warn("缺失客户端类型[{}]或客户端ID[{}]", clientType, clientId);
                exchange.getResponse().getHeaders().add(CustomHeaders.CONTENT_TYPE, "application/json");
                return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                        .bufferFactory().wrap(new JSONObject()
                                .set("code", 100000)
                                .set("message", "缺失客户端类型或客户端ID")
                                .set("ts", System.currentTimeMillis())
                                .toString().getBytes())));
            }
            ClientType type;
            try {
                type = ClientType.valueOf(clientType);
            } catch (IllegalArgumentException e) {
                log.warn("未知客户端类型[{}]", clientType);
                exchange.getResponse().getHeaders().add(CustomHeaders.CONTENT_TYPE, "application/json");
                return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                        .bufferFactory().wrap(new JSONObject()
                                .set("code", 100000)
                                .set("message", "未知客户端类型")
                                .set("ts", System.currentTimeMillis())
                                .toString().getBytes())));
            }
            switch (type) {
                case MOBILE -> {
                    String token = null;
                    String auth = exchange.getRequest().getHeaders().getFirst(SecurityConstants.AUTHORIZATION_HEADER);
                    if (StrUtil.isNotBlank(auth)) {
                        token = auth.substring(SecurityConstants.BEARER_PREFIX.length()).trim();
                    }
                    if (StrUtil.isBlank(token)) {
                        log.warn("手机客户端[{}]缺失客户端令牌[{}]", clientId, token);
                        exchange.getResponse().getHeaders().add(CustomHeaders.CONTENT_TYPE, "application/json");
                        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                                .bufferFactory().wrap(new JSONObject()
                                        .set("code", 100000)
                                        .set("message", "缺失客户端令牌")
                                        .set("ts", System.currentTimeMillis())
                                        .toString().getBytes())));
                    }
                    String finalToken = token;
                    return parseToken(token)
                            .flatMap(claims -> handleTokenClaims(exchange, chain, claims))
                            .onErrorResume(e -> handleTokenError(exchange, chain, finalToken, clientId, e));
                }
                case TBOX -> {
                    String vin = exchange.getRequest().getHeaders().getFirst(CustomHeaders.VIN);
                    if (StrUtil.isBlank(vin)) {
                        log.warn("车联终端[{}]缺失车架号[{}]", clientId, vin);
                        exchange.getResponse().getHeaders().add(CustomHeaders.CONTENT_TYPE, "application/json");
                        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                                .bufferFactory().wrap(new JSONObject()
                                        .set("code", 100000)
                                        .set("message", "缺失车架号")
                                        .set("ts", System.currentTimeMillis())
                                        .toString().getBytes())));
                    }
                    return chain.filter(exchange);
                }
            }
            return chain.filter(exchange);
        };
    }

    private Mono<Void> handleTokenClaims(ServerWebExchange exchange, GatewayFilterChain chain, Claims claims) {
        String userId = claims.getSubject();
        String clientIdFromToken = claims.get(SecurityConstants.CLIENT_ID, String.class);
        String scope = claims.get(SecurityConstants.SCOPE, String.class);
        String sessionId = claims.get(SecurityConstants.SESSION_ID, String.class);
        String deviceId = claims.get(SecurityConstants.DEVICE_ID, String.class);

        log.info("解析JWT Token成功 - userId:{}, clientId:{}, scope:{}, sessionId:{}, deviceId:{}",
                userId, clientIdFromToken, scope, sessionId, deviceId);

        ServerHttpRequest.Builder requestBuilder = exchange.getRequest().mutate();
        requestBuilder.header(SecurityConstants.USER_ID, userId != null ? userId : "");
        requestBuilder.header(SecurityConstants.CLIENT_ID, clientIdFromToken != null ? clientIdFromToken : "");
        requestBuilder.header(SecurityConstants.SCOPE, scope != null ? scope : "");
        requestBuilder.header(SecurityConstants.SESSION_ID, sessionId != null ? sessionId : "");
        if (deviceId != null && !deviceId.isEmpty()) {
            requestBuilder.header(SecurityConstants.DEVICE_ID, deviceId);
        }

        return chain.filter(exchange.mutate().request(requestBuilder.build()).build());
    }

    private Mono<Void> handleTokenError(ServerWebExchange exchange, GatewayFilterChain chain, String token, String clientId, Throwable e) {
        String errorMsg = e.getMessage();
        log.warn("JWT Token解析失败 - clientId:{}, error:{}", clientId, errorMsg);

        if (errorMsg != null && errorMsg.contains("signature")) {
            log.warn("签名验证失败，可能是公钥已过期，清除缓存并重试");
            cachedPublicKey = null;
            jwksCache.clear();
            return parseToken(token)
                    .flatMap(claims -> handleTokenClaims(exchange, chain, claims))
                    .onErrorResume(retryE -> {
                        log.warn("重试JWT Token解析也失败 - clientId:{}, error:{}", clientId, retryE.getMessage());
                        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
                        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                                .bufferFactory().wrap(new JSONObject()
                                        .set("code", 100000)
                                        .set("message", "令牌无效或已过期")
                                        .set("ts", System.currentTimeMillis())
                                        .toString().getBytes())));
                    });
        }

        exchange.getResponse().getHeaders().add(CustomHeaders.CONTENT_TYPE, "application/json");
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                .bufferFactory().wrap(new JSONObject()
                        .set("code", 100000)
                        .set("message", "令牌无效或已过期")
                        .set("ts", System.currentTimeMillis())
                        .toString().getBytes())));
    }

    @SuppressWarnings("unchecked")
    private Mono<Claims> parseToken(String token) {
        return getPublicKey()
                .flatMap(publicKey -> {
                    try {
                        Claims claims = Jwts.parser()
                                .verifyWith(publicKey)
                                .requireIssuer(ISSUER)
                                .build()
                                .parseSignedClaims(token)
                                .getPayload();
                        return Mono.just(claims);
                    } catch (Exception e) {
                        log.warn("JWT 解析失败: {}", e.getMessage());
                        return Mono.error(e);
                    }
                });
    }

    @SuppressWarnings("unchecked")
    private Mono<RSAPublicKey> getPublicKey() {
        if (cachedPublicKey != null) {
            log.info("使用缓存的公钥");
            return Mono.just(cachedPublicKey);
        }
        log.info("开始获取公钥");
        return fetchJwks()
                .flatMap(response -> {
                    Map<String, Object> data = (Map<String, Object>) response.get("data");
                    if (data == null || !data.containsKey("keys") || ((java.util.List<?>) data.get("keys")).isEmpty()) {
                        log.error("JWKS 格式错误或不包含 keys: {}", response);
                        return Mono.error(new IllegalStateException("JWKS 中没有找到公钥"));
                    }
                    Map<String, Object> key = (Map<String, Object>) ((java.util.List<?>) data.get("keys")).get(0);
                    return Mono.just(parseRSAPublicKey(key));
                })
                .doOnNext(publicKey -> this.cachedPublicKey = publicKey);
    }

    @SuppressWarnings("unchecked")
    private Mono<Map<String, Object>> fetchJwks() {
        if (!jwksCache.isEmpty()) {
            log.info("从缓存获取 JWKS");
            return (Mono<Map<String, Object>>) (Mono<?>) Mono.just(jwksCache);
        }
        log.info("从 sec-ciam 获取 JWKS");
        return webClientBuilder.build()
                .get()
                .uri(JWKS_URI)
                .retrieve()
                .bodyToMono(Map.class)
                .map(m -> (Map<String, Object>) m)
                .doOnNext(jwks -> {
                    log.info("获取到 JWKS: {}", jwks);
                    jwksCache.putAll(jwks);
                })
                .doOnError(e -> log.error("获取 JWKS 失败: {}", e.getMessage()));
    }

    private RSAPublicKey parseRSAPublicKey(Map<String, Object> jwk) {
        try {
            String kty = (String) jwk.get("kty");
            if (!"RSA".equals(kty)) {
                throw new IllegalArgumentException("不支持的密钥类型: " + kty);
            }
            String n = (String) jwk.get("n");
            String e = (String) jwk.get("e");
            byte[] nBytes = Base64.getUrlDecoder().decode(n);
            byte[] eBytes = Base64.getUrlDecoder().decode(e);
            if (nBytes.length > 0 && nBytes[0] == 0) {
                byte[] trimmed = new byte[nBytes.length - 1];
                System.arraycopy(nBytes, 1, trimmed, 0, trimmed.length);
                nBytes = trimmed;
            }
            if (eBytes.length > 0 && eBytes[0] == 0) {
                byte[] trimmed = new byte[eBytes.length - 1];
                System.arraycopy(eBytes, 1, trimmed, 0, trimmed.length);
                eBytes = trimmed;
            }
            BigInteger modulus = new BigInteger(1, nBytes);
            BigInteger exponent = new BigInteger(1, eBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
            return (RSAPublicKey) keyFactory.generatePublic(spec);
        } catch (Exception ex) {
            throw new IllegalStateException("解析 RSA 公钥失败", ex);
        }
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return List.of();
    }

    @Data
    @NoArgsConstructor
    public static class Config {
    }

}
