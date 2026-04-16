package net.hwyz.iov.cloud.edd.sgw.filter;

import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.common.constant.SecurityConstants;
import net.hwyz.iov.cloud.framework.common.enums.ClientType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static net.hwyz.iov.cloud.framework.common.enums.CustomHeaders.*;


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
            String clientType = exchange.getRequest().getHeaders().getFirst(CLIENT_TYPE.value);
            String clientId = exchange.getRequest().getHeaders().getFirst(CLIENT_ID.value);
            if (StrUtil.isBlank(clientType) || StrUtil.isBlank(clientId)) {
                log.warn("缺失客户端类型[{}]或客户端ID[{}]", clientType, clientId);
                exchange.getResponse().getHeaders().add("Content-Type", "application/json");
                return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                        .bufferFactory().wrap(new JSONObject()
                                .set("code", 100000)
                                .set("message", "缺失客户端类型或客户端ID")
                                .set("ts", System.currentTimeMillis())
                                .toString().getBytes())));
            }
            switch (ClientType.valueOf(clientType)) {
                case MOBILE -> {
                    String token = exchange.getRequest().getHeaders().getFirst(TOKEN.value);
                    if (StrUtil.isBlank(token)) {
                        log.warn("手机客户端[{}]缺失客户端令牌[{}]", clientId, token);
                        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
                        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                                .bufferFactory().wrap(new JSONObject()
                                        .set("code", 100000)
                                        .set("message", "缺失客户端令牌")
                                        .set("ts", System.currentTimeMillis())
                                        .toString().getBytes())));
                    }
                    return parseToken(token)
                            .flatMap(claims -> {
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
                            })
                            .onErrorResume(e -> {
                                log.warn("JWT Token解析失败 - clientId:{}, error:{}", clientId, e.getMessage());
                                exchange.getResponse().getHeaders().add("Content-Type", "application/json");
                                return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                                        .bufferFactory().wrap(new JSONObject()
                                                .set("code", 100000)
                                                .set("message", "令牌无效或已过期")
                                                .set("ts", System.currentTimeMillis())
                                                .toString().getBytes())));
                            });
                }
                case TBOX -> {
                    String vin = exchange.getRequest().getHeaders().getFirst(VIN.value);
                    if (StrUtil.isBlank(vin)) {
                        log.warn("车联终端[{}]缺失车架号[{}]", clientId, vin);
                        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
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
            log.warn("未知客户端类型[{}]", clientType);
            exchange.getResponse().getHeaders().add("Content-Type", "application/json");
            return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                    .bufferFactory().wrap(new JSONObject()
                            .set("code", 100000)
                            .set("message", "未知客户端类型")
                            .set("ts", System.currentTimeMillis())
                            .toString().getBytes())));
        };
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
            BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(n));
            BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(e));
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
