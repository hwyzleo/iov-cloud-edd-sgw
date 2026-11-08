package net.hwyz.iov.cloud.edd.sgw.infrastructure.security;

import com.fasterxml.jackson.databind.JsonNode;
import io.netty.channel.ChannelOption;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.loadbalancer.DefaultRequest;
import org.springframework.cloud.loadbalancer.support.LoadBalancerClientFactory;
import org.springframework.cloud.client.loadbalancer.Response;
import org.springframework.cloud.client.loadbalancer.reactive.ReactiveLoadBalancer;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 按 kid 缓存的 CIAM JWKS 密钥库。
 * <p>
 * 支持未知 kid 触发刷新、主动刷新间隔与拉取失败时的缓存容忍时限。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class JwksKeyStore {

    private final SgwProperties properties;

    private final LoadBalancerClientFactory loadBalancerClientFactory;

    private final WebClient webClient;

    private final Map<String, CachedKey> cache = new ConcurrentHashMap<>();

    private volatile Mono<Map<String, RSAPublicKey>> inflight;

    private final Object fetchLock = new Object();

    public JwksKeyStore(SgwProperties properties, LoadBalancerClientFactory loadBalancerClientFactory) {
        this.properties = properties;
        this.loadBalancerClientFactory = loadBalancerClientFactory;
        SgwProperties.Ciam ciam = properties.getSecurity().getCiam();
        HttpClient httpClient = HttpClient.create()
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, ciam.getConnectTimeoutMillis())
                .responseTimeout(Duration.ofMillis(ciam.getResponseTimeoutMillis()));
        this.webClient = WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
    }

    /**
     * 获取指定 kid 的公钥
     *
     * @param kid 密钥ID
     * @return 公钥
     */
    public Mono<RSAPublicKey> getKey(String kid) {
        CachedKey cached = cache.get(kid);
        long now = System.currentTimeMillis();
        if (cached != null && now - cached.fetchedAt < refreshIntervalMillis()) {
            return Mono.just(cached.key);
        }
        return fetch().flatMap(keys -> {
            RSAPublicKey key = keys.get(kid);
            if (key != null) {
                cache.put(kid, new CachedKey(key, now));
                return Mono.just(key);
            }
            CachedKey fallback = cache.get(kid);
            if (fallback != null && now - fallback.fetchedAt < staleDeadlineMillis()) {
                log.warn("JWKS 中未找到 kid[{}]，在容忍时限内继续使用缓存密钥", kid);
                return Mono.just(fallback.key);
            }
            return Mono.error(new IllegalStateException("未找到可信签名密钥"));
        }).onErrorResume(error -> {
            CachedKey fallback = cache.get(kid);
            if (fallback != null && now - fallback.fetchedAt < staleDeadlineMillis()) {
                log.warn("JWKS 拉取失败，在容忍时限内继续使用缓存密钥: {}", error.getMessage());
                return Mono.just(fallback.key);
            }
            return Mono.error(error);
        });
    }

    private Mono<Map<String, RSAPublicKey>> fetch() {
        Mono<Map<String, RSAPublicKey>> existing = inflight;
        if (existing != null) {
            return existing;
        }
        synchronized (fetchLock) {
            if (inflight != null) {
                return inflight;
            }
            Mono<Map<String, RSAPublicKey>> mono = doFetch().cache();
            inflight = mono;
            return mono.doFinally(signal -> inflight = null);
        }
    }

    private Mono<Map<String, RSAPublicKey>> doFetch() {
        return resolveUri().flatMap(uri -> webClient.get().uri(uri).retrieve()
                .bodyToMono(JsonNode.class)
                .map(this::parseKeys));
    }

    private Mono<String> resolveUri() {
        String jwksUri = properties.getSecurity().getCiam().getJwksUri();
        if (!jwksUri.startsWith("lb://")) {
            return Mono.just(jwksUri);
        }
        String remainder = jwksUri.substring("lb://".length());
        int slash = remainder.indexOf('/');
        String serviceId = slash < 0 ? remainder : remainder.substring(0, slash);
        String path = slash < 0 ? "/" : remainder.substring(slash);
        ReactiveLoadBalancer<ServiceInstance> loadBalancer = loadBalancerClientFactory.getInstance(serviceId);
        return Mono.from(loadBalancer.choose(new DefaultRequest<>(new Object())))
                .flatMap(response -> {
                    if (response == null || !response.hasServer()) {
                        return Mono.error(new IllegalStateException("未找到 CIAM 服务实例"));
                    }
                    ServiceInstance instance = response.getServer();
                    String scheme = instance.isSecure() ? "https" : "http";
                    int port = instance.getPort() > 0 ? instance.getPort() : (instance.isSecure() ? 443 : 80);
                    return Mono.just(scheme + "://" + instance.getHost() + ":" + port + path);
                });
    }

    private Map<String, RSAPublicKey> parseKeys(JsonNode body) {
        JsonNode keys = body.get("keys");
        if (keys == null && body.has("data")) {
            keys = body.get("data").get("keys");
        }
        Map<String, RSAPublicKey> result = new HashMap<>();
        if (keys == null || !keys.isArray()) {
            throw new IllegalStateException("JWKS 响应格式非法");
        }
        for (JsonNode key : keys) {
            String kty = text(key, "kty");
            String kid = text(key, "kid");
            String alg = text(key, "alg");
            if (!"RSA".equals(kty) || kid == null || (alg != null && !"RS256".equals(alg))) {
                continue;
            }
            String n = text(key, "n");
            String e = text(key, "e");
            if (n == null || e == null) {
                continue;
            }
            RSAPublicKey publicKey = toPublicKey(n, e);
            if (publicKey != null) {
                result.put(kid, publicKey);
            }
        }
        if (result.isEmpty()) {
            throw new IllegalStateException("JWKS 中不存在可用的 RS256 密钥");
        }
        return result;
    }

    private String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    private RSAPublicKey toPublicKey(String modulus, String exponent) {
        try {
            BigInteger n = new BigInteger(1, Base64.getUrlDecoder().decode(modulus));
            BigInteger e = new BigInteger(1, Base64.getUrlDecoder().decode(exponent));
            return (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new RSAPublicKeySpec(n, e));
        } catch (Exception ex) {
            log.warn("解析 JWKS 公钥失败");
            return null;
        }
    }

    private long refreshIntervalMillis() {
        return properties.getSecurity().getCiam().getKeyRefreshIntervalSeconds() * 1000;
    }

    private long staleDeadlineMillis() {
        return properties.getSecurity().getCiam().getKeyStaleDeadlineSeconds() * 1000;
    }

    /**
     * 清空缓存（供测试使用）
     */
    public void clearCache() {
        cache.clear();
    }

    private record CachedKey(RSAPublicKey key, long fetchedAt) {
    }

}
