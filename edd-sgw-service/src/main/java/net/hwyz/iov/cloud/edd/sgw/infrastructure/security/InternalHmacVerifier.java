package net.hwyz.iov.cloud.edd.sgw.infrastructure.security;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
import org.springframework.data.redis.connection.ReactiveRedisConnection;
import org.springframework.data.redis.core.ReactiveRedisCallback;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;

/**
 * 内部管理请求 HMAC 校验（时间戳 + nonce 防重放）。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class InternalHmacVerifier {

    private final SgwProperties properties;

    private final ReactiveStringRedisTemplate redisTemplate;

    public InternalHmacVerifier(SgwProperties properties, ReactiveStringRedisTemplate redisTemplate) {
        this.properties = properties;
        this.redisTemplate = redisTemplate;
    }

    /**
     * 启动时打印已登记内部客户端的密钥指纹，便于与 edd-mpt 日志比对（不泄露密钥本身）。
     */
    @PostConstruct
    void logConfiguredClients() {
        SgwProperties.Internal internal = properties.getSecurity().getInternal();
        if (internal.getClients().isEmpty()) {
            log.warn("未配置任何内部客户端密钥（sgw.security.internal.clients），管理接口将拒绝所有调用");
            return;
        }
        internal.getClients().forEach((client, secret) -> log.info(
                "内部客户端密钥已加载: client={}, 密钥指纹={}, 密钥长度={}",
                client, fingerprint(secret), secret == null ? 0 : secret.length()));
    }

    /**
     * 启动探测防重放存储（Redis）连通性。
     * <p>
     * 配置文件加载顺序（如 bootstrap.yml 未引入 Nacos 的 redis.yaml）会导致落到默认 localhost:6379，
     * 这里提前暴露，避免直到调用管理接口才返回 SGW-503001。
     */
    @PostConstruct
    void probeReplayStore() {
        try {
            redisTemplate.execute((ReactiveRedisCallback<String>) ReactiveRedisConnection::ping)
                    .doOnNext(pong -> log.info("防重放存储(Redis)连通正常: {}", pong))
                    .doOnError(e -> log.error("防重放存储(Redis)不可达，内部管理接口将返回 SGW-503001，"
                            + "请检查 spring.data.redis 配置（Nacos redis.yaml 是否已加载）: {}", e.toString()))
                    .onErrorResume(e -> Mono.empty())
                    .subscribe();
        } catch (RuntimeException e) {
            log.error("防重放存储(Redis)初始化失败，内部管理接口将返回 SGW-503001: {}", e.toString());
        }
    }

    /**
     * 校验签名并返回操作者
     *
     * @param request  请求
     * @param bodyHash 请求体 SHA-256
     * @return 操作者
     */
    public Mono<String> verify(ServerHttpRequest request, String bodyHash) {
        SgwProperties.Internal internal = properties.getSecurity().getInternal();
        String client = request.getHeaders().getFirst(internal.getClientHeader());
        String timestamp = request.getHeaders().getFirst(internal.getTimestampHeader());
        String nonce = request.getHeaders().getFirst(internal.getNonceHeader());
        String signature = request.getHeaders().getFirst(internal.getSignatureHeader());
        if (client == null || timestamp == null || nonce == null || signature == null) {
            log.warn("内部请求缺少签名头: method={}, path={}, client={}, timestamp={}, nonce={}, signature={}",
                    request.getMethod().name(), request.getURI().getRawPath(),
                    client, timestamp, nonce, signature);
            return Mono.error(new SgwException(SgwErrorCode.UNAUTHORIZED, "缺少内部请求签名头"));
        }
        String secret = internal.getClients().get(client);
        if (secret == null || secret.isBlank()) {
            return Mono.error(new SgwException(SgwErrorCode.FORBIDDEN, "未知内部客户端"));
        }
        long ts;
        try {
            ts = Long.parseLong(timestamp.trim());
        } catch (NumberFormatException e) {
            return Mono.error(new SgwException(SgwErrorCode.UNAUTHORIZED, "内部请求时间戳非法"));
        }
        long window = internal.getClockSkewSeconds() * 1000;
        if (Math.abs(System.currentTimeMillis() - ts) > window) {
            return Mono.error(new SgwException(SgwErrorCode.UNAUTHORIZED, "内部请求时间戳超出允许窗口"));
        }
        String canonical = request.getMethod().name() + "\n"
                + request.getURI().getRawPath() + "\n"
                + bodyHash + "\n"
                + timestamp.trim() + "\n"
                + nonce.trim() + "\n"
                + client.trim();
        String expected = hmacSha256Hex(secret, canonical);
        if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                signature.trim().toLowerCase().getBytes(StandardCharsets.UTF_8))) {
            log.warn("内部请求签名不匹配: client={}, method={}, path={}, bodyHash={}, timestamp={}, nonce={},\n"
                            + "  期望签名(服务网关侧)={}, \n  实际签名(调用方)={}, \n  密钥指纹={},\n"
                            + "  签名串=[{}]",
                    client.trim(), request.getMethod().name(), request.getURI().getRawPath(), bodyHash,
                    timestamp.trim(), nonce.trim(), expected, signature.trim(), fingerprint(secret),
                    canonical.replace("\n", "|"));
            return Mono.error(new SgwException(SgwErrorCode.UNAUTHORIZED, "内部请求签名无效"));
        }
        log.debug("内部请求签名校验通过: client={}, path={}, 密钥指纹={}",
                client.trim(), request.getURI().getRawPath(), fingerprint(secret));
        String nonceKey = "sgw:admin:nonce:" + client.trim() + ":" + nonce.trim();
        return redisTemplate.opsForValue()
                .setIfAbsent(nonceKey, "1", Duration.ofSeconds(internal.getNonceTtlSeconds()))
                .map(acquired -> {
                    if (Boolean.FALSE.equals(acquired)) {
                        throw new SgwException(SgwErrorCode.UNAUTHORIZED, "内部请求已被重放");
                    }
                    String actor = request.getHeaders().getFirst(internal.getActorHeader());
                    return actor == null || actor.isBlank() ? client.trim() : actor.trim();
                })
                .onErrorMap(e -> {
                    if (e instanceof SgwException) {
                        return e;
                    }
                    log.error("内部请求防重放不可用: client={}, path={}, 原因: {}",
                            client.trim(), request.getURI().getRawPath(), e.toString(), e);
                    return new SgwException(SgwErrorCode.UPSTREAM_UNAVAILABLE, "内部请求防重放不可用", e);
                });
    }

    /**
     * 密钥指纹（SHA-256 前 8 位十六进制）。
     * <p>
     * 仅用于两端比对密钥是否一致，不泄露密钥本身；排查完成后建议移除相关日志。
     *
     * @param secret 密钥
     * @return 指纹
     */
    public static String fingerprint(String secret) {
        if (secret == null || secret.isBlank()) {
            return "-empty-";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(secret.getBytes(StandardCharsets.UTF_8))).substring(0, 8);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    /**
     * HMAC-SHA256
     *
     * @param secret 密钥
     * @param value  文本
     * @return 十六进制签名
     */
    public static String hmacSha256Hex(String secret, String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC 计算失败", e);
        }
    }

}
