package net.hwyz.iov.cloud.edd.sgw.infrastructure.resilience;

import net.hwyz.iov.cloud.edd.sgw.api.enums.RateLimitFailureMode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * 基于 Redis 令牌桶的集群限流器。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class ClusterRateLimiter {

    private static final RedisScript<Long> TOKEN_BUCKET = new DefaultRedisScript<>("""
            local tokens = redis.call('HGET', KEYS[1], 'tokens')
            local ts = redis.call('HGET', KEYS[1], 'ts')
            local now = tonumber(ARGV[3])
            local rate = tonumber(ARGV[1])
            local burst = tonumber(ARGV[2])
            if tokens == false then
              tokens = burst
              ts = now
            end
            tokens = tonumber(tokens)
            ts = tonumber(ts)
            local elapsed = math.max(0, now - ts)
            tokens = math.min(burst, tokens + elapsed * rate / 1000)
            local allowed = 0
            if tokens >= 1 then
              tokens = tokens - 1
              allowed = 1
            end
            redis.call('HSET', KEYS[1], 'tokens', tostring(tokens), 'ts', tostring(now))
            redis.call('PEXPIRE', KEYS[1], ARGV[4])
            return allowed
            """, Long.class);

    private final ReactiveStringRedisTemplate redisTemplate;

    public ClusterRateLimiter(ReactiveStringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * 尝试获取一个令牌
     *
     * @param key           限流键
     * @param replenish     每秒补充令牌数
     * @param burst         桶容量
     * @param failureMode   失败模式
     * @return 是否允许
     */
    public Mono<Boolean> tryAcquire(String key, int replenish, int burst, RateLimitFailureMode failureMode) {
        long now = System.currentTimeMillis();
        long ttl = Math.max(1000, (long) burst * 1000L / Math.max(1, replenish) * 2);
        return redisTemplate.execute(TOKEN_BUCKET, List.of(key), List.of(
                        String.valueOf(replenish), String.valueOf(burst), String.valueOf(now), String.valueOf(ttl)))
                .next()
                .map(result -> result != null && result == 1L)
                .onErrorResume(error -> {
                    if (failureMode == RateLimitFailureMode.FAIL_OPEN) {
                        log.warn("限流组件不可用，按 FAIL_OPEN 放行: {}", key);
                        return Mono.just(true);
                    }
                    return Mono.error(new SgwException(SgwErrorCode.UPSTREAM_UNAVAILABLE, "限流组件不可用", error));
                });
    }

}
