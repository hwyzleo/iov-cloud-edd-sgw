package net.hwyz.iov.cloud.edd.sgw.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

/**
 * 流量治理策略。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TrafficPolicy {

    private String policyCode;

    private String policyName;

    private String description;

    private Integer connectTimeoutMillis;

    private Integer responseTimeoutMillis;

    private List<RateLimitRule> rateLimits;

    private Integer maxConcurrentRequests;

    private CircuitBreakerRule circuitBreaker;

    private RetryRule retry;

    private Boolean enabled;

    private Integer rowVersion;

    /**
     * 是否生效
     *
     * @return 是否启用
     */
    public boolean effective() {
        return Boolean.TRUE.equals(enabled);
    }

    /**
     * 归一化集合字段
     *
     * @return 自身
     */
    public TrafficPolicy normalized() {
        rateLimits = rateLimits == null ? new ArrayList<>() : rateLimits;
        if (retry != null) {
            retry.normalized();
        }
        return this;
    }

}
