package net.hwyz.iov.cloud.edd.sgw.api.vo.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.edd.sgw.api.vo.CircuitBreakerVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.RateLimitVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.RetryVo;

import java.util.List;

/**
 * 流量治理策略草稿保存请求。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TrafficPolicySaveRequest {

    /** 策略编码（不可变，永不复用） */
    private String policyCode;

    /** 策略名称 */
    @NotBlank(message = "策略名称不能为空")
    private String policyName;

    /** 说明 */
    private String description;

    /** 连接超时（毫秒） */
    private Integer connectTimeoutMillis;

    /** 响应超时（毫秒） */
    private Integer responseTimeoutMillis;

    /** 限流规则 */
    private List<RateLimitVo> rateLimits;

    /** 最大并发请求数 */
    private Integer maxConcurrentRequests;

    /** 熔断配置 */
    private CircuitBreakerVo circuitBreaker;

    /** 重试配置 */
    private RetryVo retry;

    /** 是否启用 */
    private Boolean enabled;

    /** 记录版本（更新时必填） */
    private Integer rowVersion;

}
