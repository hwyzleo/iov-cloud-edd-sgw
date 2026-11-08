package net.hwyz.iov.cloud.edd.sgw.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 熔断配置。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CircuitBreakerVo {

    /** 滑动窗口大小 */
    private Integer slidingWindowSize;

    /** 最小调用数 */
    private Integer minimumNumberOfCalls;

    /** 失败率阈值（百分比） */
    private Float failureRateThreshold;

    /** 慢调用率阈值（百分比） */
    private Float slowCallRateThreshold;

    /** 慢调用判定时长（毫秒） */
    private Long slowCallDurationMillis;

    /** 打开状态等待时长（毫秒） */
    private Long waitDurationInOpenStateMillis;

    /** 半开状态允许调用数 */
    private Integer permittedCallsInHalfOpenState;

}
