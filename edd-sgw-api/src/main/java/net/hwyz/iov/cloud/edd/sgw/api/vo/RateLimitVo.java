package net.hwyz.iov.cloud.edd.sgw.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.edd.sgw.api.enums.RateLimitDimension;
import net.hwyz.iov.cloud.edd.sgw.api.enums.RateLimitFailureMode;

/**
 * 限流规则。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RateLimitVo {

    /** 限流维度 */
    private RateLimitDimension dimension;

    /** 每秒补充令牌数 */
    private Integer replenishPerSecond;

    /** 桶容量 */
    private Integer burstCapacity;

    /** 失败模式 */
    private RateLimitFailureMode failureMode;

}
