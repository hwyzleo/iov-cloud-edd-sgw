package net.hwyz.iov.cloud.edd.sgw.domain.model;

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
public class RateLimitRule {

    private RateLimitDimension dimension;

    private Integer replenishPerSecond;

    private Integer burstCapacity;

    private RateLimitFailureMode failureMode;

}
