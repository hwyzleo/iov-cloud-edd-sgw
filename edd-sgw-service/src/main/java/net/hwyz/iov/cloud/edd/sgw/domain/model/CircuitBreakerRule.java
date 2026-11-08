package net.hwyz.iov.cloud.edd.sgw.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 熔断规则。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CircuitBreakerRule {

    private Integer slidingWindowSize;

    private Integer minimumNumberOfCalls;

    private Float failureRateThreshold;

    private Float slowCallRateThreshold;

    private Long slowCallDurationMillis;

    private Long waitDurationInOpenStateMillis;

    private Integer permittedCallsInHalfOpenState;

}
