package net.hwyz.iov.cloud.edd.sgw.api.vo.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.edd.sgw.api.enums.InstancePublicationStatus;

import java.time.Instant;

/**
 * 单实例发布结果。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InstancePublicationResponse {

    /** 实例ID */
    private String instanceId;

    /** 目标版本号 */
    private Long targetVersionNo;

    /** 当前生效版本号 */
    private Long activeVersionNo;

    /** 状态 */
    private InstancePublicationStatus status;

    /** 脱敏错误信息 */
    private String errorMessage;

    /** 上报时间 */
    private Instant reportTime;

}
