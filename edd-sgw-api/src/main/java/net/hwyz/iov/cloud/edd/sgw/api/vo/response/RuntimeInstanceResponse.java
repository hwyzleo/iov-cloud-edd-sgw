package net.hwyz.iov.cloud.edd.sgw.api.vo.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.edd.sgw.api.enums.PublicationStatus;

import java.time.Instant;

/**
 * 运行时实例状态。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RuntimeInstanceResponse {

    /** 实例ID */
    private String instanceId;

    /** 实例地址 */
    private String address;

    /** 是否在服务发现中健康在线 */
    private Boolean discovered;

    /** 当前生效版本号 */
    private Long activeVersionNo;

    /** 最近发布ID */
    private String lastPublicationId;

    /** 最近发布状态 */
    private PublicationStatus lastPublicationStatus;

    /** 最近发布时间 */
    private Instant lastPublicationTime;

    /** 最近错误（已脱敏） */
    private String lastError;

}
