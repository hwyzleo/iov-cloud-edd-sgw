package net.hwyz.iov.cloud.edd.sgw.api.vo.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.edd.sgw.api.enums.PublicationStatus;
import net.hwyz.iov.cloud.edd.sgw.api.enums.PublicationType;

import java.time.Instant;
import java.util.List;

/**
 * 发布记录详情。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PublicationResponse {

    /** 发布ID */
    private String publicationId;

    /** 目标版本号 */
    private Long targetVersionNo;

    /** 来源版本号 */
    private Long sourceVersionNo;

    /** 发布类型 */
    private PublicationType type;

    /** 发布状态 */
    private PublicationStatus status;

    /** 操作者 */
    private String actor;

    /** 说明 */
    private String comment;

    /** 创建时间 */
    private Instant createTime;

    /** 更新时间 */
    private Instant updateTime;

    /** 完成时间 */
    private Instant completedAt;

    /** 脱敏失败信息 */
    private String errorMessage;

    /** 各实例发布结果 */
    private List<InstancePublicationResponse> instances;

}
