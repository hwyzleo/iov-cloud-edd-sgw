package net.hwyz.iov.cloud.edd.sgw.api.vo.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.edd.sgw.api.enums.ConfigOperation;

import java.time.Instant;

/**
 * 配置版本摘要。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ConfigVersionResponse {

    /** 版本号 */
    private Long versionNo;

    /** 操作类型 */
    private ConfigOperation operation;

    /** 来源版本号（回滚版本记录被复制的历史版本） */
    private Long sourceVersionNo;

    /** 快照校验和 */
    private String checksum;

    /** 说明 */
    private String description;

    /** 创建者 */
    private String createBy;

    /** 创建时间 */
    private Instant createTime;

    /** 是否为当前目标版本 */
    private Boolean current;

}
