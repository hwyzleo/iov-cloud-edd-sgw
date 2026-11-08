package net.hwyz.iov.cloud.edd.sgw.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.edd.sgw.api.enums.ConfigOperation;

/**
 * 不可变配置版本快照。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ConfigSnapshot {

    private Long versionNo;

    private ConfigOperation operation;

    private Long sourceVersionNo;

    private SgwConfiguration configuration;

    private String snapshotJson;

    private String checksum;

    private String description;

    private String createBy;

    private java.util.Date createTime;

}
