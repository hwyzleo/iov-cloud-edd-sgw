package net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

/**
 * 不可变配置版本数据对象。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@TableName("sgw_config_version")
public class ConfigVersionPo {

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    private Long versionNo;

    private String operation;

    private Long sourceVersionNo;

    private String snapshotJson;

    private String checksum;

    private String description;

    private String createBy;

    private Date createTime;

}
