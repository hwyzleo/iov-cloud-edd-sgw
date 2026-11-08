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
 * 配置变更审计数据对象。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@TableName("sgw_config_change_log")
public class ConfigChangeLogPo {

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    private String actor;

    private String action;

    private String objectType;

    private String objectCode;

    private String beforeJson;

    private String afterJson;

    private String result;

    private String failureReason;

    private String requestId;

    private Date createTime;

}
