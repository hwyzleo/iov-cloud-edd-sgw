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
 * 配置工作区数据对象。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@TableName("sgw_config_workspace")
public class ConfigWorkspacePo {

    @TableId(value = "id", type = IdType.INPUT)
    private Long id;

    private Long draftRevision;

    private Long targetVersionNo;

    private Integer rowVersion;

    private String modifyBy;

    private Date modifyTime;

}
