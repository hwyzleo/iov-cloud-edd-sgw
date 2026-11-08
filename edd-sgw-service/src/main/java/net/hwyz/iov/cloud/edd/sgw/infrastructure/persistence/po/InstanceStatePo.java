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
 * 实例最新运行时状态数据对象。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@TableName("sgw_instance_state")
public class InstanceStatePo {

    @TableId(value = "instance_id", type = IdType.INPUT)
    private String instanceId;

    private Long activeVersionNo;

    private String lastPublicationId;

    private String status;

    private String lastError;

    private Date updateTime;

}
