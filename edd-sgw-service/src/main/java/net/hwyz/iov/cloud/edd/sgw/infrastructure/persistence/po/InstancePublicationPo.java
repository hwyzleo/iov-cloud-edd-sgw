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
 * 逐实例发布结果数据对象。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@TableName("sgw_instance_publication")
public class InstancePublicationPo {

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    private String publicationId;

    private String instanceId;

    private Long targetVersionNo;

    private Long activeVersionNo;

    private String status;

    private String errorMessage;

    private Date reportTime;

    private Date createTime;

}
