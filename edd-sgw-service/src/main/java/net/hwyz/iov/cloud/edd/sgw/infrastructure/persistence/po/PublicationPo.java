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
 * 发布记录数据对象。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@TableName("sgw_publication")
public class PublicationPo {

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    private String publicationId;

    private Long targetVersionNo;

    private Long sourceVersionNo;

    private String type;

    private String status;

    private String actor;

    private String comment;

    private String errorMessage;

    private Date createTime;

    private Date updateTime;

    private Date completedAt;

}
