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
 * 路由草稿数据对象。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@TableName("sgw_route")
public class RoutePo {

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    private String routeCode;

    private String routeName;

    private String description;

    private Integer priority;

    private Boolean enabled;

    private String matchJson;

    private String targetType;

    private String targetValue;

    private String clientTypes;

    private String transformJson;

    private String authPolicyCode;

    private String trafficPolicyCode;

    private String canaryPolicyCode;

    private Integer rowVersion;

    private Boolean rowValid;

    private String createBy;

    private Date createTime;

    private String modifyBy;

    private Date modifyTime;

}
