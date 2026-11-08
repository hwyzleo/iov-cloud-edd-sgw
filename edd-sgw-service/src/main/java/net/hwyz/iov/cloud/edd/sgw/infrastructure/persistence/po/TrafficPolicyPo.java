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
 * 流量治理策略草稿数据对象。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@TableName("sgw_traffic_policy")
public class TrafficPolicyPo {

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    private String policyCode;

    private String policyName;

    private String description;

    private Integer connectTimeoutMillis;

    private Integer responseTimeoutMillis;

    private String rateLimitsJson;

    private Integer maxConcurrentRequests;

    private String circuitBreakerJson;

    private String retryJson;

    private Boolean enabled;

    private Integer rowVersion;

    private Boolean rowValid;

    private String createBy;

    private Date createTime;

    private String modifyBy;

    private Date modifyTime;

}
