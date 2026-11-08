package net.hwyz.iov.cloud.edd.sgw.api.vo.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.edd.sgw.api.vo.RouteMatchVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.RouteTargetVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.RouteTransformVo;

import java.time.Instant;

/**
 * 路由详情。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RouteResponse {

    /** 路由编码 */
    private String routeCode;

    /** 路由名称 */
    private String routeName;

    /** 说明 */
    private String description;

    /** 优先级 */
    private Integer priority;

    /** 是否启用 */
    private Boolean enabled;

    /** 匹配条件 */
    private RouteMatchVo match;

    /** 目标 */
    private RouteTargetVo target;

    /** 请求变换 */
    private RouteTransformVo transform;

    /** 认证策略编码 */
    private String authPolicyCode;

    /** 流量策略编码 */
    private String trafficPolicyCode;

    /** 灰度策略编码 */
    private String canaryPolicyCode;

    /** 记录版本 */
    private Integer rowVersion;

    /** 创建者 */
    private String createBy;

    /** 创建时间 */
    private Instant createTime;

    /** 修改者 */
    private String modifyBy;

    /** 修改时间 */
    private Instant modifyTime;

}
