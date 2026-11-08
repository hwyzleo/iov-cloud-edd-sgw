package net.hwyz.iov.cloud.edd.sgw.api.vo.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.edd.sgw.api.vo.RouteMatchVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.RouteTargetVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.RouteTransformVo;

/**
 * 结构化路由草稿保存请求。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RouteSaveRequest {

    /** 路由编码（不可变，永不复用） */
    private String routeCode;

    /** 路由名称 */
    @NotBlank(message = "路由名称不能为空")
    private String routeName;

    /** 说明 */
    private String description;

    /** 优先级，数值小者优先 */
    @NotNull(message = "优先级不能为空")
    private Integer priority;

    /** 是否启用 */
    private Boolean enabled;

    /** 匹配条件 */
    @NotNull(message = "匹配条件不能为空")
    private RouteMatchVo match;

    /** 目标 */
    @NotNull(message = "路由目标不能为空")
    private RouteTargetVo target;

    /** 请求变换 */
    private RouteTransformVo transform;

    /** 认证策略编码 */
    private String authPolicyCode;

    /** 流量策略编码 */
    private String trafficPolicyCode;

    /** 灰度策略编码 */
    private String canaryPolicyCode;

    /** 记录版本（更新时必填） */
    private Integer rowVersion;

}
