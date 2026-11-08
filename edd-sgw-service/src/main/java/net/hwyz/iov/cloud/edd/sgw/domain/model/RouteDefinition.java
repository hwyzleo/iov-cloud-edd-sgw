package net.hwyz.iov.cloud.edd.sgw.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 结构化路由定义。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RouteDefinition {

    private String routeCode;

    private String routeName;

    private String description;

    private Integer priority;

    private Boolean enabled;

    private RouteMatch match;

    private RouteTarget target;

    private RouteTransform transform;

    private String authPolicyCode;

    private String trafficPolicyCode;

    private String canaryPolicyCode;

    private Integer rowVersion;

    /**
     * 是否生效
     *
     * @return 启用且未删除
     */
    public boolean effective() {
        return Boolean.TRUE.equals(enabled);
    }

}
