package net.hwyz.iov.cloud.edd.sgw.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.edd.sgw.api.enums.RouteTargetType;

/**
 * 灰度目标。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CanaryTarget {

    private RouteTargetType type;

    private String serviceId;

    private String uri;

    private Integer weight;

    /**
     * 转换为路由目标
     *
     * @return 路由目标
     */
    public RouteTarget toRouteTarget() {
        return RouteTarget.builder().type(type).serviceId(serviceId).uri(uri).build();
    }

}
