package net.hwyz.iov.cloud.edd.sgw.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.edd.sgw.api.enums.RouteTargetType;

/**
 * 路由目标。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RouteTarget {

    private RouteTargetType type;

    private String serviceId;

    private String uri;

    /**
     * 目标值：服务发现返回服务ID，直连返回 URI
     *
     * @return 目标值
     */
    public String targetValue() {
        if (type == RouteTargetType.SERVICE) {
            return serviceId;
        }
        if (type == null) {
            return uri;
        }
        return uri;
    }

}
