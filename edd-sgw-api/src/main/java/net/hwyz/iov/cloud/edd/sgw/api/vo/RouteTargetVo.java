package net.hwyz.iov.cloud.edd.sgw.api.vo;

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
public class RouteTargetVo {

    /** 目标类型 */
    private RouteTargetType type;

    /** 服务发现目标的服务ID */
    private String serviceId;

    /** 直连目标 URI */
    private String uri;

}
