package net.hwyz.iov.cloud.edd.sgw.api.vo;

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
public class CanaryTargetVo {

    /** 目标类型 */
    private RouteTargetType type;

    /** 服务ID */
    private String serviceId;

    /** 直连 URI */
    private String uri;

    /** 权重（同一规则内合计必须为 100） */
    private Integer weight;

}
