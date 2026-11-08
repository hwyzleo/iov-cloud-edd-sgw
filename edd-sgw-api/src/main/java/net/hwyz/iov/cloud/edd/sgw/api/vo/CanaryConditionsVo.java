package net.hwyz.iov.cloud.edd.sgw.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * 灰度规则条件。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CanaryConditionsVo {

    /** 客户端类型 */
    private List<String> clientTypes;

    /** 认证用户 */
    private List<String> userIds;

    /** 认证车辆 */
    private List<String> vehicleIds;

    /** 请求头条件 */
    private List<HeaderMatchVo> headers;

}
