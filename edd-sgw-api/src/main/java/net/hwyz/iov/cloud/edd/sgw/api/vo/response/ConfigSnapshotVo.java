package net.hwyz.iov.cloud.edd.sgw.api.vo.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * 完整配置快照（结构化，不含任何密钥）。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ConfigSnapshotVo {

    /** 路由集合 */
    private List<RouteResponse> routes;

    /** 认证授权策略集合 */
    private List<AuthPolicyResponse> authPolicies;

    /** 流量治理策略集合 */
    private List<TrafficPolicyResponse> trafficPolicies;

    /** 灰度策略集合 */
    private List<CanaryPolicyResponse> canaryPolicies;

}
