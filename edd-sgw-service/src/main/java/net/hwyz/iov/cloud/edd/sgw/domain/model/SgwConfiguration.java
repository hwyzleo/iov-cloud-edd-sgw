package net.hwyz.iov.cloud.edd.sgw.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * 完整网关配置快照（路由与策略的不可变载体）。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SgwConfiguration {

    private List<RouteDefinition> routes;

    private List<AuthPolicy> authPolicies;

    private List<TrafficPolicy> trafficPolicies;

    private List<CanaryPolicy> canaryPolicies;

    /**
     * 归一化集合
     *
     * @return 自身
     */
    public SgwConfiguration normalized() {
        routes = routes == null ? new ArrayList<>() : routes;
        authPolicies = authPolicies == null ? new ArrayList<>() : authPolicies;
        trafficPolicies = trafficPolicies == null ? new ArrayList<>() : trafficPolicies;
        canaryPolicies = canaryPolicies == null ? new ArrayList<>() : canaryPolicies;
        routes.forEach(route -> {
            if (route.getMatch() != null) {
                route.getMatch().normalized();
            }
            if (route.getTransform() != null) {
                route.getTransform().normalized();
            }
        });
        authPolicies.forEach(AuthPolicy::normalized);
        trafficPolicies.forEach(TrafficPolicy::normalized);
        canaryPolicies.forEach(CanaryPolicy::normalized);
        return this;
    }

    /**
     * 路由索引
     *
     * @return 编码到路由的映射
     */
    public Map<String, RouteDefinition> routeIndex() {
        return index(routes, RouteDefinition::getRouteCode);
    }

    /**
     * 认证策略索引
     *
     * @return 编码到策略的映射
     */
    public Map<String, AuthPolicy> authPolicyIndex() {
        return index(authPolicies, AuthPolicy::getPolicyCode);
    }

    /**
     * 流量策略索引
     *
     * @return 编码到策略的映射
     */
    public Map<String, TrafficPolicy> trafficPolicyIndex() {
        return index(trafficPolicies, TrafficPolicy::getPolicyCode);
    }

    /**
     * 灰度策略索引
     *
     * @return 编码到策略的映射
     */
    public Map<String, CanaryPolicy> canaryPolicyIndex() {
        return index(canaryPolicies, CanaryPolicy::getPolicyCode);
    }

    private <T> Map<String, T> index(List<T> values, Function<T, String> key) {
        Map<String, T> result = new LinkedHashMap<>();
        if (values != null) {
            values.forEach(value -> {
                String code = key.apply(value);
                if (code != null) {
                    result.put(code, value);
                }
            });
        }
        return result;
    }

}
