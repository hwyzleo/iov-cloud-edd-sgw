package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

import net.hwyz.iov.cloud.edd.sgw.api.enums.CanaryStableKey;
import net.hwyz.iov.cloud.edd.sgw.api.enums.MatchType;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryConditions;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryRule;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryTarget;
import net.hwyz.iov.cloud.edd.sgw.domain.model.HeaderMatch;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteTarget;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * 灰度目标选择：条件优先，加权目标使用确定性哈希保证粘性。
 *
 * @author hwyz_leo
 */
@Component
public class CanarySelector {

    private static final int BUCKETS = 10_000;

    /**
     * 选择灰度目标
     *
     * @param policy   灰度策略
     * @param route    路由
     * @param identity 认证身份（可空）
     * @param sourceIp 来源IP
     * @param request  请求
     * @return 灰度目标，未命中规则返回空
     */
    public Optional<RouteTarget> select(CanaryPolicy policy, RouteDefinition route, AuthenticatedIdentity identity,
                                        String sourceIp, ServerHttpRequest request) {
        if (policy == null || !policy.effective() || policy.getRules() == null || policy.getRules().isEmpty()) {
            return Optional.empty();
        }
        for (CanaryRule rule : policy.getRules()) {
            if (matches(rule.getConditions(), identity, request)) {
                String stableValue = stableValue(policy.getStableKey(), identity, sourceIp);
                int bucket = bucket(route.getRouteCode() + "|" + policy.getPolicyCode() + "|" + stableValue);
                RouteTarget target = chooseWeighted(rule.getTargets(), bucket);
                if (target != null) {
                    return Optional.of(target);
                }
            }
        }
        return Optional.empty();
    }

    private boolean matches(CanaryConditions conditions, AuthenticatedIdentity identity, ServerHttpRequest request) {
        if (conditions == null) {
            return false;
        }
        conditions.normalized();
        if (!conditions.getClientTypes().isEmpty()) {
            if (identity == null || identity.clientType() == null
                    || conditions.getClientTypes().stream()
                    .noneMatch(type -> type.equalsIgnoreCase(identity.clientType()))) {
                return false;
            }
        }
        if (!conditions.getUserIds().isEmpty()) {
            if (identity == null || identity.subject() == null || !conditions.getUserIds().contains(identity.subject())) {
                return false;
            }
        }
        if (!conditions.getVehicleIds().isEmpty()) {
            if (identity == null || identity.vehicleId() == null
                    || !conditions.getVehicleIds().contains(identity.vehicleId())) {
                return false;
            }
        }
        for (HeaderMatch header : conditions.getHeaders()) {
            String actual = request.getHeaders().getFirst(header.getName());
            if (actual == null) {
                return false;
            }
            if (header.getMatchType() == MatchType.REGEX) {
                if (!Pattern.compile(header.getValue()).matcher(actual).matches()) {
                    return false;
                }
            } else if (!header.getValue().equals(actual)) {
                return false;
            }
        }
        return true;
    }

    private String stableValue(CanaryStableKey key, AuthenticatedIdentity identity, String sourceIp) {
        if (key == null) {
            return sourceIp == null ? "unknown" : sourceIp;
        }
        return switch (key) {
            case VEHICLE_ID -> identity == null || identity.vehicleId() == null ? "unknown" : identity.vehicleId();
            case AUTHENTICATED_SUBJECT -> identity == null || identity.subject() == null ? "unknown" : identity.subject();
            case DEVICE_ID -> identity == null || identity.deviceId() == null ? "unknown" : identity.deviceId();
            case CLIENT_ID -> identity == null || identity.clientId() == null ? "unknown" : identity.clientId();
            case SOURCE_IP -> sourceIp == null ? "unknown" : sourceIp;
        };
    }

    private RouteTarget chooseWeighted(List<CanaryTarget> targets, int bucket) {
        int cumulative = 0;
        for (CanaryTarget target : targets) {
            Integer weight = target.getWeight();
            if (weight == null || weight <= 0) {
                continue;
            }
            cumulative += weight;
            if (bucket < cumulative * BUCKETS / 100) {
                return target.toRouteTarget();
            }
        }
        if (targets.isEmpty()) {
            return null;
        }
        CanaryTarget last = targets.get(targets.size() - 1);
        return last.toRouteTarget();
    }

    /**
     * 确定性哈希桶
     *
     * @param value 输入
     * @return [0,9999] 区间整数
     */
    public static int bucket(String value) {
        String digest = Json.sha256(value);
        long head = Long.parseLong(digest.substring(0, 8), 16);
        return (int) (head % BUCKETS);
    }

}
