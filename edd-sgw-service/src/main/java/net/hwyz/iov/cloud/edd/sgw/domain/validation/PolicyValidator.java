package net.hwyz.iov.cloud.edd.sgw.domain.validation;

import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;
import net.hwyz.iov.cloud.edd.sgw.api.enums.RateLimitDimension;
import net.hwyz.iov.cloud.edd.sgw.api.enums.RateLimitFailureMode;
import net.hwyz.iov.cloud.edd.sgw.domain.model.AuthPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryConditions;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryRule;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryTarget;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CircuitBreakerRule;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RateLimitRule;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RetryRule;
import net.hwyz.iov.cloud.edd.sgw.domain.model.TrafficPolicy;
import net.hwyz.iov.cloud.framework.common.enums.ClientType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 治理策略校验器。
 *
 * @author hwyz_leo
 */
@Component
public class PolicyValidator {

    private static final Set<String> CLIENT_TYPES = Arrays.stream(ClientType.values())
            .map(Enum::name)
            .collect(Collectors.toUnmodifiableSet());

    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");

    /**
     * 校验认证授权策略
     *
     * @param policy 策略
     * @return 结果
     */
    public ValidationResult validateAuth(AuthPolicy policy) {
        ValidationResult result = ValidationResult.ok();
        if (policy == null) {
            return result.add("policy", "策略不能为空");
        }
        RouteValidator.validateCode("policyCode", policy.getPolicyCode(), result);
        if (isBlank(policy.getPolicyName())) {
            result.add("policyName", "策略名称不能为空");
        }
        if (policy.getAccessMode() == null) {
            result.add("accessMode", "访问模式不能为空");
        }
        policy.normalized();
        for (int i = 0; i < policy.getAllowedClientTypes().size(); i++) {
            String clientType = policy.getAllowedClientTypes().get(i);
            if (clientType == null || !CLIENT_TYPES.contains(clientType.toUpperCase(Locale.ROOT))) {
                result.add("allowedClientTypes[" + i + "]", "未知客户端类型");
            }
        }
        for (int i = 0; i < policy.getRequiredScopes().size(); i++) {
            String scope = policy.getRequiredScopes().get(i);
            if (isBlank(scope) || scope.chars().anyMatch(Character::isWhitespace)) {
                result.add("requiredScopes[" + i + "]", "scope 不能为空且不能包含空白字符");
            }
        }
        for (int i = 0; i < policy.getRequiredPermissions().size(); i++) {
            String permission = policy.getRequiredPermissions().get(i);
            if (isBlank(permission) || permission.chars().anyMatch(Character::isWhitespace)) {
                result.add("requiredPermissions[" + i + "]", "权限点不能为空且不能包含空白字符");
            }
        }
        if (policy.getAccessMode() == AccessMode.ANONYMOUS
                && (!policy.getRequiredScopes().isEmpty() || !policy.getRequiredPermissions().isEmpty())) {
            result.add("accessMode", "匿名访问策略不能声明 scope 或权限点要求");
        }
        return result;
    }

    /**
     * 校验流量治理策略
     *
     * @param policy 策略
     * @return 结果
     */
    public ValidationResult validateTraffic(TrafficPolicy policy) {
        ValidationResult result = ValidationResult.ok();
        if (policy == null) {
            return result.add("policy", "策略不能为空");
        }
        RouteValidator.validateCode("policyCode", policy.getPolicyCode(), result);
        if (isBlank(policy.getPolicyName())) {
            result.add("policyName", "策略名称不能为空");
        }
        policy.normalized();
        if (policy.getConnectTimeoutMillis() == null || policy.getConnectTimeoutMillis() <= 0) {
            result.add("connectTimeoutMillis", "连接超时必须大于 0");
        }
        if (policy.getResponseTimeoutMillis() == null || policy.getResponseTimeoutMillis() <= 0) {
            result.add("responseTimeoutMillis", "响应超时必须大于 0");
        }
        if (policy.getMaxConcurrentRequests() != null && policy.getMaxConcurrentRequests() < 1) {
            result.add("maxConcurrentRequests", "最大并发数必须大于 0");
        }
        List<RateLimitRule> rateLimits = policy.getRateLimits();
        for (int i = 0; i < rateLimits.size(); i++) {
            RateLimitRule rule = rateLimits.get(i);
            String field = "rateLimits[" + i + "]";
            if (rule == null) {
                result.add(field, "限流规则不能为空");
                continue;
            }
            if (rule.getDimension() == null) {
                result.add(field + ".dimension", "限流维度不能为空");
            } else if (!isKnownDimension(rule.getDimension())) {
                result.add(field + ".dimension", "未知限流维度");
            }
            if (rule.getReplenishPerSecond() == null || rule.getReplenishPerSecond() < 1) {
                result.add(field + ".replenishPerSecond", "每秒补充令牌数必须大于 0");
            }
            if (rule.getBurstCapacity() == null || rule.getBurstCapacity() < 1) {
                result.add(field + ".burstCapacity", "令牌桶容量必须大于 0");
            }
            if (rule.getFailureMode() == null) {
                result.add(field + ".failureMode", "限流失败模式不能为空");
            } else if (!isKnownFailureMode(rule.getFailureMode())) {
                result.add(field + ".failureMode", "未知限流失败模式");
            }
        }
        validateCircuitBreaker(policy.getCircuitBreaker(), result);
        validateRetry(policy.getRetry(), result);
        return result;
    }

    /**
     * 校验灰度策略
     *
     * @param policy      策略
     * @param directHosts 获批直连主机
     * @return 结果
     */
    public ValidationResult validateCanary(CanaryPolicy policy, Set<String> directHosts) {
        ValidationResult result = ValidationResult.ok();
        if (policy == null) {
            return result.add("policy", "策略不能为空");
        }
        RouteValidator.validateCode("policyCode", policy.getPolicyCode(), result);
        if (isBlank(policy.getPolicyName())) {
            result.add("policyName", "策略名称不能为空");
        }
        policy.normalized();
        if (policy.getStableKey() == null) {
            result.add("stableKey", "稳定灰度键不能为空");
        }
        if (policy.getRules().isEmpty()) {
            result.add("rules", "至少需要一条灰度规则");
        }
        Set<Integer> priorities = new HashSet<>();
        List<CanaryRule> rules = policy.getRules();
        for (int i = 0; i < rules.size(); i++) {
            CanaryRule rule = rules.get(i);
            String field = "rules[" + i + "]";
            if (rule == null) {
                result.add(field, "灰度规则不能为空");
                continue;
            }
            rule.normalized();
            if (rule.getPriority() == null || rule.getPriority() < 0) {
                result.add(field + ".priority", "规则优先级必须为非负整数");
            } else if (!priorities.add(rule.getPriority())) {
                result.add(field + ".priority", "规则优先级必须唯一");
            }
            validateConditions(field + ".conditions", rule.getConditions(), result);
            if (rule.getTargets().isEmpty()) {
                result.add(field + ".targets", "至少需要一个灰度目标");
                continue;
            }
            int weightSum = 0;
            List<CanaryTarget> targets = rule.getTargets();
            for (int j = 0; j < targets.size(); j++) {
                CanaryTarget target = targets.get(j);
                String targetField = field + ".targets[" + j + "]";
                if (target == null) {
                    result.add(targetField, "灰度目标不能为空");
                    continue;
                }
                RouteValidator.validateTarget(targetField, target.toRouteTarget(), directHosts, result);
                if (target.getWeight() == null || target.getWeight() < 1 || target.getWeight() > 100) {
                    result.add(targetField + ".weight", "权重必须介于 1 到 100 之间");
                } else {
                    weightSum += target.getWeight();
                }
            }
            if (weightSum != 100) {
                result.add(field + ".targets", "同一规则内权重合计必须为 100");
            }
        }
        return result;
    }

    private void validateConditions(String field, CanaryConditions conditions, ValidationResult result) {
        if (conditions == null) {
            result.add(field, "匹配条件不能为空");
            return;
        }
        conditions.normalized();
        if (conditions.getClientTypes().isEmpty() && conditions.getUserIds().isEmpty()
                && conditions.getVehicleIds().isEmpty() && conditions.getHeaders().isEmpty()) {
            result.add(field, "至少需要一个匹配条件");
        }
        for (int i = 0; i < conditions.getClientTypes().size(); i++) {
            String clientType = conditions.getClientTypes().get(i);
            if (clientType == null || !CLIENT_TYPES.contains(clientType.toUpperCase(Locale.ROOT))) {
                result.add(field + ".clientTypes[" + i + "]", "未知客户端类型");
            }
        }
        for (int i = 0; i < conditions.getHeaders().size(); i++) {
            if (conditions.getHeaders().get(i) == null) {
                result.add(field + ".headers[" + i + "]", "请求头条件不能为空");
            } else if (isBlank(conditions.getHeaders().get(i).getName())) {
                result.add(field + ".headers[" + i + "].name", "请求头名称不能为空");
            }
        }
    }

    private void validateCircuitBreaker(CircuitBreakerRule rule, ValidationResult result) {
        if (rule == null) {
            return;
        }
        if (rule.getSlidingWindowSize() == null || rule.getSlidingWindowSize() < 1) {
            result.add("circuitBreaker.slidingWindowSize", "滑动窗口大小必须大于 0");
        }
        if (rule.getMinimumNumberOfCalls() == null || rule.getMinimumNumberOfCalls() < 1) {
            result.add("circuitBreaker.minimumNumberOfCalls", "最小调用数必须大于 0");
        } else if (rule.getSlidingWindowSize() != null
                && rule.getMinimumNumberOfCalls() > rule.getSlidingWindowSize()) {
            result.add("circuitBreaker.minimumNumberOfCalls", "最小调用数不能大于滑动窗口大小");
        }
        if (rule.getFailureRateThreshold() == null
                || rule.getFailureRateThreshold() <= 0 || rule.getFailureRateThreshold() > 100) {
            result.add("circuitBreaker.failureRateThreshold", "失败率阈值必须介于 0 到 100 之间");
        }
        if (rule.getSlowCallRateThreshold() != null
                && (rule.getSlowCallRateThreshold() <= 0 || rule.getSlowCallRateThreshold() > 100)) {
            result.add("circuitBreaker.slowCallRateThreshold", "慢调用率阈值必须介于 0 到 100 之间");
        }
        if (rule.getSlowCallDurationMillis() == null || rule.getSlowCallDurationMillis() < 1) {
            result.add("circuitBreaker.slowCallDurationMillis", "慢调用判定时长必须大于 0");
        }
        if (rule.getWaitDurationInOpenStateMillis() == null || rule.getWaitDurationInOpenStateMillis() < 0) {
            result.add("circuitBreaker.waitDurationInOpenStateMillis", "熔断打开等待时长不能为负数");
        }
        if (rule.getPermittedCallsInHalfOpenState() == null || rule.getPermittedCallsInHalfOpenState() < 1) {
            result.add("circuitBreaker.permittedCallsInHalfOpenState", "半开允许调用数必须大于 0");
        }
    }

    private void validateRetry(RetryRule rule, ValidationResult result) {
        if (rule == null) {
            return;
        }
        rule.normalized();
        if (rule.getMaxAttempts() == null || rule.getMaxAttempts() < 1) {
            result.add("retry.maxAttempts", "最大尝试次数必须大于 0");
        }
        if (rule.getBackoffMillis() == null || rule.getBackoffMillis() < 0) {
            result.add("retry.backoffMillis", "重试退避时长不能为负数");
        }
        if (rule.getMethods().isEmpty()) {
            result.add("retry.methods", "必须显式声明可重试的安全方法");
        }
        for (int i = 0; i < rule.getMethods().size(); i++) {
            String method = rule.getMethods().get(i);
            if (method == null || !SAFE_METHODS.contains(method.toUpperCase(Locale.ROOT))) {
                result.add("retry.methods[" + i + "]", "仅允许重试安全方法 GET/HEAD/OPTIONS");
            }
        }
        for (int i = 0; i < rule.getStatuses().size(); i++) {
            Integer status = rule.getStatuses().get(i);
            if (status == null || status < 500 || status > 599) {
                result.add("retry.statuses[" + i + "]", "触发重试的上游状态码必须为 5xx");
            }
        }
    }

    private boolean isKnownDimension(RateLimitDimension dimension) {
        return Arrays.asList(RateLimitDimension.values()).contains(dimension);
    }

    private boolean isKnownFailureMode(RateLimitFailureMode mode) {
        return Arrays.asList(RateLimitFailureMode.values()).contains(mode);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /**
     * 灰度策略是否可以被该访问模式使用
     *
     * @param policy 灰度策略
     * @param mode   访问模式
     * @return 可用集合
     */
    public List<String> unavailableStableKeys(CanaryPolicy policy, AccessMode mode) {
        List<String> keys = new ArrayList<>();
        if (policy == null || policy.getStableKey() == null) {
            return keys;
        }
        if (mode == AccessMode.ANONYMOUS) {
            switch (policy.getStableKey()) {
                case VEHICLE_ID -> keys.add("VEHICLE_ID");
                case AUTHENTICATED_SUBJECT -> keys.add("AUTHENTICATED_SUBJECT");
                case DEVICE_ID -> keys.add("DEVICE_ID");
                case CLIENT_ID -> keys.add("CLIENT_ID");
                default -> {
                }
            }
        }
        return keys;
    }

}
