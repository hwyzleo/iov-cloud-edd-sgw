package net.hwyz.iov.cloud.edd.sgw.application;

import net.hwyz.iov.cloud.edd.sgw.api.vo.CanaryConditionsVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.CanaryRuleVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.CanaryTargetVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.CircuitBreakerVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.HeaderMatchVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.QueryParamMatchVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.RateLimitVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.RetryVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.RouteMatchVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.RouteTargetVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.RouteTransformVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.AuthPolicySaveRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.CanaryPolicySaveRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.RouteSaveRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.TrafficPolicySaveRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.AuthPolicyResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.CanaryPolicyResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigSnapshotVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigVersionResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.RouteResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.TrafficPolicyResponse;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.domain.model.AuthPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.ConfigSnapshot;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.SgwConfiguration;
import net.hwyz.iov.cloud.edd.sgw.domain.model.TrafficPolicy;

import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * 领域模型与接口契约之间的转换。
 *
 * @author hwyz_leo
 */
public final class Assembler {

    private Assembler() {
    }

    /**
     * 路由请求转领域模型
     *
     * @param request 请求
     * @return 领域模型
     */
    public static RouteDefinition toDomain(RouteSaveRequest request) {
        return RouteDefinition.builder()
                .routeCode(request.getRouteCode())
                .routeName(request.getRouteName())
                .description(request.getDescription())
                .priority(request.getPriority())
                .enabled(request.getEnabled() == null || request.getEnabled())
                .match(request.getMatch() == null ? null : Json.convert(request.getMatch(), net.hwyz.iov.cloud.edd.sgw.domain.model.RouteMatch.class))
                .target(request.getTarget() == null ? null : Json.convert(request.getTarget(), net.hwyz.iov.cloud.edd.sgw.domain.model.RouteTarget.class))
                .transform(request.getTransform() == null ? null : Json.convert(request.getTransform(), net.hwyz.iov.cloud.edd.sgw.domain.model.RouteTransform.class))
                .authPolicyCode(request.getAuthPolicyCode())
                .trafficPolicyCode(request.getTrafficPolicyCode())
                .canaryPolicyCode(request.getCanaryPolicyCode())
                .rowVersion(request.getRowVersion())
                .build();
    }

    /**
     * 路由领域模型转响应
     *
     * @param route 领域模型
     * @return 响应
     */
    public static RouteResponse toResponse(RouteDefinition route) {
        return RouteResponse.builder()
                .routeCode(route.getRouteCode())
                .routeName(route.getRouteName())
                .description(route.getDescription())
                .priority(route.getPriority())
                .enabled(route.getEnabled())
                .match(route.getMatch() == null ? null : Json.convert(route.getMatch(), RouteMatchVo.class))
                .target(route.getTarget() == null ? null : Json.convert(route.getTarget(), RouteTargetVo.class))
                .transform(route.getTransform() == null ? null : Json.convert(route.getTransform(), RouteTransformVo.class))
                .authPolicyCode(route.getAuthPolicyCode())
                .trafficPolicyCode(route.getTrafficPolicyCode())
                .canaryPolicyCode(route.getCanaryPolicyCode())
                .rowVersion(route.getRowVersion())
                .build();
    }

    /**
     * 认证授权策略请求转领域模型
     *
     * @param request 请求
     * @return 领域模型
     */
    public static AuthPolicy toDomain(AuthPolicySaveRequest request) {
        return AuthPolicy.builder()
                .policyCode(request.getPolicyCode())
                .policyName(request.getPolicyName())
                .description(request.getDescription())
                .accessMode(request.getAccessMode())
                .allowedClientTypes(request.getAllowedClientTypes())
                .requiredScopes(request.getRequiredScopes())
                .requiredPermissions(request.getRequiredPermissions())
                .enabled(request.getEnabled() == null || request.getEnabled())
                .rowVersion(request.getRowVersion())
                .build();
    }

    /**
     * 认证授权策略转响应
     *
     * @param policy 领域模型
     * @return 响应
     */
    public static AuthPolicyResponse toResponse(AuthPolicy policy) {
        return AuthPolicyResponse.builder()
                .policyCode(policy.getPolicyCode())
                .policyName(policy.getPolicyName())
                .description(policy.getDescription())
                .accessMode(policy.getAccessMode())
                .allowedClientTypes(policy.getAllowedClientTypes())
                .requiredScopes(policy.getRequiredScopes())
                .requiredPermissions(policy.getRequiredPermissions())
                .enabled(policy.getEnabled())
                .rowVersion(policy.getRowVersion())
                .build();
    }

    /**
     * 流量策略请求转领域模型
     *
     * @param request 请求
     * @return 领域模型
     */
    public static TrafficPolicy toDomain(TrafficPolicySaveRequest request) {
        return TrafficPolicy.builder()
                .policyCode(request.getPolicyCode())
                .policyName(request.getPolicyName())
                .description(request.getDescription())
                .connectTimeoutMillis(request.getConnectTimeoutMillis())
                .responseTimeoutMillis(request.getResponseTimeoutMillis())
                .rateLimits(request.getRateLimits() == null ? null
                        : request.getRateLimits().stream()
                        .map(item -> Json.convert(item, net.hwyz.iov.cloud.edd.sgw.domain.model.RateLimitRule.class)).toList())
                .maxConcurrentRequests(request.getMaxConcurrentRequests())
                .circuitBreaker(request.getCircuitBreaker() == null ? null
                        : Json.convert(request.getCircuitBreaker(), net.hwyz.iov.cloud.edd.sgw.domain.model.CircuitBreakerRule.class))
                .retry(request.getRetry() == null ? null
                        : Json.convert(request.getRetry(), net.hwyz.iov.cloud.edd.sgw.domain.model.RetryRule.class))
                .enabled(request.getEnabled() == null || request.getEnabled())
                .rowVersion(request.getRowVersion())
                .build();
    }

    /**
     * 流量策略转响应
     *
     * @param policy 领域模型
     * @return 响应
     */
    public static TrafficPolicyResponse toResponse(TrafficPolicy policy) {
        return TrafficPolicyResponse.builder()
                .policyCode(policy.getPolicyCode())
                .policyName(policy.getPolicyName())
                .description(policy.getDescription())
                .connectTimeoutMillis(policy.getConnectTimeoutMillis())
                .responseTimeoutMillis(policy.getResponseTimeoutMillis())
                .rateLimits(policy.getRateLimits() == null ? List.of()
                        : policy.getRateLimits().stream().map(item -> Json.convert(item, RateLimitVo.class)).toList())
                .maxConcurrentRequests(policy.getMaxConcurrentRequests())
                .circuitBreaker(policy.getCircuitBreaker() == null ? null
                        : Json.convert(policy.getCircuitBreaker(), CircuitBreakerVo.class))
                .retry(policy.getRetry() == null ? null : Json.convert(policy.getRetry(), RetryVo.class))
                .enabled(policy.getEnabled())
                .rowVersion(policy.getRowVersion())
                .build();
    }

    /**
     * 灰度策略请求转领域模型
     *
     * @param request 请求
     * @return 领域模型
     */
    public static CanaryPolicy toDomain(CanaryPolicySaveRequest request) {
        return CanaryPolicy.builder()
                .policyCode(request.getPolicyCode())
                .policyName(request.getPolicyName())
                .description(request.getDescription())
                .stableKey(request.getStableKey())
                .rules(request.getRules() == null ? null
                        : request.getRules().stream()
                        .map(item -> Json.convert(item, net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryRule.class)).toList())
                .enabled(request.getEnabled() == null || request.getEnabled())
                .rowVersion(request.getRowVersion())
                .build();
    }

    /**
     * 灰度策略转响应
     *
     * @param policy 领域模型
     * @return 响应
     */
    public static CanaryPolicyResponse toResponse(CanaryPolicy policy) {
        return CanaryPolicyResponse.builder()
                .policyCode(policy.getPolicyCode())
                .policyName(policy.getPolicyName())
                .description(policy.getDescription())
                .stableKey(policy.getStableKey())
                .rules(policy.getRules() == null ? List.of()
                        : policy.getRules().stream().map(item -> Json.convert(item, CanaryRuleVo.class)).toList())
                .enabled(policy.getEnabled())
                .rowVersion(policy.getRowVersion())
                .build();
    }

    /**
     * 配置转结构化快照 VO
     *
     * @param configuration 配置
     * @return 快照 VO
     */
    public static ConfigSnapshotVo toSnapshotVo(SgwConfiguration configuration) {
        return ConfigSnapshotVo.builder()
                .routes(configuration.getRoutes().stream().map(Assembler::toResponse).toList())
                .authPolicies(configuration.getAuthPolicies().stream().map(Assembler::toResponse).toList())
                .trafficPolicies(configuration.getTrafficPolicies().stream().map(Assembler::toResponse).toList())
                .canaryPolicies(configuration.getCanaryPolicies().stream().map(Assembler::toResponse).toList())
                .build();
    }

    /**
     * 版本快照转版本摘要
     *
     * @param snapshot 版本快照
     * @param current  当前目标版本
     * @return 摘要
     */
    public static ConfigVersionResponse toVersionResponse(ConfigSnapshot snapshot, Long current) {
        return ConfigVersionResponse.builder()
                .versionNo(snapshot.getVersionNo())
                .operation(snapshot.getOperation())
                .sourceVersionNo(snapshot.getSourceVersionNo())
                .checksum(snapshot.getChecksum())
                .description(snapshot.getDescription())
                .createBy(snapshot.getCreateBy())
                .createTime(instant(snapshot.getCreateTime()))
                .current(current != null && current.equals(snapshot.getVersionNo()))
                .build();
    }

    /**
     * 时间转换
     *
     * @param date 时间
     * @return Instant
     */
    public static Instant instant(Date date) {
        return date == null ? null : date.toInstant();
    }

}
