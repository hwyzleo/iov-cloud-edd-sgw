package net.hwyz.iov.cloud.edd.sgw.domain.validation;

import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;
import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
import net.hwyz.iov.cloud.edd.sgw.domain.model.AuthPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteMatch;
import net.hwyz.iov.cloud.edd.sgw.domain.model.SgwConfiguration;
import net.hwyz.iov.cloud.edd.sgw.domain.model.TrafficPolicy;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * 完整配置快照校验器。
 * <p>
 * 在发布前校验编码唯一性、引用完整性、目标合法性、优先级歧义与灰度键可用性。
 *
 * @author hwyz_leo
 */
@Component
public class ConfigurationValidator {

    private final RouteValidator routeValidator;

    private final PolicyValidator policyValidator;

    private final SgwProperties properties;

    public ConfigurationValidator(RouteValidator routeValidator, PolicyValidator policyValidator,
                                  SgwProperties properties) {
        this.routeValidator = routeValidator;
        this.policyValidator = policyValidator;
        this.properties = properties;
    }

    /**
     * 校验完整配置
     *
     * @param configuration 配置
     * @return 校验结果
     */
    public ValidationResult validate(SgwConfiguration configuration) {
        ValidationResult result = ValidationResult.ok();
        if (configuration == null) {
            return result.add("configuration", "配置不能为空");
        }
        configuration.normalized();
        Set<String> directHosts = new LinkedHashSet<>(properties.getRuntime().getDirectUpstreamHosts());

        checkDuplicateCodes("routes", configuration.getRoutes(), RouteDefinition::getRouteCode, result);
        checkDuplicateCodes("authPolicies", configuration.getAuthPolicies(), AuthPolicy::getPolicyCode, result);
        checkDuplicateCodes("trafficPolicies", configuration.getTrafficPolicies(), TrafficPolicy::getPolicyCode, result);
        checkDuplicateCodes("canaryPolicies", configuration.getCanaryPolicies(), CanaryPolicy::getPolicyCode, result);

        configuration.getRoutes().forEach(route -> result.merge(routeValidator.validate(route, directHosts)));
        configuration.getAuthPolicies().forEach(policy -> result.merge(policyValidator.validateAuth(policy)));
        configuration.getTrafficPolicies().forEach(policy -> result.merge(policyValidator.validateTraffic(policy)));
        configuration.getCanaryPolicies().forEach(policy -> result.merge(policyValidator.validateCanary(policy, directHosts)));

        Map<String, AuthPolicy> authPolicies = configuration.authPolicyIndex();
        Map<String, TrafficPolicy> trafficPolicies = configuration.trafficPolicyIndex();
        Map<String, CanaryPolicy> canaryPolicies = configuration.canaryPolicyIndex();

        for (RouteDefinition route : configuration.getRoutes()) {
            if (route.getAuthPolicyCode() != null && !authPolicies.containsKey(route.getAuthPolicyCode())) {
                result.add("routes[" + route.getRouteCode() + "].authPolicyCode", "引用的认证授权策略不存在");
            }
            if (route.getTrafficPolicyCode() != null && !trafficPolicies.containsKey(route.getTrafficPolicyCode())) {
                result.add("routes[" + route.getRouteCode() + "].trafficPolicyCode", "引用的流量治理策略不存在");
            }
            if (route.getCanaryPolicyCode() != null && !canaryPolicies.containsKey(route.getCanaryPolicyCode())) {
                result.add("routes[" + route.getRouteCode() + "].canaryPolicyCode", "引用的灰度策略不存在");
            }
        }

        checkAmbiguousRoutes(configuration.getRoutes(), result);
        checkCanaryKeyAvailability(configuration.getRoutes(), authPolicies, canaryPolicies, result);
        return result;
    }

    private <T> void checkDuplicateCodes(String field, List<T> values,
                                         java.util.function.Function<T, String> code,
                                         ValidationResult result) {
        Set<String> seen = new HashSet<>();
        for (T value : values) {
            String key = code.apply(value);
            if (key != null && !seen.add(key)) {
                result.add(field, "编码重复：" + key);
            }
        }
    }

    private void checkAmbiguousRoutes(List<RouteDefinition> routes, ValidationResult result) {
        Map<Integer, Map<String, String>> byPriority = new HashMap<>();
        for (RouteDefinition route : routes) {
            if (!route.effective()) {
                continue;
            }
            String signature = matchSignature(route.getMatch());
            Map<String, String> signatures = byPriority.computeIfAbsent(route.getPriority(), key -> new HashMap<>());
            String existing = signatures.putIfAbsent(signature, route.getRouteCode());
            if (existing != null) {
                result.add("routes[" + route.getRouteCode() + "].priority",
                        "与路由 " + existing + " 优先级相同且匹配条件等价，存在歧义");
            }
        }
    }

    private String matchSignature(RouteMatch match) {
        if (match == null) {
            return "";
        }
        match.normalized();
        List<String> paths = new ArrayList<>(match.getPaths());
        List<String> methods = new ArrayList<>(match.getMethods());
        List<String> hosts = new ArrayList<>(match.getHosts());
        List<String> clientTypes = new ArrayList<>(match.getClientTypes());
        paths.sort(Comparator.naturalOrder());
        methods.sort(Comparator.naturalOrder());
        hosts.sort(Comparator.naturalOrder());
        clientTypes.sort(Comparator.naturalOrder());
        StringBuilder builder = new StringBuilder();
        builder.append(String.join(",", paths)).append('|')
                .append(String.join(",", methods)).append('|')
                .append(String.join(",", hosts)).append('|')
                .append(String.join(",", clientTypes));
        match.getHeaders().forEach(header -> builder.append('|').append(header.getName())
                .append('=').append(header.getMatchType()).append(':').append(header.getValue()));
        match.getQueryParams().forEach(param -> builder.append('|').append(param.getName())
                .append('=').append(param.getMatchType()).append(':').append(param.getValue()));
        return builder.toString().toLowerCase(Locale.ROOT);
    }

    private void checkCanaryKeyAvailability(List<RouteDefinition> routes,
                                            Map<String, AuthPolicy> authPolicies,
                                            Map<String, CanaryPolicy> canaryPolicies,
                                            ValidationResult result) {
        for (RouteDefinition route : routes) {
            if (!route.effective() || route.getCanaryPolicyCode() == null) {
                continue;
            }
            CanaryPolicy canaryPolicy = canaryPolicies.get(route.getCanaryPolicyCode());
            if (canaryPolicy == null || !canaryPolicy.effective()) {
                continue;
            }
            AccessMode mode = AccessMode.ANONYMOUS;
            if (route.getAuthPolicyCode() != null) {
                AuthPolicy authPolicy = authPolicies.get(route.getAuthPolicyCode());
                if (authPolicy != null && authPolicy.getAccessMode() != null) {
                    mode = authPolicy.getAccessMode();
                }
            }
            List<String> unavailable = policyValidator.unavailableStableKeys(canaryPolicy, mode);
            if (!unavailable.isEmpty()) {
                result.add("routes[" + route.getRouteCode() + "].canaryPolicyCode",
                        "灰度稳定键 " + unavailable.get(0) + " 在 " + mode + " 访问模式下不可用");
            }
        }
    }

}
