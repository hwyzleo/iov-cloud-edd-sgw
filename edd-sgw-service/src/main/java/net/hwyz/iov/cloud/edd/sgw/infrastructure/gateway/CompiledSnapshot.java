package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

import lombok.Getter;
import net.hwyz.iov.cloud.edd.sgw.domain.model.AuthPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.SgwConfiguration;
import net.hwyz.iov.cloud.edd.sgw.domain.model.TrafficPolicy;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * 已编译并激活的不可变配置快照。
 *
 * @author hwyz_leo
 */
@Getter
public class CompiledSnapshot {

    private final long versionNo;

    private final String checksum;

    private final SgwConfiguration configuration;

    private final List<CompiledRoute> routes;

    private final Map<String, CompiledRoute> routeIndex;

    private final Map<String, AuthPolicy> authPolicies;

    private final Map<String, TrafficPolicy> trafficPolicies;

    private final Map<String, CanaryPolicy> canaryPolicies;

    private final Instant activatedAt;

    public CompiledSnapshot(long versionNo, String checksum, SgwConfiguration configuration,
                            List<CompiledRoute> routes, Instant activatedAt) {
        this.versionNo = versionNo;
        this.checksum = checksum;
        this.configuration = configuration;
        this.routes = routes;
        this.routeIndex = routes.stream()
                .collect(java.util.stream.Collectors.toMap(CompiledRoute::routeCode, route -> route,
                        (left, right) -> left, java.util.LinkedHashMap::new));
        this.authPolicies = configuration.authPolicyIndex();
        this.trafficPolicies = configuration.trafficPolicyIndex();
        this.canaryPolicies = configuration.canaryPolicyIndex();
        this.activatedAt = activatedAt;
    }

}
