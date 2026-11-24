package net.hwyz.iov.cloud.edd.sgw.application;

import net.hwyz.iov.cloud.edd.sgw.domain.model.SgwConfiguration;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.AuthPolicyRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.CanaryPolicyRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.RouteRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.TrafficPolicyRepository;
import org.springframework.stereotype.Service;

/**
 * 草稿配置装配器（EDD-SGW-DSN-CR-004）。
 * <p>
 * 发布、导出与待发布变更预览共用同一草稿读取与规范化链路，避免筛选、排序或规范化口径不一致产生假差异。
 *
 * @author hwyz_leo
 */
@Service
public class DraftConfigurationLoader {

    private final RouteRepository routeRepository;

    private final AuthPolicyRepository authPolicyRepository;

    private final TrafficPolicyRepository trafficPolicyRepository;

    private final CanaryPolicyRepository canaryPolicyRepository;

    public DraftConfigurationLoader(RouteRepository routeRepository, AuthPolicyRepository authPolicyRepository,
                                    TrafficPolicyRepository trafficPolicyRepository,
                                    CanaryPolicyRepository canaryPolicyRepository) {
        this.routeRepository = routeRepository;
        this.authPolicyRepository = authPolicyRepository;
        this.trafficPolicyRepository = trafficPolicyRepository;
        this.canaryPolicyRepository = canaryPolicyRepository;
    }

    /**
     * 读取并规范化当前有效草稿
     *
     * @return 归一化配置
     */
    public SgwConfiguration load() {
        SgwConfiguration configuration = SgwConfiguration.builder()
                .routes(routeRepository.findAllValid())
                .authPolicies(authPolicyRepository.findAllValid())
                .trafficPolicies(trafficPolicyRepository.findAllValid())
                .canaryPolicies(canaryPolicyRepository.findAllValid())
                .build();
        return configuration.normalized();
    }

}
