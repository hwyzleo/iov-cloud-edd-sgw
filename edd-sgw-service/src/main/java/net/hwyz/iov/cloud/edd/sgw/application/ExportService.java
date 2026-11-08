package net.hwyz.iov.cloud.edd.sgw.application;

import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ExportResponseVo;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.domain.model.SgwConfiguration;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.AuthPolicyRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.CanaryPolicyRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.RouteRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.TrafficPolicyRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;

/**
 * 结构化配置导出用例（不含任何密钥）。
 *
 * @author hwyz_leo
 */
@Service
public class ExportService {

    private final RouteRepository routeRepository;

    private final AuthPolicyRepository authPolicyRepository;

    private final TrafficPolicyRepository trafficPolicyRepository;

    private final CanaryPolicyRepository canaryPolicyRepository;

    public ExportService(RouteRepository routeRepository, AuthPolicyRepository authPolicyRepository,
                         TrafficPolicyRepository trafficPolicyRepository,
                         CanaryPolicyRepository canaryPolicyRepository) {
        this.routeRepository = routeRepository;
        this.authPolicyRepository = authPolicyRepository;
        this.trafficPolicyRepository = trafficPolicyRepository;
        this.canaryPolicyRepository = canaryPolicyRepository;
    }

    /**
     * 导出配置
     *
     * @param type 导出类型
     * @return 导出结果
     */
    public ExportResponseVo export(String type) {
        String content = switch (type == null ? "" : type) {
            case "routes" -> Json.write(routeRepository.findAllValid().stream()
                    .map(Assembler::toResponse).toList());
            case "auth-policies" -> Json.write(authPolicyRepository.findAllValid().stream()
                    .map(Assembler::toResponse).toList());
            case "traffic-policies" -> Json.write(trafficPolicyRepository.findAllValid().stream()
                    .map(Assembler::toResponse).toList());
            case "canary-policies" -> Json.write(canaryPolicyRepository.findAllValid().stream()
                    .map(Assembler::toResponse).toList());
            case "config" -> Json.write(Assembler.toSnapshotVo(configuration()));
            default -> throw new SgwException(SgwErrorCode.VALIDATION_FAILED, "未知导出类型: " + type);
        };
        return ExportResponseVo.builder()
                .type(type)
                .generatedAt(Instant.now())
                .content(content)
                .build();
    }

    private SgwConfiguration configuration() {
        return SgwConfiguration.builder()
                .routes(routeRepository.findAllValid())
                .authPolicies(authPolicyRepository.findAllValid())
                .trafficPolicies(trafficPolicyRepository.findAllValid())
                .canaryPolicies(canaryPolicyRepository.findAllValid())
                .build().normalized();
    }

}
