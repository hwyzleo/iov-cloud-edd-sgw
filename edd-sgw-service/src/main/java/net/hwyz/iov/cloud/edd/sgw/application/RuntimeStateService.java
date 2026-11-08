package net.hwyz.iov.cloud.edd.sgw.application;

import net.hwyz.iov.cloud.edd.sgw.api.enums.PublicationStatus;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.RuntimeInstanceResponse;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.InstanceStatePo;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.InstanceStateRepository;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 运行时实例状态用例。
 *
 * @author hwyz_leo
 */
@Service
public class RuntimeStateService {

    private final GatewayInstanceProvider gatewayInstanceProvider;

    private final InstanceStateRepository instanceStateRepository;

    public RuntimeStateService(GatewayInstanceProvider gatewayInstanceProvider,
                               InstanceStateRepository instanceStateRepository) {
        this.gatewayInstanceProvider = gatewayInstanceProvider;
        this.instanceStateRepository = instanceStateRepository;
    }

    /**
     * 已发现实例及其配置版本状态
     *
     * @return 实例状态
     */
    public List<RuntimeInstanceResponse> instances() {
        Map<String, InstanceStatePo> states = new HashMap<>();
        instanceStateRepository.findAll().forEach(state -> states.put(state.getInstanceId(), state));
        return gatewayInstanceProvider.currentInstances().stream()
                .map(instance -> toResponse(instance, states.get(instanceId(instance))))
                .toList();
    }

    private RuntimeInstanceResponse toResponse(ServiceInstance instance, InstanceStatePo state) {
        return RuntimeInstanceResponse.builder()
                .instanceId(instanceId(instance))
                .address(instance.getHost() + ":" + instance.getPort())
                .discovered(true)
                .activeVersionNo(state == null ? null : state.getActiveVersionNo())
                .lastPublicationId(state == null ? null : state.getLastPublicationId())
                .lastPublicationStatus(state == null || state.getStatus() == null
                        ? null : parseStatus(state.getStatus()))
                .lastPublicationTime(state == null ? null : Assembler.instant(state.getUpdateTime()))
                .lastError(state == null ? null : state.getLastError())
                .build();
    }

    private PublicationStatus parseStatus(String status) {
        try {
            return PublicationStatus.valueOf(status);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private String instanceId(ServiceInstance instance) {
        return instance.getHost() + ":" + instance.getPort();
    }

}
