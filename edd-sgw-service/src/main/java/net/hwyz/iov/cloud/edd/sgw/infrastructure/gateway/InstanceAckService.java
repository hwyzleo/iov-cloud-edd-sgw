package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

import net.hwyz.iov.cloud.edd.sgw.api.enums.InstancePublicationStatus;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.InstancePublicationRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.InstanceStateRepository;
import org.springframework.stereotype.Component;

/**
 * 实例发布确认：写入逐实例结果与最新运行时状态。
 *
 * @author hwyz_leo
 */
@Component
public class InstanceAckService {

    private final InstancePublicationRepository instancePublicationRepository;

    private final InstanceStateRepository instanceStateRepository;

    private final PublicationAggregator publicationAggregator;

    private final InstanceIdProvider instanceIdProvider;

    public InstanceAckService(InstancePublicationRepository instancePublicationRepository,
                              InstanceStateRepository instanceStateRepository,
                              PublicationAggregator publicationAggregator,
                              InstanceIdProvider instanceIdProvider) {
        this.instancePublicationRepository = instancePublicationRepository;
        this.instanceStateRepository = instanceStateRepository;
        this.publicationAggregator = publicationAggregator;
        this.instanceIdProvider = instanceIdProvider;
    }

    /**
     * 记录应用成功
     *
     * @param publicationId 发布ID（可空，启动加载无发布上下文）
     * @param targetVersion 目标版本
     * @param activeVersion 生效版本
     */
    public void recordSuccess(String publicationId, Long targetVersion, Long activeVersion) {
        String instanceId = instanceIdProvider.getInstanceId();
        if (publicationId != null) {
            instancePublicationRepository.recordResult(publicationId, instanceId, targetVersion, activeVersion,
                    InstancePublicationStatus.SUCCEEDED, null);
        }
        instanceStateRepository.upsert(instanceId, activeVersion, publicationId,
                InstancePublicationStatus.SUCCEEDED.name(), null);
        if (publicationId != null) {
            publicationAggregator.recompute(publicationId);
        }
    }

    /**
     * 记录应用失败
     *
     * @param publicationId 发布ID（可空）
     * @param targetVersion 目标版本
     * @param activeVersion 当前生效版本
     * @param error         脱敏错误
     */
    public void recordFailure(String publicationId, Long targetVersion, Long activeVersion, String error) {
        String instanceId = instanceIdProvider.getInstanceId();
        String sanitized = Json.truncate(sanitize(error), 1000);
        if (publicationId != null) {
            instancePublicationRepository.recordResult(publicationId, instanceId, targetVersion, activeVersion,
                    InstancePublicationStatus.FAILED, sanitized);
        }
        instanceStateRepository.upsert(instanceId, activeVersion, publicationId,
                InstancePublicationStatus.FAILED.name(), sanitized);
        if (publicationId != null) {
            publicationAggregator.recompute(publicationId);
        }
    }

    private String sanitize(String error) {
        if (error == null) {
            return "未知错误";
        }
        return error.replaceAll("(?i)(secret|password|token)=[^,\\s]+", "$1=***");
    }

}
