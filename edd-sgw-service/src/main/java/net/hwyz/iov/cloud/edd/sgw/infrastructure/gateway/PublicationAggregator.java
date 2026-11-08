package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

import net.hwyz.iov.cloud.edd.sgw.api.enums.InstancePublicationStatus;
import net.hwyz.iov.cloud.edd.sgw.api.enums.PublicationStatus;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.InstancePublicationPo;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.PublicationPo;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.InstancePublicationRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.PublicationRepository;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;

/**
 * 发布结果聚合：根据逐实例结果计算整体发布状态。
 *
 * @author hwyz_leo
 */
@Component
public class PublicationAggregator {

    private final PublicationRepository publicationRepository;

    private final InstancePublicationRepository instancePublicationRepository;

    public PublicationAggregator(PublicationRepository publicationRepository,
                                 InstancePublicationRepository instancePublicationRepository) {
        this.publicationRepository = publicationRepository;
        this.instancePublicationRepository = instancePublicationRepository;
    }

    /**
     * 重新计算发布状态
     *
     * @param publicationId 发布ID
     * @return 计算结果
     */
    public PublicationStatus recompute(String publicationId) {
        PublicationPo publication = publicationRepository.findByPublicationId(publicationId).orElse(null);
        if (publication == null) {
            return null;
        }
        if (PublicationStatus.valueOf(publication.getStatus()).isTerminal()) {
            return PublicationStatus.valueOf(publication.getStatus());
        }
        List<InstancePublicationPo> instances = instancePublicationRepository.findByPublicationId(publicationId);
        if (instances.isEmpty()) {
            return PublicationStatus.valueOf(publication.getStatus());
        }
        boolean anyPending = instances.stream()
                .anyMatch(item -> InstancePublicationStatus.PENDING.name().equals(item.getStatus()));
        if (anyPending) {
            if (!PublicationStatus.WAITING_ACK.name().equals(publication.getStatus())) {
                publicationRepository.updateStatus(publicationId, PublicationStatus.WAITING_ACK, null, null);
            }
            return PublicationStatus.WAITING_ACK;
        }
        long succeeded = instances.stream()
                .filter(item -> InstancePublicationStatus.SUCCEEDED.name().equals(item.getStatus())).count();
        long failed = instances.size() - succeeded;
        PublicationStatus status;
        if (failed == 0) {
            status = PublicationStatus.SUCCEEDED;
        } else if (succeeded > 0) {
            status = PublicationStatus.PARTIAL_FAILED;
        } else {
            status = PublicationStatus.FAILED;
        }
        String error = status == PublicationStatus.SUCCEEDED ? null : "存在未成功应用目标版本的实例";
        publicationRepository.updateStatus(publicationId, status, error,
                status.isTerminal() ? new Date() : null);
        return status;
    }

}
