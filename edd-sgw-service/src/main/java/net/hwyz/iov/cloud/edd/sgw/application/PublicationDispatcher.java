package net.hwyz.iov.cloud.edd.sgw.application;

import net.hwyz.iov.cloud.edd.sgw.api.enums.PublicationStatus;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.PublicationPointer;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.VersionPointerStore;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.PublicationRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 * 发布分发器：向 Nacos 推送版本指针并记录分发结果。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class PublicationDispatcher {

    private final VersionPointerStore versionPointerStore;

    private final PublicationRepository publicationRepository;

    private final AuditService auditService;

    public PublicationDispatcher(VersionPointerStore versionPointerStore,
                                 PublicationRepository publicationRepository, AuditService auditService) {
        this.versionPointerStore = versionPointerStore;
        this.publicationRepository = publicationRepository;
        this.auditService = auditService;
    }

    /**
     * 分发版本指针
     *
     * @param prepared 待分发发布
     * @param context  操作上下文
     */
    public void dispatch(PreparedPublication prepared, AdminContext context) {
        try {
            versionPointerStore.publish(new PublicationPointer(prepared.versionNo(), prepared.publicationId(),
                    prepared.checksum()));
            publicationRepository.updateStatus(prepared.publicationId(), PublicationStatus.WAITING_ACK,
                    null, null);
            auditService.record("PUBLISH", "CONFIG_VERSION", String.valueOf(prepared.versionNo()),
                    null, prepared, context, false, null);
        } catch (Exception e) {
            log.error("版本指针分发失败: 版本[{}]", prepared.versionNo(), e);
            publicationRepository.updateStatus(prepared.publicationId(), PublicationStatus.FAILED,
                    "版本指针分发失败", new Date());
            auditService.record("PUBLISH", "CONFIG_VERSION", String.valueOf(prepared.versionNo()),
                    null, prepared, context, true, "版本指针分发失败");
            throw new SgwException(SgwErrorCode.DISPATCH_FAILED, "配置发布分发失败", e);
        }
    }

}
