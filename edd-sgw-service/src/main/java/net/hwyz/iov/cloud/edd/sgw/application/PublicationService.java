package net.hwyz.iov.cloud.edd.sgw.application;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.sgw.api.enums.InstancePublicationStatus;
import net.hwyz.iov.cloud.edd.sgw.api.enums.PublicationStatus;
import net.hwyz.iov.cloud.edd.sgw.api.enums.PublicationType;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.RetryPublicationRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.InstancePublicationResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.PublicationResponse;
import net.hwyz.iov.cloud.edd.sgw.common.PageSlice;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.PublicationAggregator;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.InstancePublicationPo;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.PublicationPo;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.InstancePublicationRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.PublicationRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 发布记录用例与超时扫描。
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
public class PublicationService {

    private final PublishTransactionService publishTransactionService;

    private final PublicationDispatcher publicationDispatcher;

    private final PublicationRepository publicationRepository;

    private final InstancePublicationRepository instancePublicationRepository;

    private final PublicationAggregator publicationAggregator;

    private final SgwProperties properties;

    public PublicationService(PublishTransactionService publishTransactionService,
                              PublicationDispatcher publicationDispatcher,
                              PublicationRepository publicationRepository,
                              InstancePublicationRepository instancePublicationRepository,
                              PublicationAggregator publicationAggregator, SgwProperties properties) {
        this.publishTransactionService = publishTransactionService;
        this.publicationDispatcher = publicationDispatcher;
        this.publicationRepository = publicationRepository;
        this.instancePublicationRepository = instancePublicationRepository;
        this.publicationAggregator = publicationAggregator;
        this.properties = properties;
    }

    /**
     * 重试失败发布
     *
     * @param request 请求
     * @param context 上下文
     * @return 新发布记录
     */
    public PublicationResponse retry(RetryPublicationRequest request, AdminContext context) {
        PreparedPublication prepared = publishTransactionService.prepareRetry(request.getPublicationId(),
                context.actor());
        publicationDispatcher.dispatch(prepared, context);
        return get(prepared.publicationId());
    }

    /**
     * 分页查询发布记录
     *
     * @param page            页码
     * @param size            每页条数
     * @param status          状态
     * @param targetVersionNo 目标版本
     * @return 分页结果
     */
    public PageSlice<PublicationResponse> page(int page, int size, PublicationStatus status,
                                               Long targetVersionNo) {
        PageSlice<PublicationPo> slice = publicationRepository.page(page, size, status, targetVersionNo);
        return new PageSlice<>(slice.items().stream().map(this::toResponse).toList(),
                slice.total(), slice.page(), slice.size());
    }

    /**
     * 查询发布记录
     *
     * @param publicationId 发布ID
     * @return 发布记录
     */
    public PublicationResponse get(String publicationId) {
        PublicationPo publication = publicationRepository.findByPublicationId(publicationId)
                .orElseThrow(() -> new SgwException(SgwErrorCode.VALIDATION_FAILED,
                        "发布记录不存在: " + publicationId));
        List<InstancePublicationResponse> instances = instancePublicationRepository
                .findByPublicationId(publicationId).stream()
                .map(this::toInstanceResponse)
                .toList();
        return PublicationResponse.builder()
                .publicationId(publication.getPublicationId())
                .targetVersionNo(publication.getTargetVersionNo())
                .sourceVersionNo(publication.getSourceVersionNo())
                .type(PublicationType.valueOf(publication.getType()))
                .status(PublicationStatus.valueOf(publication.getStatus()))
                .actor(publication.getActor())
                .comment(publication.getComment())
                .createTime(Assembler.instant(publication.getCreateTime()))
                .updateTime(Assembler.instant(publication.getUpdateTime()))
                .completedAt(Assembler.instant(publication.getCompletedAt()))
                .errorMessage(publication.getErrorMessage())
                .instances(instances)
                .build();
    }

    private PublicationResponse toResponse(PublicationPo publication) {
        List<InstancePublicationResponse> instances = instancePublicationRepository
                .findByPublicationId(publication.getPublicationId()).stream()
                .map(this::toInstanceResponse)
                .toList();
        return PublicationResponse.builder()
                .publicationId(publication.getPublicationId())
                .targetVersionNo(publication.getTargetVersionNo())
                .sourceVersionNo(publication.getSourceVersionNo())
                .type(PublicationType.valueOf(publication.getType()))
                .status(PublicationStatus.valueOf(publication.getStatus()))
                .actor(publication.getActor())
                .comment(publication.getComment())
                .createTime(Assembler.instant(publication.getCreateTime()))
                .updateTime(Assembler.instant(publication.getUpdateTime()))
                .completedAt(Assembler.instant(publication.getCompletedAt()))
                .errorMessage(publication.getErrorMessage())
                .instances(instances)
                .build();
    }

    private InstancePublicationResponse toInstanceResponse(InstancePublicationPo po) {
        return InstancePublicationResponse.builder()
                .instanceId(po.getInstanceId())
                .targetVersionNo(po.getTargetVersionNo())
                .activeVersionNo(po.getActiveVersionNo())
                .status(InstancePublicationStatus.valueOf(po.getStatus()))
                .errorMessage(po.getErrorMessage())
                .reportTime(Assembler.instant(po.getReportTime()))
                .build();
    }

    /**
     * 发布超时扫描：未确认的实例结果标记为超时并重新聚合发布状态。
     */
    @Scheduled(fixedDelayString = "${sgw.publication.timeout-sweep-interval-millis:5000}")
    public void sweepTimeouts() {
        SgwProperties.Publication config = properties.getPublication();
        Date threshold = new Date(System.currentTimeMillis() - config.getDeadlineSeconds() * 1000L);
        Set<String> affected = new LinkedHashSet<>();
        List<InstancePublicationPo> pending = instancePublicationRepository
                .findPendingOlderThan(threshold, config.getTimeoutSweepBatchSize());
        for (InstancePublicationPo po : pending) {
            instancePublicationRepository.markTimeout(po.getId());
            affected.add(po.getPublicationId());
        }
        affected.forEach(publicationAggregator::recompute);
        for (PublicationPo publication : publicationRepository.findActiveOlderThan(threshold)) {
            List<InstancePublicationPo> instances = instancePublicationRepository
                    .findByPublicationId(publication.getPublicationId());
            if (instances.isEmpty()) {
                publicationRepository.updateStatus(publication.getPublicationId(), PublicationStatus.FAILED,
                        "实例未在发布时限内确认", new Date());
            } else {
                publicationAggregator.recompute(publication.getPublicationId());
            }
        }
    }

}
