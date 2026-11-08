package net.hwyz.iov.cloud.edd.sgw.application;

import net.hwyz.iov.cloud.edd.sgw.api.enums.ConfigOperation;
import net.hwyz.iov.cloud.edd.sgw.api.enums.InstancePublicationStatus;
import net.hwyz.iov.cloud.edd.sgw.api.enums.PublicationStatus;
import net.hwyz.iov.cloud.edd.sgw.api.enums.PublicationType;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.domain.model.ConfigSnapshot;
import net.hwyz.iov.cloud.edd.sgw.domain.model.SgwConfiguration;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.ConfigurationValidator;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.ValidationResult;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.ConfigWorkspacePo;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.PublicationPo;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.AuthPolicyRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.CanaryPolicyRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.ConfigVersionRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.InstancePublicationRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.PublicationRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.RouteRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.TrafficPolicyRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.WorkspaceRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * 发布事务：锁定工作区、校验完整配置、写入不可变版本与发布记录。
 * <p>
 * 版本指针分发在事务提交后由 {@link PublicationDispatcher} 执行。
 *
 * @author hwyz_leo
 */
@Service
public class PublishTransactionService {

    private final RouteRepository routeRepository;

    private final AuthPolicyRepository authPolicyRepository;

    private final TrafficPolicyRepository trafficPolicyRepository;

    private final CanaryPolicyRepository canaryPolicyRepository;

    private final ConfigVersionRepository configVersionRepository;

    private final PublicationRepository publicationRepository;

    private final InstancePublicationRepository instancePublicationRepository;

    private final WorkspaceRepository workspaceRepository;

    private final ConfigurationValidator configurationValidator;

    private final GatewayInstanceProvider gatewayInstanceProvider;

    public PublishTransactionService(RouteRepository routeRepository, AuthPolicyRepository authPolicyRepository,
                                     TrafficPolicyRepository trafficPolicyRepository,
                                     CanaryPolicyRepository canaryPolicyRepository,
                                     ConfigVersionRepository configVersionRepository,
                                     PublicationRepository publicationRepository,
                                     InstancePublicationRepository instancePublicationRepository,
                                     WorkspaceRepository workspaceRepository,
                                     ConfigurationValidator configurationValidator,
                                     GatewayInstanceProvider gatewayInstanceProvider) {
        this.routeRepository = routeRepository;
        this.authPolicyRepository = authPolicyRepository;
        this.trafficPolicyRepository = trafficPolicyRepository;
        this.canaryPolicyRepository = canaryPolicyRepository;
        this.configVersionRepository = configVersionRepository;
        this.publicationRepository = publicationRepository;
        this.instancePublicationRepository = instancePublicationRepository;
        this.workspaceRepository = workspaceRepository;
        this.configurationValidator = configurationValidator;
        this.gatewayInstanceProvider = gatewayInstanceProvider;
    }

    /**
     * 准备发布当前草稿修订
     *
     * @param draftRevision 草稿修订号
     * @param actor         操作者
     * @param comment       说明
     * @return 待分发发布
     */
    @Transactional
    public PreparedPublication preparePublish(long draftRevision, String actor, String comment) {
        ConfigWorkspacePo workspace = lockWorkspace(draftRevision);
        SgwConfiguration configuration = loadConfiguration();
        validateOrThrow(configuration);
        long versionNo = nextVersionNo(workspace);
        String snapshotJson = Json.write(configuration);
        String checksum = Json.sha256(snapshotJson);
        Long sourceVersionNo = workspace.getTargetVersionNo();

        ConfigSnapshot snapshot = ConfigSnapshot.builder()
                .versionNo(versionNo)
                .operation(ConfigOperation.PUBLISH)
                .sourceVersionNo(sourceVersionNo)
                .snapshotJson(snapshotJson)
                .checksum(checksum)
                .description(comment)
                .createBy(actor)
                .createTime(new Date())
                .build();
        configVersionRepository.insert(snapshot);

        String publicationId = UUID.randomUUID().toString();
        insertPublication(publicationId, versionNo, sourceVersionNo, PublicationType.PUBLISH, actor, comment);
        registerInstances(publicationId, versionNo);
        workspaceRepository.setTargetVersion(versionNo, actor);
        return new PreparedPublication(publicationId, versionNo, checksum, PublicationType.PUBLISH.name(),
                sourceVersionNo);
    }

    /**
     * 准备回滚发布
     *
     * @param versionNo     历史版本号
     * @param draftRevision 草稿修订号
     * @param actor         操作者
     * @param comment       说明
     * @return 待分发发布
     */
    @Transactional
    public PreparedPublication prepareRollback(long versionNo, long draftRevision, String actor, String comment) {
        ConfigWorkspacePo workspace = lockWorkspace(draftRevision);
        ConfigSnapshot source = configVersionRepository.findByVersionNo(versionNo)
                .orElseThrow(() -> new SgwException(SgwErrorCode.VALIDATION_FAILED,
                        "回滚目标版本不存在: " + versionNo));
        String checksum = Json.sha256(source.getSnapshotJson());
        if (!checksum.equals(source.getChecksum())) {
            throw new SgwException(SgwErrorCode.VALIDATION_FAILED, "历史版本校验和不匹配，拒绝回滚");
        }
        SgwConfiguration configuration = Json.read(source.getSnapshotJson(), SgwConfiguration.class);
        validateOrThrow(configuration);
        long newVersionNo = nextVersionNo(workspace);
        Long preRollbackVersion = workspace.getTargetVersionNo();

        ConfigSnapshot snapshot = ConfigSnapshot.builder()
                .versionNo(newVersionNo)
                .operation(ConfigOperation.ROLLBACK)
                .sourceVersionNo(versionNo)
                .snapshotJson(source.getSnapshotJson())
                .checksum(checksum)
                .description(comment == null ? "回滚到版本 " + versionNo : comment)
                .createBy(actor)
                .createTime(new Date())
                .build();
        configVersionRepository.insert(snapshot);

        String publicationId = UUID.randomUUID().toString();
        insertPublication(publicationId, newVersionNo, preRollbackVersion, PublicationType.ROLLBACK, actor,
                snapshot.getDescription());
        registerInstances(publicationId, newVersionNo);
        workspaceRepository.setTargetVersion(newVersionNo, actor);
        return new PreparedPublication(publicationId, newVersionNo, checksum, PublicationType.ROLLBACK.name(),
                preRollbackVersion);
    }

    /**
     * 准备重试发布（不改变目标版本的不可变内容）
     *
     * @param publicationId 原发布ID
     * @param actor         操作者
     * @return 待分发发布
     */
    @Transactional
    public PreparedPublication prepareRetry(String publicationId, String actor) {
        PublicationPo original = publicationRepository.findByPublicationId(publicationId)
                .orElseThrow(() -> new SgwException(SgwErrorCode.VALIDATION_FAILED,
                        "发布记录不存在: " + publicationId));
        PublicationStatus status = PublicationStatus.valueOf(original.getStatus());
        if (status != PublicationStatus.FAILED && status != PublicationStatus.PARTIAL_FAILED) {
            throw new SgwException(SgwErrorCode.CONFLICT, "仅允许重试失败或部分失败的发布");
        }
        ConfigSnapshot snapshot = configVersionRepository.findByVersionNo(original.getTargetVersionNo())
                .orElseThrow(() -> new SgwException(SgwErrorCode.VALIDATION_FAILED, "目标版本不存在，无法重试"));
        String checksum = Json.sha256(snapshot.getSnapshotJson());
        if (!checksum.equals(snapshot.getChecksum())) {
            throw new SgwException(SgwErrorCode.VALIDATION_FAILED, "目标版本校验和不匹配，拒绝重试");
        }
        String newPublicationId = UUID.randomUUID().toString();
        insertPublication(newPublicationId, original.getTargetVersionNo(), original.getSourceVersionNo(),
                PublicationType.RETRY, actor, "重试发布 " + publicationId);
        registerInstances(newPublicationId, original.getTargetVersionNo());
        return new PreparedPublication(newPublicationId, original.getTargetVersionNo(), checksum,
                PublicationType.RETRY.name(), original.getSourceVersionNo());
    }

    private ConfigWorkspacePo lockWorkspace(long draftRevision) {
        ConfigWorkspacePo workspace = workspaceRepository.lock();
        if (workspace == null) {
            throw new SgwException(SgwErrorCode.CONFLICT, "配置工作区不可用");
        }
        if (!java.util.Objects.equals(workspace.getDraftRevision(), draftRevision)) {
            throw new SgwException(SgwErrorCode.CONFLICT,
                    "草稿修订号不匹配，请刷新后重新发布");
        }
        return workspace;
    }

    private SgwConfiguration loadConfiguration() {
        SgwConfiguration configuration = SgwConfiguration.builder()
                .routes(routeRepository.findAllValid())
                .authPolicies(authPolicyRepository.findAllValid())
                .trafficPolicies(trafficPolicyRepository.findAllValid())
                .canaryPolicies(canaryPolicyRepository.findAllValid())
                .build();
        return configuration.normalized();
    }

    private void validateOrThrow(SgwConfiguration configuration) {
        ValidationResult result = configurationValidator.validate(configuration);
        result.throwIfInvalid(SgwErrorCode.VALIDATION_FAILED);
    }

    private long nextVersionNo(ConfigWorkspacePo workspace) {
        Long max = configVersionRepository.maxVersionNo();
        long candidate = Math.max(max == null ? 0 : max,
                workspace.getTargetVersionNo() == null ? 0 : workspace.getTargetVersionNo());
        return candidate + 1;
    }

    private void insertPublication(String publicationId, Long versionNo, Long sourceVersionNo, PublicationType type,
                                   String actor, String comment) {
        Date now = new Date();
        publicationRepository.insert(PublicationPo.builder()
                .publicationId(publicationId)
                .targetVersionNo(versionNo)
                .sourceVersionNo(sourceVersionNo)
                .type(type.name())
                .status(PublicationStatus.DISPATCHING.name())
                .actor(actor)
                .comment(comment)
                .createTime(now)
                .updateTime(now)
                .build());
    }

    private void registerInstances(String publicationId, Long versionNo) {
        Set<String> instanceIds = new HashSet<>(gatewayInstanceProvider.currentInstanceIds());
        for (String instanceId : instanceIds) {
            instancePublicationRepository.insertPending(publicationId, instanceId, versionNo);
        }
    }

}
