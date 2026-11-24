package net.hwyz.iov.cloud.edd.sgw.application;

import net.hwyz.iov.cloud.edd.sgw.api.vo.request.PublishConfigRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.RollbackRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigDiffItemVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigDiffResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigVersionDetailResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigVersionResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.DraftConfigDiffResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.PublicationResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.WorkspaceResponse;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.common.PageSlice;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.domain.model.ConfigSnapshot;
import net.hwyz.iov.cloud.edd.sgw.domain.model.SgwConfiguration;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.ConfigWorkspacePo;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.ConfigVersionRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.WorkspaceRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * 配置版本与回滚用例。
 *
 * @author hwyz_leo
 */
@Service
public class ConfigVersionService {

    private final PublishTransactionService publishTransactionService;

    private final PublicationDispatcher publicationDispatcher;

    private final ConfigVersionRepository configVersionRepository;

    private final WorkspaceRepository workspaceRepository;

    private final PublicationService publicationService;

    private final DraftConfigurationLoader draftConfigurationLoader;

    private final ConfigurationDiffService configurationDiffService;

    public ConfigVersionService(PublishTransactionService publishTransactionService,
                                PublicationDispatcher publicationDispatcher,
                                ConfigVersionRepository configVersionRepository,
                                WorkspaceRepository workspaceRepository,
                                PublicationService publicationService,
                                DraftConfigurationLoader draftConfigurationLoader,
                                ConfigurationDiffService configurationDiffService) {
        this.publishTransactionService = publishTransactionService;
        this.publicationDispatcher = publicationDispatcher;
        this.configVersionRepository = configVersionRepository;
        this.workspaceRepository = workspaceRepository;
        this.publicationService = publicationService;
        this.draftConfigurationLoader = draftConfigurationLoader;
        this.configurationDiffService = configurationDiffService;
    }

    /**
     * 当前工作区状态
     *
     * @return 工作区
     */
    public WorkspaceResponse workspace() {
        ConfigWorkspacePo workspace = workspaceRepository.get();
        return WorkspaceResponse.builder()
                .draftRevision(workspace.getDraftRevision())
                .targetVersionNo(workspace.getTargetVersionNo())
                .rowVersion(workspace.getRowVersion())
                .build();
    }

    /**
     * 校验并发布当前草稿修订
     *
     * @param request 发布请求
     * @param context 上下文
     * @return 发布记录
     */
    public PublicationResponse publish(PublishConfigRequest request, AdminContext context) {
        PreparedPublication prepared = publishTransactionService.preparePublish(request.getDraftRevision(),
                context.actor(), request.getComment());
        publicationDispatcher.dispatch(prepared, context);
        return publicationService.get(prepared.publicationId());
    }

    /**
     * 创建并发布回滚版本
     *
     * @param versionNo 历史版本
     * @param request   回滚请求
     * @param context   上下文
     * @return 发布记录
     */
    public PublicationResponse rollback(Long versionNo, RollbackRequest request, AdminContext context) {
        PreparedPublication prepared = publishTransactionService.prepareRollback(versionNo,
                request.getDraftRevision(), context.actor(), request.getComment());
        publicationDispatcher.dispatch(prepared, context);
        return publicationService.get(prepared.publicationId());
    }

    /**
     * 版本历史
     *
     * @param page 页码
     * @param size 每页条数
     * @return 版本分页
     */
    public PageSlice<ConfigVersionResponse> history(int page, int size) {
        Long current = currentTargetVersion();
        PageSlice<ConfigSnapshot> slice = configVersionRepository.page(page, size);
        return new PageSlice<>(slice.items().stream()
                .map(snapshot -> Assembler.toVersionResponse(snapshot, current)).toList(),
                slice.total(), slice.page(), slice.size());
    }

    /**
     * 不可变版本详情
     *
     * @param versionNo 版本号
     * @return 版本详情
     */
    public ConfigVersionDetailResponse detail(Long versionNo) {
        ConfigSnapshot snapshot = loadVerified(versionNo);
        SgwConfiguration configuration = Json.read(snapshot.getSnapshotJson(), SgwConfiguration.class);
        Long current = currentTargetVersion();
        return ConfigVersionDetailResponse.builder()
                .versionNo(snapshot.getVersionNo())
                .operation(snapshot.getOperation())
                .sourceVersionNo(snapshot.getSourceVersionNo())
                .checksum(snapshot.getChecksum())
                .description(snapshot.getDescription())
                .createBy(snapshot.getCreateBy())
                .createTime(Assembler.instant(snapshot.getCreateTime()))
                .current(current != null && current.equals(snapshot.getVersionNo()))
                .snapshot(Assembler.toSnapshotVo(configuration))
                .build();
    }

    /**
     * 结构化版本差异
     *
     * @param from 起始版本
     * @param to   目标版本
     * @return 差异
     */
    public ConfigDiffResponse diff(Long from, Long to) {
        SgwConfiguration fromConfiguration = Json.read(loadVerified(from).getSnapshotJson(), SgwConfiguration.class);
        SgwConfiguration toConfiguration = Json.read(loadVerified(to).getSnapshotJson(), SgwConfiguration.class);
        List<ConfigDiffItemVo> items = configurationDiffService.compare(fromConfiguration, toConfiguration);
        return ConfigDiffResponse.builder().fromVersionNo(from).toVersionNo(to).items(items).build();
    }

    /**
     * 待发布配置变更预览（EDD-SGW-DSN-CR-004）：当前发布版本与工作区草稿的只读一致比较。
     * <p>
     * 事务内首个查询为工作区，使基准快照与四类草稿处于同一数据库一致读视图；不锁定工作区、不写入任何记录。
     *
     * @return 待发布差异
     */
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public DraftConfigDiffResponse draftDiff() {
        ConfigWorkspacePo workspace = workspaceRepository.find();
        if (workspace == null) {
            throw new SgwException(SgwErrorCode.CONFLICT, "配置工作区不可用");
        }
        Long baseVersionNo = workspace.getTargetVersionNo();
        SgwConfiguration base = baseVersionNo == null
                ? SgwConfiguration.builder().build().normalized()
                : Json.read(loadVerified(baseVersionNo).getSnapshotJson(), SgwConfiguration.class);
        SgwConfiguration draft = draftConfigurationLoader.load();
        return DraftConfigDiffResponse.builder()
                .baseVersionNo(baseVersionNo)
                .draftRevision(workspace.getDraftRevision())
                .items(configurationDiffService.compare(base, draft))
                .build();
    }

    private ConfigSnapshot loadVerified(Long versionNo) {
        ConfigSnapshot snapshot = configVersionRepository.findByVersionNo(versionNo)
                .orElseThrow(() -> new SgwException(SgwErrorCode.VALIDATION_FAILED, "版本不存在: " + versionNo));
        String checksum = Json.sha256(snapshot.getSnapshotJson());
        if (!checksum.equals(snapshot.getChecksum())) {
            throw new SgwException(SgwErrorCode.VALIDATION_FAILED, "版本校验和不匹配: " + versionNo);
        }
        return snapshot;
    }

    private Long currentTargetVersion() {
        ConfigWorkspacePo workspace = workspaceRepository.get();
        return workspace == null ? null : workspace.getTargetVersionNo();
    }

}
