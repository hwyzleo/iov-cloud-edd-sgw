package net.hwyz.iov.cloud.edd.sgw.application;

import net.hwyz.iov.cloud.edd.sgw.api.vo.request.PublishConfigRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.RollbackRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigDiffItemVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigDiffResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigVersionDetailResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigVersionResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.PublicationResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.WorkspaceResponse;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.common.PageSlice;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.domain.model.AuthPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.ConfigSnapshot;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.SgwConfiguration;
import net.hwyz.iov.cloud.edd.sgw.domain.model.TrafficPolicy;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.ConfigWorkspacePo;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.ConfigVersionRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.WorkspaceRepository;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

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

    public ConfigVersionService(PublishTransactionService publishTransactionService,
                                PublicationDispatcher publicationDispatcher,
                                ConfigVersionRepository configVersionRepository,
                                WorkspaceRepository workspaceRepository,
                                PublicationService publicationService) {
        this.publishTransactionService = publishTransactionService;
        this.publicationDispatcher = publicationDispatcher;
        this.configVersionRepository = configVersionRepository;
        this.workspaceRepository = workspaceRepository;
        this.publicationService = publicationService;
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
        List<ConfigDiffItemVo> items = new ArrayList<>();
        compare("ROUTE", fromConfiguration.getRoutes(), toConfiguration.getRoutes(),
                RouteDefinition::getRouteCode, items);
        compare("AUTH_POLICY", fromConfiguration.getAuthPolicies(), toConfiguration.getAuthPolicies(),
                AuthPolicy::getPolicyCode, items);
        compare("TRAFFIC_POLICY", fromConfiguration.getTrafficPolicies(), toConfiguration.getTrafficPolicies(),
                TrafficPolicy::getPolicyCode, items);
        compare("CANARY_POLICY", fromConfiguration.getCanaryPolicies(), toConfiguration.getCanaryPolicies(),
                CanaryPolicy::getPolicyCode, items);
        return ConfigDiffResponse.builder().fromVersionNo(from).toVersionNo(to).items(items).build();
    }

    private <T> void compare(String type, List<T> from, List<T> to, java.util.function.Function<T, String> code,
                             List<ConfigDiffItemVo> items) {
        Map<String, String> fromMap = index(from, code);
        Map<String, String> toMap = index(to, code);
        Map<String, String> all = new LinkedHashMap<>(fromMap);
        toMap.forEach(all::putIfAbsent);
        for (String key : all.keySet()) {
            boolean inFrom = fromMap.containsKey(key);
            boolean inTo = toMap.containsKey(key);
            if (!inFrom) {
                items.add(item(type, key, "ADDED"));
            } else if (!inTo) {
                items.add(item(type, key, "REMOVED"));
            } else if (!fromMap.get(key).equals(toMap.get(key))) {
                items.add(item(type, key, "MODIFIED"));
            }
        }
    }

    private <T> Map<String, String> index(List<T> values, java.util.function.Function<T, String> code) {
        Map<String, String> result = new LinkedHashMap<>();
        for (T value : values) {
            result.put(code.apply(value), Json.canonical(value));
        }
        return result;
    }

    private ConfigDiffItemVo item(String type, String code, String changeType) {
        return ConfigDiffItemVo.builder().objectType(type).code(code).changeType(changeType).build();
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
