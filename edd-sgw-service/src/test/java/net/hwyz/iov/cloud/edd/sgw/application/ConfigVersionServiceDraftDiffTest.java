package net.hwyz.iov.cloud.edd.sgw.application;

import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigDiffItemVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigFieldDiffVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.DraftConfigDiffResponse;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.domain.model.ConfigSnapshot;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteMatch;
import net.hwyz.iov.cloud.edd.sgw.domain.model.SgwConfiguration;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.ConfigWorkspacePo;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.ConfigVersionRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.WorkspaceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * 待发布变更预览用例测试（EDD-SGW-DSN-CR-004，TC-004-4/5/7/8）。
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
class ConfigVersionServiceDraftDiffTest {

    @Mock
    private PublishTransactionService publishTransactionService;

    @Mock
    private PublicationDispatcher publicationDispatcher;

    @Mock
    private ConfigVersionRepository configVersionRepository;

    @Mock
    private WorkspaceRepository workspaceRepository;

    @Mock
    private PublicationService publicationService;

    @Mock
    private DraftConfigurationLoader draftConfigurationLoader;

    private ConfigVersionService service;

    @BeforeEach
    void setUp() {
        service = new ConfigVersionService(publishTransactionService, publicationDispatcher, configVersionRepository,
                workspaceRepository, publicationService, draftConfigurationLoader, new ConfigurationDiffService());
    }

    @Test
    @DisplayName("首次发布前无基准版本：baseVersionNo 为空，全部有效草稿对象为新增")
    void returnsAllAddedWithoutBaseVersion() {
        when(workspaceRepository.find()).thenReturn(workspace(null, 18L));
        when(draftConfigurationLoader.load()).thenReturn(SgwConfiguration.builder()
                .routes(List.of(route("vehicle-profile", 100)))
                .build());

        DraftConfigDiffResponse response = service.draftDiff();

        assertThat(response.getBaseVersionNo()).isNull();
        assertThat(response.getDraftRevision()).isEqualTo(18L);
        assertThat(response.getItems()).hasSize(1);
        ConfigDiffItemVo item = response.getItems().get(0);
        assertThat(item.getObjectType()).isEqualTo("ROUTE");
        assertThat(item.getCode()).isEqualTo("vehicle-profile");
        assertThat(item.getChangeType()).isEqualTo("ADDED");
        assertThat(item.getAfter().get("priority").asInt()).isEqualTo(100);
        verify(configVersionRepository, never()).findByVersionNo(anyLong());
    }

    @Test
    @DisplayName("以工作区目标版本为基准返回对象级与字段级差异及草稿修订号")
    void comparesWorkspaceTargetVersionWithDraft() {
        when(workspaceRepository.find()).thenReturn(workspace(5L, 21L));
        when(configVersionRepository.findByVersionNo(5L))
                .thenReturn(Optional.of(snapshot(5L, SgwConfiguration.builder()
                        .routes(List.of(route("vehicle-profile", 100)))
                        .build())));
        when(draftConfigurationLoader.load()).thenReturn(SgwConfiguration.builder()
                .routes(List.of(route("vehicle-profile", 200)))
                .build());

        DraftConfigDiffResponse response = service.draftDiff();

        assertThat(response.getBaseVersionNo()).isEqualTo(5L);
        assertThat(response.getDraftRevision()).isEqualTo(21L);
        ConfigDiffItemVo item = response.getItems().get(0);
        assertThat(item.getChangeType()).isEqualTo("MODIFIED");
        assertThat(item.getBefore().get("priority").asInt()).isEqualTo(100);
        assertThat(item.getAfter().get("priority").asInt()).isEqualTo(200);
        assertThat(item.getFields()).extracting(ConfigFieldDiffVo::getPath).containsExactly("/priority");
    }

    @Test
    @DisplayName("无差异时返回空差异集合")
    void returnsEmptyItemsWhenDraftEqualsPublishedVersion() {
        SgwConfiguration configuration = SgwConfiguration.builder()
                .routes(List.of(route("vehicle-profile", 100)))
                .build();
        when(workspaceRepository.find()).thenReturn(workspace(5L, 21L));
        when(configVersionRepository.findByVersionNo(5L)).thenReturn(Optional.of(snapshot(5L, configuration)));
        when(draftConfigurationLoader.load()).thenReturn(SgwConfiguration.builder()
                .routes(List.of(route("vehicle-profile", 100)))
                .build());

        DraftConfigDiffResponse response = service.draftDiff();

        assertThat(response.getBaseVersionNo()).isEqualTo(5L);
        assertThat(response.getItems()).isEmpty();
    }

    @Test
    @DisplayName("基准版本不存在返回 SGW-400001")
    void rejectsMissingBaseVersion() {
        when(workspaceRepository.find()).thenReturn(workspace(5L, 21L));
        when(configVersionRepository.findByVersionNo(5L)).thenReturn(Optional.empty());

        assertThatThrownBy(service::draftDiff)
                .isInstanceOf(SgwException.class)
                .extracting(exception -> ((SgwException) exception).errorCode())
                .isEqualTo(SgwErrorCode.VALIDATION_FAILED);
        verify(draftConfigurationLoader, never()).load();
    }

    @Test
    @DisplayName("基准版本校验和不匹配返回 SGW-400001 且不返回未校验内容")
    void rejectsTamperedBaseVersion() {
        ConfigSnapshot snapshot = snapshot(5L, SgwConfiguration.builder()
                .routes(List.of(route("vehicle-profile", 100)))
                .build());
        snapshot.setChecksum("tampered");
        when(workspaceRepository.find()).thenReturn(workspace(5L, 21L));
        when(configVersionRepository.findByVersionNo(5L)).thenReturn(Optional.of(snapshot));

        assertThatThrownBy(service::draftDiff)
                .isInstanceOf(SgwException.class)
                .extracting(exception -> ((SgwException) exception).errorCode())
                .isEqualTo(SgwErrorCode.VALIDATION_FAILED);
        verify(draftConfigurationLoader, never()).load();
    }

    @Test
    @DisplayName("工作区不存在返回 SGW-409001 且不初始化工作区、不写入任何记录")
    void rejectsMissingWorkspaceWithoutInitialization() {
        when(workspaceRepository.find()).thenReturn(null);

        assertThatThrownBy(service::draftDiff)
                .isInstanceOf(SgwException.class)
                .extracting(exception -> ((SgwException) exception).errorCode())
                .isEqualTo(SgwErrorCode.CONFLICT);
        verify(workspaceRepository, never()).get();
        verify(workspaceRepository, never()).lock();
        verify(workspaceRepository, never()).ensureInitialized();
        verifyNoInteractions(configVersionRepository, draftConfigurationLoader);
    }

    @Test
    @DisplayName("预览为只读操作，不产生版本、发布记录或工作区变更")
    void previewHasNoWriteSideEffects() {
        when(workspaceRepository.find()).thenReturn(workspace(5L, 21L));
        when(configVersionRepository.findByVersionNo(5L)).thenReturn(Optional.of(snapshot(5L,
                SgwConfiguration.builder().routes(List.of(route("vehicle-profile", 100))).build())));
        when(draftConfigurationLoader.load()).thenReturn(SgwConfiguration.builder()
                .routes(List.of(route("vehicle-profile", 200)))
                .build());

        service.draftDiff();

        verify(configVersionRepository, never()).insert(any());
        verify(configVersionRepository, never()).maxVersionNo();
        verify(workspaceRepository, never()).setTargetVersion(any(), any());
        verify(workspaceRepository, never()).bumpDraftRevision(any());
        verifyNoInteractions(publishTransactionService, publicationDispatcher, publicationService);
    }

    private ConfigWorkspacePo workspace(Long targetVersionNo, Long draftRevision) {
        ConfigWorkspacePo workspace = new ConfigWorkspacePo();
        workspace.setId(1L);
        workspace.setTargetVersionNo(targetVersionNo);
        workspace.setDraftRevision(draftRevision);
        workspace.setRowVersion(3);
        return workspace;
    }

    private ConfigSnapshot snapshot(Long versionNo, SgwConfiguration configuration) {
        String json = Json.write(configuration.normalized());
        return ConfigSnapshot.builder()
                .versionNo(versionNo)
                .snapshotJson(json)
                .checksum(Json.sha256(json))
                .build();
    }

    private RouteDefinition route(String code, int priority) {
        return RouteDefinition.builder()
                .routeCode(code)
                .routeName(code)
                .priority(priority)
                .match(RouteMatch.builder().paths(new ArrayList<>(List.of("/v1"))).build())
                .build();
    }

}
