package net.hwyz.iov.cloud.edd.sgw.application;

import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;
import net.hwyz.iov.cloud.edd.sgw.api.enums.ConfigOperation;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.domain.model.AuthPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.ConfigSnapshot;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteMatch;
import net.hwyz.iov.cloud.edd.sgw.domain.model.SgwConfiguration;
import net.hwyz.iov.cloud.edd.sgw.domain.model.TrafficPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.ConfigurationValidator;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.ValidationResult;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.ConfigWorkspacePo;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.AuthPolicyRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.CanaryPolicyRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.ConfigVersionRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.InstancePublicationRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.PublicationRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.RouteRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.TrafficPolicyRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.WorkspaceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * 草稿装配器测试（EDD-SGW-DSN-CR-004，TC-004-6）。
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
class DraftConfigurationLoaderTest {

    @Mock
    private RouteRepository routeRepository;

    @Mock
    private AuthPolicyRepository authPolicyRepository;

    @Mock
    private TrafficPolicyRepository trafficPolicyRepository;

    @Mock
    private CanaryPolicyRepository canaryPolicyRepository;

    @Mock
    private ConfigVersionRepository configVersionRepository;

    @Mock
    private PublicationRepository publicationRepository;

    @Mock
    private InstancePublicationRepository instancePublicationRepository;

    @Mock
    private WorkspaceRepository workspaceRepository;

    @Mock
    private GatewayInstanceProvider gatewayInstanceProvider;

    @Mock
    private ConfigurationValidator configurationValidator;

    private DraftConfigurationLoader loader;

    @BeforeEach
    void setUp() {
        loader = new DraftConfigurationLoader(routeRepository, authPolicyRepository, trafficPolicyRepository,
                canaryPolicyRepository);
    }

    @Test
    @DisplayName("草稿装配器读取四类有效草稿并规范化嵌套集合")
    void loadsAndNormalizesValidDrafts() {
        when(routeRepository.findAllValid()).thenReturn(List.of(RouteDefinition.builder()
                .routeCode("vehicle-profile")
                .match(RouteMatch.builder().paths(null).build())
                .build()));
        when(authPolicyRepository.findAllValid()).thenReturn(List.of(AuthPolicy.builder()
                .policyCode("auth").accessMode(AccessMode.AUTHENTICATED).enabled(true).build()));
        when(trafficPolicyRepository.findAllValid()).thenReturn(List.of(TrafficPolicy.builder()
                .policyCode("traffic").enabled(true).build()));
        when(canaryPolicyRepository.findAllValid()).thenReturn(List.of(CanaryPolicy.builder()
                .policyCode("canary").enabled(true).build()));

        SgwConfiguration configuration = loader.load();

        assertThat(configuration.getRoutes()).extracting(RouteDefinition::getRouteCode).containsExactly("vehicle-profile");
        assertThat(configuration.getRoutes().get(0).getMatch().getPaths()).isEmpty();
        assertThat(configuration.getAuthPolicies()).extracting(AuthPolicy::getPolicyCode).containsExactly("auth");
        assertThat(configuration.getTrafficPolicies()).extracting(TrafficPolicy::getPolicyCode)
                .containsExactly("traffic");
        assertThat(configuration.getCanaryPolicies()).extracting(CanaryPolicy::getPolicyCode).containsExactly("canary");
        verify(routeRepository).findAllValid();
        verify(authPolicyRepository).findAllValid();
        verify(trafficPolicyRepository).findAllValid();
        verify(canaryPolicyRepository).findAllValid();
    }

    @Test
    @DisplayName("发布事务与预览共用同一草稿装配器，发布快照内容与装配结果一致")
    void publishUsesSharedLoader() {
        SgwConfiguration draft = SgwConfiguration.builder()
                .routes(List.of(RouteDefinition.builder().routeCode("vehicle-profile").priority(100)
                        .match(RouteMatch.builder().paths(List.of("/v1")).build()).build()))
                .authPolicies(List.of())
                .trafficPolicies(List.of())
                .canaryPolicies(List.of())
                .build();
        ConfigWorkspacePo workspace = new ConfigWorkspacePo();
        workspace.setId(1L);
        workspace.setDraftRevision(7L);
        workspace.setTargetVersionNo(null);
        when(workspaceRepository.lock()).thenReturn(workspace);
        when(configVersionRepository.maxVersionNo()).thenReturn(null);
        when(routeRepository.findAllValid()).thenReturn(draft.getRoutes());
        when(authPolicyRepository.findAllValid()).thenReturn(List.of());
        when(trafficPolicyRepository.findAllValid()).thenReturn(List.of());
        when(canaryPolicyRepository.findAllValid()).thenReturn(List.of());
        when(configurationValidator.validate(any())).thenReturn(ValidationResult.ok());
        when(gatewayInstanceProvider.currentInstanceIds()).thenReturn(List.of());

        PublishTransactionService publishTransactionService = new PublishTransactionService(loader,
                configVersionRepository, publicationRepository, instancePublicationRepository, workspaceRepository,
                configurationValidator, gatewayInstanceProvider);
        publishTransactionService.preparePublish(7L, "it-admin", "发布");

        ArgumentCaptor<ConfigSnapshot> captor = ArgumentCaptor.forClass(ConfigSnapshot.class);
        verify(configVersionRepository).insert(captor.capture());
        ConfigSnapshot inserted = captor.getValue();
        assertThat(inserted.getOperation()).isEqualTo(ConfigOperation.PUBLISH);
        assertThat(Json.read(inserted.getSnapshotJson(), SgwConfiguration.class))
                .isEqualTo(loader.load());
    }

}
