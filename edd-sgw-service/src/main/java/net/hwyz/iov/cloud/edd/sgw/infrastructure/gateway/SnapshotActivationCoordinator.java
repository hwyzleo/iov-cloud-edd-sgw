package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.ConfigWorkspacePo;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.WorkspaceRepository;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import reactor.core.scheduler.Schedulers;

import jakarta.annotation.PostConstruct;

/**
 * 快照激活协调器：注册版本指针监听并在启动时完成首次加载。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class SnapshotActivationCoordinator implements ApplicationRunner {

    private final VersionPointerStore versionPointerStore;

    private final SnapshotManager snapshotManager;

    private final WorkspaceRepository workspaceRepository;

    public SnapshotActivationCoordinator(VersionPointerStore versionPointerStore, SnapshotManager snapshotManager,
                                         WorkspaceRepository workspaceRepository) {
        this.versionPointerStore = versionPointerStore;
        this.snapshotManager = snapshotManager;
        this.workspaceRepository = workspaceRepository;
    }

    @PostConstruct
    public void registerListener() {
        versionPointerStore.addListener(pointer -> Schedulers.boundedElastic().schedule(() -> {
            try {
                snapshotManager.activate(pointer, true);
            } catch (RuntimeException e) {
                log.error("应用版本指针失败: 版本[{}]", pointer.versionNo());
            }
        }));
    }

    @Override
    public void run(ApplicationArguments args) {
        Schedulers.boundedElastic().schedule(this::activateAtStartup);
    }

    private void activateAtStartup() {
        try {
            ConfigWorkspacePo workspace = workspaceRepository.get();
            Long targetVersion = workspace == null ? null : workspace.getTargetVersionNo();
            PublicationPointer pointer = versionPointerStore.current()
                    .orElseGet(() -> targetVersion == null
                            ? null : new PublicationPointer(targetVersion, null, null));
            if (pointer == null) {
                log.warn("无可用配置版本指针，服务网关保持未就绪");
                return;
            }
            snapshotManager.activate(pointer, pointer.publicationId() != null);
        } catch (RuntimeException e) {
            log.error("启动加载配置快照失败，实例保持未就绪");
        }
    }

}
