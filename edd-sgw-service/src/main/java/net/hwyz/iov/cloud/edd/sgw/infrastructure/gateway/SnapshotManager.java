package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.domain.model.ConfigSnapshot;
import net.hwyz.iov.cloud.edd.sgw.domain.model.SgwConfiguration;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.ConfigurationValidator;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.ValidationResult;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.ConfigVersionRepository;
import org.springframework.stereotype.Component;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 运行时快照管理器。
 * <p>
 * 每个实例只持有一个不可变快照；新快照在侧路完成校验与编译后原子替换。
 * 任何加载或编译失败都不会影响当前生效快照。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class SnapshotManager {

    private final ConfigVersionRepository configVersionRepository;

    private final SnapshotCompiler snapshotCompiler;

    private final ConfigurationValidator configurationValidator;

    private final GovernanceRegistry governanceRegistry;

    private final InstanceAckService instanceAckService;

    private final AtomicReference<CompiledSnapshot> active = new AtomicReference<>();

    private final AtomicReference<String> lastAckedPublicationId = new AtomicReference<>();

    private volatile boolean ready;

    public SnapshotManager(ConfigVersionRepository configVersionRepository, SnapshotCompiler snapshotCompiler,
                           ConfigurationValidator configurationValidator, GovernanceRegistry governanceRegistry,
                           InstanceAckService instanceAckService) {
        this.configVersionRepository = configVersionRepository;
        this.snapshotCompiler = snapshotCompiler;
        this.configurationValidator = configurationValidator;
        this.governanceRegistry = governanceRegistry;
        this.instanceAckService = instanceAckService;
    }

    /**
     * 当前生效快照
     *
     * @return 快照，未激活时为 null
     */
    public CompiledSnapshot current() {
        return active.get();
    }

    /**
     * 是否就绪（必须存在有效生效快照）
     *
     * @return 是否就绪
     */
    public boolean isReady() {
        return ready && active.get() != null;
    }

    /**
     * 当前生效版本号
     *
     * @return 版本号，未激活时为 null
     */
    public Long activeVersionNo() {
        CompiledSnapshot snapshot = active.get();
        return snapshot == null ? null : snapshot.getVersionNo();
    }

    /**
     * 激活目标版本
     *
     * @param pointer   版本指针
     * @param recordAck 是否记录实例确认
     */
    public synchronized void activate(PublicationPointer pointer, boolean recordAck) {
        if (pointer == null || pointer.versionNo() == null) {
            ready = false;
            log.warn("未找到目标配置版本，实例保持未就绪");
            return;
        }
        CompiledSnapshot current = active.get();
        if (current != null && current.getVersionNo() == pointer.versionNo()
                && Objects.equals(lastAckedPublicationId.get(), pointer.publicationId())) {
            log.debug("目标版本[{}]已生效，跳过重复激活", pointer.versionNo());
            return;
        }
        try {
            ConfigSnapshot snapshot = configVersionRepository.findByVersionNo(pointer.versionNo())
                    .orElseThrow(() -> new IllegalStateException("目标配置版本不存在"));
            String checksum = Json.sha256(snapshot.getSnapshotJson());
            if (!checksum.equals(snapshot.getChecksum())) {
                throw new IllegalStateException("配置快照校验和不匹配");
            }
            if (pointer.checksum() != null && !pointer.checksum().equals(checksum)) {
                throw new IllegalStateException("版本指针校验和不匹配");
            }
            SgwConfiguration configuration = Json.read(snapshot.getSnapshotJson(), SgwConfiguration.class);
            ValidationResult validation = configurationValidator.validate(configuration);
            if (!validation.valid()) {
                throw new IllegalStateException("配置快照校验失败: " + validation.message());
            }
            CompiledSnapshot compiled = snapshotCompiler.compile(pointer.versionNo(), checksum, configuration);
            governanceRegistry.rebuild(configuration);
            active.set(compiled);
            lastAckedPublicationId.set(pointer.publicationId());
            ready = true;
            log.info("配置快照已激活: 版本[{}], 路由[{}]", compiled.getVersionNo(), compiled.getRoutes().size());
            if (recordAck) {
                instanceAckService.recordSuccess(pointer.publicationId(), pointer.versionNo(), pointer.versionNo());
            }
        } catch (RuntimeException e) {
            String message = sanitize(e.getMessage());
            log.error("配置快照激活失败: 版本[{}], 原因: {}", pointer.versionNo(), message);
            if (recordAck) {
                instanceAckService.recordFailure(pointer.publicationId(), pointer.versionNo(), activeVersionNo(), message);
            }
            if (active.get() == null) {
                ready = false;
                governanceRegistry.clear();
            }
            throw e instanceof SgwException sgwException
                    ? sgwException
                    : new SgwException(SgwErrorCode.DISPATCH_FAILED, message, e);
        }
    }

    private String sanitize(String message) {
        if (message == null) {
            return "未知错误";
        }
        return Json.truncate(message.replaceAll("(?i)(secret|password|token)=[^,\\s]+", "$1=***"), 500);
    }

}
