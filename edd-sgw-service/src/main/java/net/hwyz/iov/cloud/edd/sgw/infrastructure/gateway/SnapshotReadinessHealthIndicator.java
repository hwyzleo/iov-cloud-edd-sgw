package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * 就绪探针：只有加载并激活有效目标快照后才报告可用。
 *
 * @author hwyz_leo
 */
@Component("sgwSnapshot")
public class SnapshotReadinessHealthIndicator implements HealthIndicator {

    private final SnapshotManager snapshotManager;

    public SnapshotReadinessHealthIndicator(SnapshotManager snapshotManager) {
        this.snapshotManager = snapshotManager;
    }

    @Override
    public Health health() {
        if (!snapshotManager.isReady()) {
            return Health.down().withDetail("reason", "未加载有效配置快照").build();
        }
        return Health.up()
                .withDetail("activeVersion", snapshotManager.activeVersionNo())
                .build();
    }

}
