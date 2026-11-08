package net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import net.hwyz.iov.cloud.edd.sgw.api.enums.ConfigOperation;
import net.hwyz.iov.cloud.edd.sgw.common.PageSlice;
import net.hwyz.iov.cloud.edd.sgw.domain.model.ConfigSnapshot;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.mapper.ConfigVersionMapper;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.ConfigVersionPo;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.Optional;

/**
 * 不可变配置版本仓储。
 *
 * @author hwyz_leo
 */
@Repository
public class ConfigVersionRepository {

    private final ConfigVersionMapper mapper;

    public ConfigVersionRepository(ConfigVersionMapper mapper) {
        this.mapper = mapper;
    }

    public void insert(ConfigSnapshot snapshot) {
        ConfigVersionPo po = ConfigVersionPo.builder()
                .versionNo(snapshot.getVersionNo())
                .operation(snapshot.getOperation().name())
                .sourceVersionNo(snapshot.getSourceVersionNo())
                .snapshotJson(snapshot.getSnapshotJson())
                .checksum(snapshot.getChecksum())
                .description(snapshot.getDescription())
                .createBy(snapshot.getCreateBy())
                .createTime(snapshot.getCreateTime() == null ? new Date() : snapshot.getCreateTime())
                .build();
        mapper.insert(po);
    }

    public Optional<ConfigSnapshot> findByVersionNo(Long versionNo) {
        ConfigVersionPo po = mapper.selectOne(new LambdaQueryWrapper<ConfigVersionPo>()
                .eq(ConfigVersionPo::getVersionNo, versionNo));
        return Optional.ofNullable(po).map(this::toDomain);
    }

    public PageSlice<ConfigSnapshot> page(int page, int size) {
        Page<ConfigVersionPo> result = mapper.selectPage(new Page<>(page, size),
                new LambdaQueryWrapper<ConfigVersionPo>().orderByDesc(ConfigVersionPo::getVersionNo));
        return new PageSlice<>(result.getRecords().stream().map(this::toDomain).toList(),
                result.getTotal(), page, size);
    }

    public Long maxVersionNo() {
        ConfigVersionPo po = mapper.selectOne(new LambdaQueryWrapper<ConfigVersionPo>()
                .select(ConfigVersionPo::getVersionNo)
                .orderByDesc(ConfigVersionPo::getVersionNo)
                .last("LIMIT 1"));
        return po == null ? null : po.getVersionNo();
    }

    private ConfigSnapshot toDomain(ConfigVersionPo po) {
        return ConfigSnapshot.builder()
                .versionNo(po.getVersionNo())
                .operation(ConfigOperation.valueOf(po.getOperation()))
                .sourceVersionNo(po.getSourceVersionNo())
                .snapshotJson(po.getSnapshotJson())
                .checksum(po.getChecksum())
                .description(po.getDescription())
                .createBy(po.getCreateBy())
                .createTime(po.getCreateTime())
                .build();
    }

}
