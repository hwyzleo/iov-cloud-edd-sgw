package net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.LambdaUpdateWrapper;
import net.hwyz.iov.cloud.edd.sgw.api.enums.InstancePublicationStatus;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.mapper.InstancePublicationMapper;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.InstancePublicationPo;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * 逐实例发布结果仓储。
 *
 * @author hwyz_leo
 */
@Repository
public class InstancePublicationRepository {

    private final InstancePublicationMapper mapper;

    public InstancePublicationRepository(InstancePublicationMapper mapper) {
        this.mapper = mapper;
    }

    /**
     * 登记一个待确认的实例结果
     *
     * @param publicationId 发布ID
     * @param instanceId    实例ID
     * @param versionNo     目标版本号
     */
    public void insertPending(String publicationId, String instanceId, Long versionNo) {
        Date now = new Date();
        InstancePublicationPo po = InstancePublicationPo.builder()
                .publicationId(publicationId)
                .instanceId(instanceId)
                .targetVersionNo(versionNo)
                .status(InstancePublicationStatus.PENDING.name())
                .createTime(now)
                .build();
        mapper.insert(po);
    }

    /**
     * 记录实例应用结果（不存在时补登记）
     *
     * @param publicationId  发布ID
     * @param instanceId     实例ID
     * @param targetVersion  目标版本
     * @param activeVersion  生效版本
     * @param status         状态
     * @param errorMessage   脱敏错误
     */
    public void recordResult(String publicationId, String instanceId, Long targetVersion, Long activeVersion,
                             InstancePublicationStatus status, String errorMessage) {
        Date now = new Date();
        int rows = mapper.update(null, new LambdaUpdateWrapper<InstancePublicationPo>()
                .eq(InstancePublicationPo::getPublicationId, publicationId)
                .eq(InstancePublicationPo::getInstanceId, instanceId)
                .set(InstancePublicationPo::getActiveVersionNo, activeVersion)
                .set(InstancePublicationPo::getStatus, status.name())
                .set(InstancePublicationPo::getErrorMessage, errorMessage)
                .set(InstancePublicationPo::getReportTime, now));
        if (rows == 0) {
            InstancePublicationPo po = InstancePublicationPo.builder()
                    .publicationId(publicationId)
                    .instanceId(instanceId)
                    .targetVersionNo(targetVersion)
                    .activeVersionNo(activeVersion)
                    .status(status.name())
                    .errorMessage(errorMessage)
                    .reportTime(now)
                    .createTime(now)
                    .build();
            mapper.insert(po);
        }
    }

    public List<InstancePublicationPo> findByPublicationId(String publicationId) {
        return mapper.selectList(new LambdaQueryWrapper<InstancePublicationPo>()
                .eq(InstancePublicationPo::getPublicationId, publicationId)
                .orderByAsc(InstancePublicationPo::getInstanceId));
    }

    public Optional<InstancePublicationPo> find(String publicationId, String instanceId) {
        return Optional.ofNullable(mapper.selectOne(new LambdaQueryWrapper<InstancePublicationPo>()
                .eq(InstancePublicationPo::getPublicationId, publicationId)
                .eq(InstancePublicationPo::getInstanceId, instanceId)));
    }

    /**
     * 查询超时未确认的实例结果
     *
     * @param threshold 创建时间阈值
     * @param limit     批量上限
     * @return 记录
     */
    public List<InstancePublicationPo> findPendingOlderThan(Date threshold, int limit) {
        return mapper.selectList(new LambdaQueryWrapper<InstancePublicationPo>()
                .eq(InstancePublicationPo::getStatus, InstancePublicationStatus.PENDING.name())
                .lt(InstancePublicationPo::getCreateTime, threshold)
                .last("LIMIT " + limit));
    }

    public void markTimeout(Long id) {
        mapper.update(null, new LambdaUpdateWrapper<InstancePublicationPo>()
                .eq(InstancePublicationPo::getId, id)
                .eq(InstancePublicationPo::getStatus, InstancePublicationStatus.PENDING.name())
                .set(InstancePublicationPo::getStatus, InstancePublicationStatus.TIMEOUT.name())
                .set(InstancePublicationPo::getErrorMessage, "实例未在发布时限内确认")
                .set(InstancePublicationPo::getReportTime, new Date()));
    }

    public void deleteByPublicationId(String publicationId) {
        mapper.delete(new LambdaQueryWrapper<InstancePublicationPo>()
                .eq(InstancePublicationPo::getPublicationId, publicationId));
    }

}
