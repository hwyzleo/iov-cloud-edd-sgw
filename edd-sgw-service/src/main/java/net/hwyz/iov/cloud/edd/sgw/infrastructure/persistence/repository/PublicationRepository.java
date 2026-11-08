package net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.LambdaUpdateWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import net.hwyz.iov.cloud.edd.sgw.api.enums.PublicationStatus;
import net.hwyz.iov.cloud.edd.sgw.common.PageSlice;
import net.hwyz.iov.cloud.edd.sgw.api.enums.PublicationType;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.mapper.PublicationMapper;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.PublicationPo;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * 发布记录仓储。
 *
 * @author hwyz_leo
 */
@Repository
public class PublicationRepository {

    private final PublicationMapper mapper;

    public PublicationRepository(PublicationMapper mapper) {
        this.mapper = mapper;
    }

    public void insert(PublicationPo po) {
        mapper.insert(po);
    }

    public Optional<PublicationPo> findByPublicationId(String publicationId) {
        return Optional.ofNullable(mapper.selectOne(new LambdaQueryWrapper<PublicationPo>()
                .eq(PublicationPo::getPublicationId, publicationId)));
    }

    public List<PublicationPo> findByTargetVersionNo(Long versionNo) {
        return mapper.selectList(new LambdaQueryWrapper<PublicationPo>()
                .eq(PublicationPo::getTargetVersionNo, versionNo)
                .orderByDesc(PublicationPo::getId));
    }

    public void updateStatus(String publicationId, PublicationStatus status, String errorMessage, Date completedAt) {
        mapper.update(null, new LambdaUpdateWrapper<PublicationPo>()
                .eq(PublicationPo::getPublicationId, publicationId)
                .set(PublicationPo::getStatus, status.name())
                .set(PublicationPo::getErrorMessage, errorMessage)
                .set(PublicationPo::getCompletedAt, completedAt)
                .set(PublicationPo::getUpdateTime, new Date()));
    }

    public void touch(String publicationId) {
        mapper.update(null, new LambdaUpdateWrapper<PublicationPo>()
                .eq(PublicationPo::getPublicationId, publicationId)
                .set(PublicationPo::getUpdateTime, new Date()));
    }

    /**
     * 查询超过时限仍处于活动状态的发布
     *
     * @param threshold 时间阈值
     * @return 发布记录
     */
    public List<PublicationPo> findActiveOlderThan(Date threshold) {
        return mapper.selectList(new LambdaQueryWrapper<PublicationPo>()
                .in(PublicationPo::getStatus, PublicationStatus.WAITING_ACK.name(),
                        PublicationStatus.DISPATCHING.name())
                .lt(PublicationPo::getCreateTime, threshold));
    }

    /**
     * 分页查询发布记录
     *
     * @param page            页码
     * @param size            每页条数
     * @param status          状态
     * @param targetVersionNo 目标版本
     * @return 分页结果
     */
    public PageSlice<PublicationPo> page(int page, int size, PublicationStatus status, Long targetVersionNo) {
        LambdaQueryWrapper<PublicationPo> wrapper = new LambdaQueryWrapper<PublicationPo>()
                .eq(status != null, PublicationPo::getStatus, status == null ? null : status.name())
                .eq(targetVersionNo != null, PublicationPo::getTargetVersionNo, targetVersionNo)
                .orderByDesc(PublicationPo::getId);
        Page<PublicationPo> result = mapper.selectPage(new Page<>(page, size), wrapper);
        return new PageSlice<>(result.getRecords(), result.getTotal(), page, size);
    }

    public PublicationType typeOf(PublicationPo po) {
        return PublicationType.valueOf(po.getType());
    }

}
