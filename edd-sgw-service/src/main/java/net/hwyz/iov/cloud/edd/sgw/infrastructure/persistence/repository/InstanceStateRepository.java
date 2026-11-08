package net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository;

import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.mapper.InstanceStateMapper;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.InstanceStatePo;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;

/**
 * 实例运行时状态仓储。
 *
 * @author hwyz_leo
 */
@Repository
public class InstanceStateRepository {

    private final InstanceStateMapper mapper;

    public InstanceStateRepository(InstanceStateMapper mapper) {
        this.mapper = mapper;
    }

    /**
     * 写入或更新实例状态
     *
     * @param instanceId       实例ID
     * @param activeVersion    生效版本
     * @param publicationId    发布ID
     * @param status           状态
     * @param errorMessage     脱敏错误
     */
    public void upsert(String instanceId, Long activeVersion, String publicationId, String status, String errorMessage) {
        InstanceStatePo existing = mapper.selectById(instanceId);
        InstanceStatePo po = InstanceStatePo.builder()
                .instanceId(instanceId)
                .activeVersionNo(activeVersion)
                .lastPublicationId(publicationId)
                .status(status)
                .lastError(errorMessage)
                .updateTime(new Date())
                .build();
        if (existing == null) {
            mapper.insert(po);
        } else {
            mapper.updateById(po);
        }
    }

    public InstanceStatePo find(String instanceId) {
        return mapper.selectById(instanceId);
    }

    public List<InstanceStatePo> findAll() {
        return mapper.selectList(null);
    }

}
