package net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository;

import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.mapper.ConfigChangeLogMapper;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.ConfigChangeLogPo;
import org.springframework.stereotype.Repository;

import java.util.Date;

/**
 * 配置变更审计仓储。
 *
 * @author hwyz_leo
 */
@Repository
public class ChangeLogRepository {

    private final ConfigChangeLogMapper mapper;

    public ChangeLogRepository(ConfigChangeLogMapper mapper) {
        this.mapper = mapper;
    }

    /**
     * 写入审计记录
     *
     * @param actor         操作者
     * @param action        动作
     * @param objectType    对象类型
     * @param objectCode    对象编码
     * @param beforeJson    变更前
     * @param afterJson     变更后
     * @param success       是否成功
     * @param failureReason 失败原因
     * @param requestId     请求ID
     */
    public void append(String actor, String action, String objectType, String objectCode,
                       String beforeJson, String afterJson, boolean success, String failureReason,
                       String requestId) {
        mapper.insert(ConfigChangeLogPo.builder()
                .actor(actor)
                .action(action)
                .objectType(objectType)
                .objectCode(objectCode)
                .beforeJson(beforeJson)
                .afterJson(afterJson)
                .result(success ? "SUCCESS" : "FAILURE")
                .failureReason(failureReason)
                .requestId(requestId)
                .createTime(new Date())
                .build());
    }

}
