package net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository;

import com.baomidou.mybatisplus.core.conditions.update.LambdaUpdateWrapper;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.mapper.ConfigWorkspaceMapper;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.ConfigWorkspacePo;
import org.springframework.stereotype.Repository;

import java.util.Date;

/**
 * 配置工作区仓储。
 *
 * @author hwyz_leo
 */
@Repository
public class WorkspaceRepository {

    private static final long WORKSPACE_ID = 1L;

    private final ConfigWorkspaceMapper mapper;

    public WorkspaceRepository(ConfigWorkspaceMapper mapper) {
        this.mapper = mapper;
    }

    /**
     * 读取工作区，不存在时初始化
     *
     * @return 工作区
     */
    public ConfigWorkspacePo get() {
        ConfigWorkspacePo po = mapper.selectById(WORKSPACE_ID);
        if (po == null) {
            ensureInitialized();
            po = mapper.selectById(WORKSPACE_ID);
        }
        return po;
    }

    /**
     * 行锁读取工作区（必须在事务中调用）
     *
     * @return 工作区
     */
    public ConfigWorkspacePo lock() {
        ConfigWorkspacePo po = mapper.lockWorkspace();
        if (po == null) {
            ensureInitialized();
            po = mapper.lockWorkspace();
        }
        return po;
    }

    /**
     * 确保工作区记录存在
     */
    public void ensureInitialized() {
        if (mapper.selectById(WORKSPACE_ID) == null) {
            ConfigWorkspacePo po = new ConfigWorkspacePo();
            po.setId(WORKSPACE_ID);
            po.setDraftRevision(0L);
            po.setRowVersion(1);
            po.setModifyBy("system");
            po.setModifyTime(new Date());
            try {
                mapper.insert(po);
            } catch (RuntimeException ignored) {
                // 并发初始化时唯一主键冲突，说明已存在
            }
        }
    }

    /**
     * 递增草稿修订号
     *
     * @param actor 操作者
     */
    public void bumpDraftRevision(String actor) {
        mapper.update(null, new LambdaUpdateWrapper<ConfigWorkspacePo>()
                .eq(ConfigWorkspacePo::getId, WORKSPACE_ID)
                .setSql("draft_revision = draft_revision + 1")
                .setSql("row_version = row_version + 1")
                .set(ConfigWorkspacePo::getModifyBy, actor)
                .set(ConfigWorkspacePo::getModifyTime, new Date()));
    }

    /**
     * 设置当前目标版本
     *
     * @param versionNo 版本号
     * @param actor     操作者
     */
    public void setTargetVersion(Long versionNo, String actor) {
        mapper.update(null, new LambdaUpdateWrapper<ConfigWorkspacePo>()
                .eq(ConfigWorkspacePo::getId, WORKSPACE_ID)
                .set(ConfigWorkspacePo::getTargetVersionNo, versionNo)
                .setSql("row_version = row_version + 1")
                .set(ConfigWorkspacePo::getModifyBy, actor)
                .set(ConfigWorkspacePo::getModifyTime, new Date()));
    }

}
