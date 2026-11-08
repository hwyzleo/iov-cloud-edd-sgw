package net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.ConfigWorkspacePo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

/**
 * 配置工作区 Mapper。
 *
 * @author hwyz_leo
 */
@Mapper
public interface ConfigWorkspaceMapper extends BaseMapper<ConfigWorkspacePo> {

    /**
     * 以行锁方式读取工作区，用于串行化发布与回滚
     *
     * @return 工作区记录
     */
    @Select("SELECT * FROM sgw_config_workspace WHERE id = 1 FOR UPDATE")
    ConfigWorkspacePo lockWorkspace();

}
