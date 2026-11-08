package net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.ConfigChangeLogPo;
import org.apache.ibatis.annotations.Mapper;

/**
 * 配置变更审计 Mapper。
 *
 * @author hwyz_leo
 */
@Mapper
public interface ConfigChangeLogMapper extends BaseMapper<ConfigChangeLogPo> {

}
