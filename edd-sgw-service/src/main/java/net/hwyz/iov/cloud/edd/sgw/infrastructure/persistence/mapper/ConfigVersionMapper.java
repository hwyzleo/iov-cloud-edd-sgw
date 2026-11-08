package net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.ConfigVersionPo;
import org.apache.ibatis.annotations.Mapper;

/**
 * 配置版本 Mapper。
 *
 * @author hwyz_leo
 */
@Mapper
public interface ConfigVersionMapper extends BaseMapper<ConfigVersionPo> {

}
