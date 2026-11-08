package net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.InstanceStatePo;
import org.apache.ibatis.annotations.Mapper;

/**
 * 实例运行时状态 Mapper。
 *
 * @author hwyz_leo
 */
@Mapper
public interface InstanceStateMapper extends BaseMapper<InstanceStatePo> {

}
