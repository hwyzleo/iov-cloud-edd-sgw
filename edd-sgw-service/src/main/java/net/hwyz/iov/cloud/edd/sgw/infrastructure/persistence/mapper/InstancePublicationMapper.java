package net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.InstancePublicationPo;
import org.apache.ibatis.annotations.Mapper;

/**
 * 逐实例发布结果 Mapper。
 *
 * @author hwyz_leo
 */
@Mapper
public interface InstancePublicationMapper extends BaseMapper<InstancePublicationPo> {

}
