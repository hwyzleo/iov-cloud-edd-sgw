package net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.PublicationPo;
import org.apache.ibatis.annotations.Mapper;

/**
 * 发布记录 Mapper。
 *
 * @author hwyz_leo
 */
@Mapper
public interface PublicationMapper extends BaseMapper<PublicationPo> {

}
