package net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.CanaryPolicyPo;
import org.apache.ibatis.annotations.Mapper;

/**
 * 灰度策略草稿 Mapper。
 *
 * @author hwyz_leo
 */
@Mapper
public interface CanaryPolicyMapper extends BaseMapper<CanaryPolicyPo> {

}
