package net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.TrafficPolicyPo;
import org.apache.ibatis.annotations.Mapper;

/**
 * 流量治理策略草稿 Mapper。
 *
 * @author hwyz_leo
 */
@Mapper
public interface TrafficPolicyMapper extends BaseMapper<TrafficPolicyPo> {

}
