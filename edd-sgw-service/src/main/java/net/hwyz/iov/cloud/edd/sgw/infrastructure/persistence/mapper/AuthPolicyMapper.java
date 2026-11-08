package net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.AuthPolicyPo;
import org.apache.ibatis.annotations.Mapper;

/**
 * 认证授权策略草稿 Mapper。
 *
 * @author hwyz_leo
 */
@Mapper
public interface AuthPolicyMapper extends BaseMapper<AuthPolicyPo> {

}
