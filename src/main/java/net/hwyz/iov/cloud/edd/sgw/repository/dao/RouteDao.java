package net.hwyz.iov.cloud.edd.sgw.repository.dao;

import net.hwyz.iov.cloud.framework.mysql.dao.BaseDao;
import net.hwyz.iov.cloud.edd.sgw.repository.po.RoutePo;
import org.apache.ibatis.annotations.Mapper;

/**
 * <p>
 * 路由表 DAO
 * </p>
 *
 * @author hwyz_leo
 * @since 2024-10-08
 */
@Mapper
public interface RouteDao extends BaseDao<RoutePo, Long> {

}
