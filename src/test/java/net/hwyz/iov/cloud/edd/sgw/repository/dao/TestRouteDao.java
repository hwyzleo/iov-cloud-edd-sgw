package net.hwyz.iov.cloud.edd.sgw.repository.dao;

import cn.hutool.json.JSONUtil;
import net.hwyz.iov.cloud.edd.sgw.BaseTest;
import net.hwyz.iov.cloud.edd.sgw.enums.RouteTargetType;
import net.hwyz.iov.cloud.edd.sgw.repository.po.RoutePo;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashMap;
import java.util.Map;

/**
 * 路由表 DAO 测试类
 *
 * @author hwyz_leo
 */
public class TestRouteDao extends BaseTest {

    @Autowired
    private RouteDao routeDao;

    @Test
    @Order(1)
    @DisplayName("新增一条记录")
    public void testInsertPo() throws Exception {
        Map<String, Object> predicates = new HashMap<>();
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("pattern", "/mp/dealership/**");
        predicates.put("Path", arguments);
        Map<String, Object> filters = new HashMap<>();
        filters.put("Authentication", new HashMap<>());
        RoutePo routePo = RoutePo.builder()
                .predicates(JSONUtil.toJsonStr(predicates))
                .filters(JSONUtil.toJsonStr(filters))
                .targetType(RouteTargetType.LB.name())
                .targetUri("org-service")
                .sort(99)
                .build();
        routeDao.insertPo(routePo);
    }

}
