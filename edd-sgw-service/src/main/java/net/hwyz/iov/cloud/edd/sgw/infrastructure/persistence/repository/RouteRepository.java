package net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.LambdaUpdateWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.common.PageSlice;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteMatch;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteTarget;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteTransform;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.mapper.RouteMapper;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.RoutePo;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;

import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * 路由草稿仓储。
 *
 * @author hwyz_leo
 */
@Repository
public class RouteRepository {

    private final RouteMapper mapper;

    public RouteRepository(RouteMapper mapper) {
        this.mapper = mapper;
    }

    /**
     * 物理分页查询
     *
     * @param page       页码
     * @param size       每页条数
     * @param name       名称模糊匹配
     * @param enabled    启用状态
     * @param target     目标值
     * @param clientType 客户端类型
     * @return 分页结果
     */
    public PageSlice<RouteDefinition> page(int page, int size, String name, Boolean enabled,
                                           String target, String clientType) {
        LambdaQueryWrapper<RoutePo> wrapper = new LambdaQueryWrapper<RoutePo>()
                .eq(RoutePo::getRowValid, true)
                .like(StringUtils.hasText(name), RoutePo::getRouteName, name)
                .eq(enabled != null, RoutePo::getEnabled, enabled)
                .eq(StringUtils.hasText(target), RoutePo::getTargetValue, target)
                .like(StringUtils.hasText(clientType), RoutePo::getClientTypes, clientType)
                .orderByAsc(RoutePo::getPriority)
                .orderByAsc(RoutePo::getRouteCode);
        Page<RoutePo> result = mapper.selectPage(new Page<>(page, size), wrapper);
        return new PageSlice<>(result.getRecords().stream().map(this::toDomain).toList(),
                result.getTotal(), page, size);
    }

    /**
     * 查询全部有效草稿（用于构建快照）
     *
     * @return 路由列表
     */
    public List<RouteDefinition> findAllValid() {
        List<RoutePo> records = mapper.selectList(new LambdaQueryWrapper<RoutePo>()
                .eq(RoutePo::getRowValid, true)
                .orderByAsc(RoutePo::getPriority)
                .orderByAsc(RoutePo::getRouteCode));
        return records.stream().map(this::toDomain).toList();
    }

    /**
     * 查询有效路由
     *
     * @param routeCode 编码
     * @return 路由
     */
    public Optional<RouteDefinition> findValid(String routeCode) {
        RoutePo po = mapper.selectOne(new LambdaQueryWrapper<RoutePo>()
                .eq(RoutePo::getRouteCode, routeCode)
                .eq(RoutePo::getRowValid, true));
        return Optional.ofNullable(po).map(this::toDomain);
    }

    /**
     * 查询任意状态路由（含已逻辑删除，用于编码永不复用校验）
     *
     * @param routeCode 编码
     * @return 路由
     */
    public Optional<RouteDefinition> findAny(String routeCode) {
        RoutePo po = mapper.selectOne(new LambdaQueryWrapper<RoutePo>()
                .eq(RoutePo::getRouteCode, routeCode));
        return Optional.ofNullable(po).map(this::toDomain);
    }

    /**
     * 新增路由草稿
     *
     * @param route 路由
     * @param actor 操作者
     */
    public void insert(RouteDefinition route, String actor) {
        Date now = new Date();
        RoutePo po = toPo(route);
        po.setRowVersion(1);
        po.setRowValid(true);
        po.setCreateBy(actor);
        po.setCreateTime(now);
        po.setModifyBy(actor);
        po.setModifyTime(now);
        mapper.insert(po);
        route.setRowVersion(1);
    }

    /**
     * 乐观更新路由草稿
     *
     * @param route 路由
     * @param actor 操作者
     * @return 是否更新成功
     */
    public boolean update(RouteDefinition route, String actor) {
        int expected = route.getRowVersion() == null ? 0 : route.getRowVersion();
        int rows = mapper.update(null, new LambdaUpdateWrapper<RoutePo>()
                .eq(RoutePo::getRouteCode, route.getRouteCode())
                .eq(RoutePo::getRowValid, true)
                .eq(RoutePo::getRowVersion, expected)
                .set(RoutePo::getRouteName, route.getRouteName())
                .set(RoutePo::getDescription, route.getDescription())
                .set(RoutePo::getPriority, route.getPriority())
                .set(RoutePo::getEnabled, route.getEnabled())
                .set(RoutePo::getMatchJson, Json.write(route.getMatch().normalized()))
                .set(RoutePo::getTargetType, route.getTarget().getType().name())
                .set(RoutePo::getTargetValue, route.getTarget().targetValue())
                .set(RoutePo::getClientTypes, joinClientTypes(route.getMatch()))
                .set(RoutePo::getTransformJson, route.getTransform() == null ? null : Json.write(route.getTransform().normalized()))
                .set(RoutePo::getAuthPolicyCode, route.getAuthPolicyCode())
                .set(RoutePo::getTrafficPolicyCode, route.getTrafficPolicyCode())
                .set(RoutePo::getCanaryPolicyCode, route.getCanaryPolicyCode())
                .set(RoutePo::getModifyBy, actor)
                .set(RoutePo::getModifyTime, new Date())
                .set(RoutePo::getRowVersion, expected + 1));
        if (rows > 0) {
            route.setRowVersion(expected + 1);
        }
        return rows > 0;
    }

    /**
     * 逻辑删除路由草稿
     *
     * @param routeCode 编码
     * @param actor     操作者
     * @return 是否删除成功
     */
    public boolean logicalDelete(String routeCode, String actor) {
        int rows = mapper.update(null, new LambdaUpdateWrapper<RoutePo>()
                .eq(RoutePo::getRouteCode, routeCode)
                .eq(RoutePo::getRowValid, true)
                .set(RoutePo::getRowValid, false)
                .set(RoutePo::getModifyBy, actor)
                .set(RoutePo::getModifyTime, new Date())
                .setSql("row_version = row_version + 1"));
        return rows > 0;
    }

    /**
     * 查询引用指定策略的路由编码
     *
     * @param policyType 策略类型：auth、traffic、canary
     * @param policyCode 策略编码
     * @return 路由编码列表
     */
    public List<String> findRouteCodesReferencing(String policyType, String policyCode) {
        LambdaQueryWrapper<RoutePo> wrapper = new LambdaQueryWrapper<RoutePo>()
                .eq(RoutePo::getRowValid, true)
                .select(RoutePo::getRouteCode);
        switch (policyType) {
            case "auth" -> wrapper.eq(RoutePo::getAuthPolicyCode, policyCode);
            case "traffic" -> wrapper.eq(RoutePo::getTrafficPolicyCode, policyCode);
            case "canary" -> wrapper.eq(RoutePo::getCanaryPolicyCode, policyCode);
            default -> {
                return List.of();
            }
        }
        return mapper.selectList(wrapper).stream().map(RoutePo::getRouteCode).toList();
    }

    private RoutePo toPo(RouteDefinition route) {
        return RoutePo.builder()
                .routeCode(route.getRouteCode())
                .routeName(route.getRouteName())
                .description(route.getDescription())
                .priority(route.getPriority())
                .enabled(Boolean.TRUE.equals(route.getEnabled()))
                .matchJson(Json.write(route.getMatch().normalized()))
                .targetType(route.getTarget().getType().name())
                .targetValue(route.getTarget().targetValue())
                .clientTypes(joinClientTypes(route.getMatch()))
                .transformJson(route.getTransform() == null ? null : Json.write(route.getTransform().normalized()))
                .authPolicyCode(route.getAuthPolicyCode())
                .trafficPolicyCode(route.getTrafficPolicyCode())
                .canaryPolicyCode(route.getCanaryPolicyCode())
                .build();
    }

    private RouteDefinition toDomain(RoutePo po) {
        RouteDefinition.RouteDefinitionBuilder builder = RouteDefinition.builder()
                .routeCode(po.getRouteCode())
                .routeName(po.getRouteName())
                .description(po.getDescription())
                .priority(po.getPriority())
                .enabled(po.getEnabled())
                .match(po.getMatchJson() == null ? new RouteMatch() : Json.read(po.getMatchJson(), RouteMatch.class))
                .target(RouteTarget.builder()
                        .type(net.hwyz.iov.cloud.edd.sgw.api.enums.RouteTargetType.valueOf(po.getTargetType()))
                        .serviceId(net.hwyz.iov.cloud.edd.sgw.api.enums.RouteTargetType.SERVICE.name().equals(po.getTargetType())
                                ? po.getTargetValue() : null)
                        .uri(net.hwyz.iov.cloud.edd.sgw.api.enums.RouteTargetType.SERVICE.name().equals(po.getTargetType())
                                ? null : po.getTargetValue())
                        .build())
                .transform(StringUtils.hasText(po.getTransformJson())
                        ? Json.read(po.getTransformJson(), RouteTransform.class) : null)
                .authPolicyCode(po.getAuthPolicyCode())
                .trafficPolicyCode(po.getTrafficPolicyCode())
                .canaryPolicyCode(po.getCanaryPolicyCode())
                .rowVersion(po.getRowVersion());
        return builder.build();
    }

    private String joinClientTypes(RouteMatch match) {
        if (match == null || match.getClientTypes() == null || match.getClientTypes().isEmpty()) {
            return null;
        }
        return String.join(",", match.getClientTypes());
    }

}
