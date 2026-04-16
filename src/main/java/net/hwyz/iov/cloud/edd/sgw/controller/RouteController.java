package net.hwyz.iov.cloud.edd.sgw.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.mpt.api.domain.TspSgwRoute;
import net.hwyz.iov.cloud.edd.sgw.route.DefaultRouteDefinitionRepository;
import net.hwyz.iov.cloud.edd.sgw.service.DynamicRouteService;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;

/**
 * 路由相关接口实现类
 *
 * @author hwyz_leo
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping(value = "/route")
public class RouteController {

    private final DynamicRouteService dynamicRouteService;
    private final DefaultRouteDefinitionRepository defaultRouteDefinitionRepository;

    /**
     * 新增路由
     *
     * @param route 路由
     */
    @PostMapping
    public void add(@RequestBody @Validated TspSgwRoute route) {
        log.info("新增路由[{}]", route.getTargetUri());
        dynamicRouteService.add(defaultRouteDefinitionRepository.addRoute(String.valueOf(route.getId()), route.getPredicates(),
                route.getFilters(), route.getTargetType(), route.getTargetUri()));
    }

    /**
     * 更新路由
     *
     * @param route 路由
     */
    @PutMapping
    public void update(@RequestBody @Validated TspSgwRoute route) {
        log.info("更新路由[{}]", route.getTargetUri());
        dynamicRouteService.update(defaultRouteDefinitionRepository.addRoute(String.valueOf(route.getId()), route.getPredicates(),
                route.getFilters(), route.getTargetType(), route.getTargetUri()));
    }

    /**
     * 删除路由
     *
     * @param ids 路由ID列表
     */
    @DeleteMapping("/{ids}")
    public void delete(@PathVariable Long[] ids) {
        log.info("删除路由[{}]", Arrays.toString(ids));
        dynamicRouteService.delete(ids);
    }

    /**
     * 刷新路由
     * 从数据库重新加载所有路由配置，使增删改过的路由实时生效
     */
    @PostMapping("/refresh")
    public void refresh() {
        log.info("刷新路由配置");
        dynamicRouteService.refresh();
    }

}
