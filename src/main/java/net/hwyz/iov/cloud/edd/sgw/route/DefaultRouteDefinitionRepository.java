package net.hwyz.iov.cloud.edd.sgw.route;

import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.sgw.enums.RouteTargetType;
import net.hwyz.iov.cloud.edd.sgw.repository.dao.RouteDao;
import org.springframework.cloud.gateway.event.RefreshRoutesEvent;
import org.springframework.cloud.gateway.filter.FilterDefinition;
import org.springframework.cloud.gateway.handler.predicate.PredicateDefinition;
import org.springframework.cloud.gateway.route.RouteDefinition;
import org.springframework.cloud.gateway.route.RouteDefinitionRepository;
import org.springframework.cloud.gateway.support.NotFoundException;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * 默认路由仓库
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DefaultRouteDefinitionRepository implements RouteDefinitionRepository, ApplicationEventPublisherAware {

    private final RouteDao routeDao;

    private ApplicationEventPublisher publisher;
    private List<RouteDefinition> routeDefinitionList = new ArrayList<>();

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    @PostConstruct
    public void init() {
        load();
    }

    /**
     * 监听事件刷新配置
     */
    @EventListener
    public void listenEvent(RefreshRoutesEvent event) {
        load();
    }

    /**
     * 加载
     */
    private void load() {
        try {
            List<RouteDefinition> list = new ArrayList<>();
            routeDao.selectPoByMap(new HashMap<>()).forEach(routePo -> {
                list.add(addRoute(routePo.getId().toString(), routePo.getPredicates(), routePo.getFilters(),
                        routePo.getTargetType(), routePo.getTargetUri()));
            });
            routeDefinitionList = list;
            logger.info("路由配置已加载,加载条数:{}", routeDefinitionList.size());
        } catch (Exception e) {
            logger.error("从文件加载路由配置异常", e);
        }
    }

    /**
     * 添加路由
     *
     * @param id             唯一ID
     * @param predicatesJson 断言JSON
     * @param filtersJson    过滤器JSON
     * @param targetType     目标类型
     * @param targetUri      目标URI
     * @return 路由
     */
    public RouteDefinition addRoute(String id, String predicatesJson, String filtersJson, String targetType, String targetUri) {
        JSONObject predicatesJsonObject = JSONUtil.parseObj(predicatesJson);
        List<PredicateDefinition> predicateDefinitions = new ArrayList<>();
        for (String key : predicatesJsonObject.keySet()) {
            PredicateDefinition predicateDefinition = new PredicateDefinition();
            predicateDefinition.setName(key);
            predicatesJsonObject.getJSONObject(key).forEach((argKey, argVal) -> predicateDefinition.addArg(argKey, argVal.toString()));
            predicateDefinitions.add(predicateDefinition);
        }
        if (predicateDefinitions.isEmpty()) {
            throw new RuntimeException("断言不能为空");
        }
        JSONObject filtersJsonObject = JSONUtil.parseObj(filtersJson);
        List<FilterDefinition> filterDefinitions = new ArrayList<>();
        for (String key : filtersJsonObject.keySet()) {
            FilterDefinition filterDefinition = new FilterDefinition();
            filterDefinition.setName(key);
            filtersJsonObject.getJSONObject(key).forEach((argKey, argVal) -> filterDefinition.addArg(argKey, argVal.toString()));
            filterDefinitions.add(filterDefinition);
        }
        RouteTargetType routeTargetType = RouteTargetType.valOf(targetType);
        if (routeTargetType == null) {
            throw new RuntimeException("目标类型不存在");
        }
        RouteDefinition route = new RouteDefinition();
        route.setId(id);
        route.setPredicates(predicateDefinitions);
        route.setFilters(filterDefinitions);
        route.setUri(URI.create(routeTargetType.protocol + targetUri));
        return route;
    }

    @Override
    public Mono<Void> save(Mono<RouteDefinition> route) {
        return Mono.defer(() -> Mono.error(new NotFoundException("Unsupported operation")));
    }

    @Override
    public Mono<Void> delete(Mono<String> routeId) {
        return Mono.defer(() -> Mono.error(new NotFoundException("Unsupported operation")));
    }

    @Override
    public Flux<RouteDefinition> getRouteDefinitions() {
        return Flux.fromIterable(routeDefinitionList);
    }

}
