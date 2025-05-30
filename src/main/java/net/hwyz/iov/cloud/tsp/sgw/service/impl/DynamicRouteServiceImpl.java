package net.hwyz.iov.cloud.tsp.sgw.service.impl;

import net.hwyz.iov.cloud.tsp.sgw.service.DynamicRouteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.event.RefreshRoutesEvent;
import org.springframework.cloud.gateway.route.RouteDefinition;
import org.springframework.cloud.gateway.route.RouteDefinitionWriter;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * 动态路由服务实现类
 *
 * @author hwyz_leo
 */
@Service
public class DynamicRouteServiceImpl implements DynamicRouteService, ApplicationEventPublisherAware {

    @Autowired
    private RouteDefinitionWriter routeDefinitionWriter;
    private ApplicationEventPublisher publisher;

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    @Override
    public void add(RouteDefinition definition) {
        routeDefinitionWriter.save(Mono.just(definition)).subscribe();
        this.publisher.publishEvent(new RefreshRoutesEvent(this));
    }

    @Override
    public void update(RouteDefinition definition) {
        delete(definition.getId());
        routeDefinitionWriter.save(Mono.just(definition)).subscribe();
        this.publisher.publishEvent(new RefreshRoutesEvent(this));
    }

    @Override
    public void delete(Long[] ids) {
        for (Long id : ids) {
            delete(id.toString());
        }
    }

    private void delete(String id) {
        this.routeDefinitionWriter.delete(Mono.just(id)).onErrorResume((t) -> Mono.empty());
    }
}
