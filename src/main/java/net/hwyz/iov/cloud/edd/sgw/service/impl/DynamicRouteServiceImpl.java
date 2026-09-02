package net.hwyz.iov.cloud.edd.sgw.service.impl;

import net.hwyz.iov.cloud.edd.sgw.service.DynamicRouteService;
import org.springframework.cloud.gateway.event.RefreshRoutesEvent;
import org.springframework.cloud.gateway.route.RouteDefinition;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.stereotype.Service;

/**
 * 动态路由服务实现类
 * <p>
 * 路由数据以数据库为准（由管理后台写入），本服务仅负责在增删改后
 * 发布 {@link RefreshRoutesEvent}，触发 {@code DefaultRouteDefinitionRepository}
 * 从数据库重新加载路由，使变更实时生效。
 *
 * @author hwyz_leo
 */
@Service
public class DynamicRouteServiceImpl implements DynamicRouteService, ApplicationEventPublisherAware {

    private ApplicationEventPublisher publisher;

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    @Override
    public void add(RouteDefinition definition) {
        this.publisher.publishEvent(new RefreshRoutesEvent(this));
    }

    @Override
    public void update(RouteDefinition definition) {
        this.publisher.publishEvent(new RefreshRoutesEvent(this));
    }

    @Override
    public void delete(Long[] ids) {
        this.publisher.publishEvent(new RefreshRoutesEvent(this));
    }

    @Override
    public void refresh() {
        this.publisher.publishEvent(new RefreshRoutesEvent(this));
    }
}
