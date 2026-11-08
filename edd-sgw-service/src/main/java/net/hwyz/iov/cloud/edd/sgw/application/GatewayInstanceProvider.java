package net.hwyz.iov.cloud.edd.sgw.application;

import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 已发现网关实例提供者（用于登记待确认实例）。
 *
 * @author hwyz_leo
 */
@Component
public class GatewayInstanceProvider {

    private final ObjectProvider<DiscoveryClient> discoveryClientProvider;

    private final SgwProperties properties;

    public GatewayInstanceProvider(ObjectProvider<DiscoveryClient> discoveryClientProvider,
                                   SgwProperties properties) {
        this.discoveryClientProvider = discoveryClientProvider;
        this.properties = properties;
    }

    /**
     * 当前服务发现中的实例标识（host:port）
     *
     * @return 实例标识
     */
    public List<String> currentInstanceIds() {
        DiscoveryClient discoveryClient = discoveryClientProvider.getIfAvailable();
        if (discoveryClient == null) {
            return List.of();
        }
        try {
            return discoveryClient.getInstances(properties.getRuntime().getDiscoveryServiceName())
                    .stream()
                    .map(this::instanceId)
                    .filter(java.util.Objects::nonNull)
                    .distinct()
                    .toList();
        } catch (RuntimeException e) {
            return List.of();
        }
    }

    /**
     * 已发现实例
     *
     * @return 实例
     */
    public List<ServiceInstance> currentInstances() {
        DiscoveryClient discoveryClient = discoveryClientProvider.getIfAvailable();
        if (discoveryClient == null) {
            return List.of();
        }
        try {
            return discoveryClient.getInstances(properties.getRuntime().getDiscoveryServiceName());
        } catch (RuntimeException e) {
            return List.of();
        }
    }

    /**
     * 指定服务的实例数
     *
     * @param serviceId 服务ID
     * @return 实例数
     */
    public int instanceCount(String serviceId) {
        DiscoveryClient discoveryClient = discoveryClientProvider.getIfAvailable();
        if (discoveryClient == null) {
            return 0;
        }
        try {
            return discoveryClient.getInstances(serviceId).size();
        } catch (RuntimeException e) {
            return 0;
        }
    }

    /**
     * 服务清单
     *
     * @return 服务ID
     */
    public List<String> services() {
        DiscoveryClient discoveryClient = discoveryClientProvider.getIfAvailable();
        if (discoveryClient == null) {
            return List.of();
        }
        try {
            return discoveryClient.getServices();
        } catch (RuntimeException e) {
            return List.of();
        }
    }

    private String instanceId(ServiceInstance instance) {
        if (instance == null || instance.getHost() == null) {
            return null;
        }
        return instance.getHost() + ":" + instance.getPort();
    }

}
