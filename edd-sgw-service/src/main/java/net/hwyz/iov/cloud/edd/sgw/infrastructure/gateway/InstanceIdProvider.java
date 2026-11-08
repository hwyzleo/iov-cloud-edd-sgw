package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.InetAddress;

/**
 * 实例ID提供者。默认使用宿主地址:端口，保证与 Nacos 服务发现实例可对齐。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class InstanceIdProvider {

    private final SgwProperties properties;

    private final int serverPort;

    private String instanceId;

    public InstanceIdProvider(SgwProperties properties, @Value("${server.port:10803}") int serverPort) {
        this.properties = properties;
        this.serverPort = serverPort;
    }

    @PostConstruct
    public void init() {
        if (properties.getInstanceId() != null && !properties.getInstanceId().isBlank()) {
            this.instanceId = properties.getInstanceId();
        } else {
            String host;
            try {
                host = InetAddress.getLocalHost().getHostAddress();
            } catch (Exception e) {
                host = "127.0.0.1";
            }
            this.instanceId = host + ":" + serverPort;
        }
        log.info("服务网关实例ID: {}", instanceId);
    }

    /**
     * 实例ID
     *
     * @return 实例ID
     */
    public String getInstanceId() {
        return instanceId;
    }

}
