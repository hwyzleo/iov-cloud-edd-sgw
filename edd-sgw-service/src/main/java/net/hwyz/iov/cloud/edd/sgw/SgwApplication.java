package net.hwyz.iov.cloud.edd.sgw;

import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * 服务网关启动类。
 *
 * @author hwyz_leo
 */
@Slf4j
@EnableScheduling
@EnableDiscoveryClient
@EnableConfigurationProperties(SgwProperties.class)
@SpringBootApplication
public class SgwApplication {

    public static void main(String[] args) {
        System.setProperty("nacos.logging.default.config.enabled", "false");
        SpringApplication.run(SgwApplication.class, args);
        log.info("服务网关启动完成");
    }

}
