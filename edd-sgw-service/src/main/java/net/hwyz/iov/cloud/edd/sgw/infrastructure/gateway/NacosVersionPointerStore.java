package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

import com.alibaba.cloud.nacos.NacosConfigManager;
import com.alibaba.nacos.api.config.ConfigType;
import com.alibaba.nacos.api.config.listener.Listener;
import com.alibaba.nacos.api.exception.NacosException;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

/**
 * 基于 Nacos Config 的版本指针存储。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "sgw.publication.pointer-store", havingValue = "nacos", matchIfMissing = true)
public class NacosVersionPointerStore implements VersionPointerStore {

    private final NacosConfigManager nacosConfigManager;

    private final SgwProperties properties;

    private final List<Consumer<PublicationPointer>> listeners = new CopyOnWriteArrayList<>();

    private final Executor executor = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "sgw-nacos-pointer");
        thread.setDaemon(true);
        return thread;
    });

    public NacosVersionPointerStore(NacosConfigManager nacosConfigManager, SgwProperties properties) {
        this.nacosConfigManager = nacosConfigManager;
        this.properties = properties;
    }

    @Override
    public void publish(PublicationPointer pointer) throws NacosException {
        SgwProperties.Publication config = properties.getPublication();
        nacosConfigManager.getConfigService().publishConfig(config.getDataId(), config.getGroup(),
                Json.write(pointer), ConfigType.JSON.getType());
        log.info("已向 Nacos 发布版本指针: 版本[{}], 发布[{}]", pointer.versionNo(), pointer.publicationId());
    }

    @Override
    public Optional<PublicationPointer> current() {
        try {
            SgwProperties.Publication config = properties.getPublication();
            String content = nacosConfigManager.getConfigService().getConfig(config.getDataId(), config.getGroup(), 3000);
            return parse(content);
        } catch (NacosException e) {
            log.warn("读取 Nacos 版本指针失败: {}", e.getErrMsg());
            return Optional.empty();
        }
    }

    @Override
    public void addListener(Consumer<PublicationPointer> listener) {
        listeners.add(listener);
        SgwProperties.Publication config = properties.getPublication();
        try {
            nacosConfigManager.getConfigService().addListener(config.getDataId(), config.getGroup(), new Listener() {
                @Override
                public Executor getExecutor() {
                    return executor;
                }

                @Override
                public void receiveConfigInfo(String configInfo) {
                    parse(configInfo).ifPresent(pointer -> listeners.forEach(consumer -> consumer.accept(pointer)));
                }
            });
        } catch (NacosException e) {
            log.error("注册 Nacos 版本指针监听失败: {}", e.getErrMsg());
        }
    }

    private Optional<PublicationPointer> parse(String content) {
        if (content == null || content.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(Json.read(content, PublicationPointer.class));
        } catch (RuntimeException e) {
            log.warn("版本指针内容非法，已忽略");
            return Optional.empty();
        }
    }

}
