package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * 内存版本指针存储（用于集成测试与本地验证）。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "sgw.publication.pointer-store", havingValue = "memory")
public class InMemoryVersionPointerStore implements VersionPointerStore {

    private final AtomicReference<PublicationPointer> current = new AtomicReference<>();

    private final List<Consumer<PublicationPointer>> listeners = new CopyOnWriteArrayList<>();

    @Override
    public void publish(PublicationPointer pointer) {
        log.info("内存发布版本指针: 版本[{}], 发布[{}]", pointer.versionNo(), pointer.publicationId());
        current.set(pointer);
        listeners.forEach(listener -> listener.accept(pointer));
    }

    @Override
    public Optional<PublicationPointer> current() {
        return Optional.ofNullable(current.get());
    }

    @Override
    public void addListener(Consumer<PublicationPointer> listener) {
        listeners.add(listener);
        Optional.ofNullable(current.get()).ifPresent(listener);
    }

    /**
     * 清空状态，供测试使用
     */
    public void reset() {
        current.set(null);
        listeners.clear();
    }

}
