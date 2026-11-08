package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

import java.util.Optional;
import java.util.function.Consumer;

/**
 * 版本指针存储。
 * <p>
 * 生产实现为 Nacos Config，测试实现为内存存储。
 *
 * @author hwyz_leo
 */
public interface VersionPointerStore {

    /**
     * 发布版本指针
     *
     * @param pointer 指针
     * @throws Exception 分发失败
     */
    void publish(PublicationPointer pointer) throws Exception;

    /**
     * 读取当前版本指针
     *
     * @return 指针
     */
    Optional<PublicationPointer> current();

    /**
     * 注册指针变更监听
     *
     * @param listener 监听器
     */
    void addListener(Consumer<PublicationPointer> listener);

}
