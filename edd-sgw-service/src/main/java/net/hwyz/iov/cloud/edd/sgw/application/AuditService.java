package net.hwyz.iov.cloud.edd.sgw.application;

import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.ChangeLogRepository;
import org.springframework.stereotype.Service;

import java.util.function.Supplier;

/**
 * 配置变更审计服务。
 *
 * @author hwyz_leo
 */
@Service
public class AuditService {

    private final ChangeLogRepository changeLogRepository;

    public AuditService(ChangeLogRepository changeLogRepository) {
        this.changeLogRepository = changeLogRepository;
    }

    /**
     * 执行带审计的变更动作
     *
     * @param action     动作
     * @param objectType 对象类型
     * @param objectCode 对象编码
     * @param before     变更前（可空）
     * @param context    操作上下文
     * @param supplier   变更动作
     * @param <T>        结果类型
     * @return 变更结果
     */
    public <T> T run(String action, String objectType, String objectCode, Object before, AdminContext context,
                     Supplier<Audited<T>> supplier) {
        try {
            Audited<T> audited = supplier.get();
            changeLogRepository.append(context.actor(), action, objectType, objectCode,
                    before == null ? null : Json.write(before),
                    audited.after() == null ? null : Json.write(audited.after()),
                    true, null, context.requestId());
            return audited.value();
        } catch (RuntimeException e) {
            changeLogRepository.append(context.actor(), action, objectType, objectCode,
                    before == null ? null : Json.write(before), null, false,
                    Json.truncate(e.getMessage(), 1000), context.requestId());
            throw e;
        }
    }

    /**
     * 记录一次发布类变更
     *
     * @param action     动作
     * @param objectType 对象类型
     * @param objectCode 对象编码
     * @param before     变更前
     * @param after      变更后
     * @param context    上下文
     * @param failed     是否失败
     * @param reason     失败原因
     */
    public void record(String action, String objectType, String objectCode, Object before, Object after,
                       AdminContext context, boolean failed, String reason) {
        changeLogRepository.append(context.actor(), action, objectType, objectCode,
                before == null ? null : Json.write(before),
                after == null ? null : Json.write(after),
                !failed, failed ? Json.truncate(reason, 1000) : null, context.requestId());
    }

    /**
     * 审计结果载体
     *
     * @param value 返回值
     * @param after 变更后对象
     * @param <T>   类型
     */
    public record Audited<T>(T value, Object after) {

        /**
         * 仅返回值
         *
         * @param value 返回值
         * @param <T>   类型
         * @return 审计结果
         */
        public static <T> Audited<T> of(T value) {
            return new Audited<>(value, null);
        }

        /**
         * 返回值与变更后对象
         *
         * @param value 返回值
         * @param after 变更后对象
         * @param <T>   类型
         * @return 审计结果
         */
        public static <T> Audited<T> of(T value, Object after) {
            return new Audited<>(value, after);
        }

    }

}
