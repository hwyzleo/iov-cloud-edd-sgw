package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.security.RejectReason;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 路由与鉴权指标（EDD-SGW-DSN-CR-003 US-016）。
 * <p>
 * 进程内 Micrometer 计数，不新增端点、不接入监控平台；标签仅使用
 * {@code route_code} / {@code access_mode} / {@code reject_reason} / {@code identity_source} / {@code policy_code}，
 * 且 {@code route_code} 超出上限统一归一为 {@code OTHER}，避免标签基数爆炸（RD-003-10）。
 * 指标写入失败不影响请求（计数器为纯内存操作）。
 *
 * @author hwyz_leo
 */
@Component
public class SgwRouteMetrics {

    /** 路由命中 */
    public static final String MATCH = "sgw.route.match";

    /** 无路由命中 */
    public static final String MISS = "sgw.route.miss";

    /** 鉴权拒绝 */
    public static final String AUTH_REJECT = "sgw.auth.reject";

    /** 身份来源分布 */
    public static final String IDENTITY_SOURCE = "sgw.identity.source";

    /** 匿名策略命中 */
    public static final String POLICY_ANONYMOUS = "sgw.policy.anonymous";

    /** 标签归一值 */
    public static final String OTHER = "OTHER";

    /** route_code 标签基数上限 */
    public static final int MAX_ROUTE_CODES = 200;

    /** 未知访问模式的标签值（配置漂移时不得抛异常） */
    public static final String UNKNOWN_MODE = "UNKNOWN";

    private final MeterRegistry registry;

    private final Set<String> routeCodes = ConcurrentHashMap.newKeySet();

    public SgwRouteMetrics(MeterRegistry registry) {
        this.registry = registry;
    }

    /**
     * 路由命中计数
     *
     * @param routeCode  路由编码
     * @param accessMode 访问模式，可空
     */
    public void routeHit(String routeCode, AccessMode accessMode) {
        counter(MATCH, "route_code", normalizeRouteCode(routeCode),
                "access_mode", accessMode == null ? UNKNOWN_MODE : accessMode.name()).increment();
    }

    /**
     * 路由未命中计数
     */
    public void routeMiss() {
        counter(MISS).increment();
    }

    /**
     * 鉴权拒绝计数
     *
     * @param reason    拒绝原因
     * @param routeCode 路由编码
     */
    public void authReject(RejectReason reason, String routeCode) {
        counter(AUTH_REJECT, "reject_reason", reason == null ? RejectReason.NO_POLICY.name() : reason.name(),
                "route_code", normalizeRouteCode(routeCode)).increment();
    }

    /**
     * 身份来源分布计数
     *
     * @param source 来源标签（{@code CIAM} / {@code DECLARED} / {@code NONE}）
     */
    public void identitySource(String source) {
        counter(IDENTITY_SOURCE, "source", source == null || source.isBlank() ? "NONE" : source).increment();
    }

    /**
     * 匿名策略命中计数
     *
     * @param policyCode 策略编码
     */
    public void anonymousPolicy(String policyCode) {
        counter(POLICY_ANONYMOUS, "policy_code",
                policyCode == null || policyCode.isBlank() ? OTHER : policyCode).increment();
    }

    private Counter counter(String name, String... tags) {
        Counter.Builder builder = Counter.builder(name);
        for (int i = 0; i + 1 < tags.length; i += 2) {
            builder.tag(tags[i], tags[i + 1]);
        }
        return builder.register(registry);
    }

    private String normalizeRouteCode(String routeCode) {
        if (routeCode == null || routeCode.isBlank()) {
            return OTHER;
        }
        if (routeCodes.contains(routeCode)) {
            return routeCode;
        }
        if (routeCodes.size() >= MAX_ROUTE_CODES) {
            return OTHER;
        }
        routeCodes.add(routeCode);
        return routeCode;
    }

}
