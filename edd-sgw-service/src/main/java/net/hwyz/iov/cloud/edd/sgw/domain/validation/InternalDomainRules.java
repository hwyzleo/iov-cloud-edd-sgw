package net.hwyz.iov.cloud.edd.sgw.domain.validation;

import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;
import net.hwyz.iov.cloud.edd.sgw.common.Cidr;
import net.hwyz.iov.cloud.edd.sgw.domain.catalog.SgwInternalDomain;
import net.hwyz.iov.cloud.edd.sgw.domain.model.AuthPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteMatch;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * 内部服务域判定规则（EDD-SGW-DSN-CR-003 D-003-1 / R-7 / R-9）。
 * <p>
 * 发布期校验与启动期 fail-fast 共用同一口径，避免「发布放过、启动失败」或反之。
 *
 * @author hwyz_leo
 */
public final class InternalDomainRules {

    private InternalDomainRules() {
    }

    /**
     * 是否存在被有效路由引用的 {@code INTERNAL} 策略（决定 {@code internal-cidrs} 是否必需）
     *
     * @param routes   路由集合
     * @param policies 策略索引
     * @return 是否存在
     */
    public static boolean requiresSourceCidrs(Collection<RouteDefinition> routes, Map<String, AuthPolicy> policies) {
        return internalRouteCodes(routes, policies).size() > 0;
    }

    /**
     * 引用有效 {@code INTERNAL} 策略的路由编码
     *
     * @param routes   路由集合
     * @param policies 策略索引
     * @return 路由编码集合
     */
    public static List<String> internalRouteCodes(Collection<RouteDefinition> routes, Map<String, AuthPolicy> policies) {
        List<String> codes = new ArrayList<>();
        if (routes == null) {
            return codes;
        }
        for (RouteDefinition route : routes) {
            if (route == null || !route.effective()) {
                continue;
            }
            AuthPolicy policy = policies == null ? null : policies.get(route.getAuthPolicyCode());
            if (isInternal(policy)) {
                codes.add(route.getRouteCode());
            }
        }
        return codes;
    }

    /**
     * 是否为生效的 {@code INTERNAL} 策略
     *
     * @param policy 策略
     * @return 是否内部服务域
     */
    public static boolean isInternal(AuthPolicy policy) {
        return policy != null && policy.effective() && policy.getAccessMode() == AccessMode.INTERNAL;
    }

    /**
     * 内部来源网段配置问题（R-7：非空时必须全部可解析为合法 CIDR/IP）。
     * <p>
     * 终审 R-1：**先过滤空白条目**再校验。{@code SGW_INTERNAL_CIDRS} 未设置时占位符会展开为空串，
     * {@code a,,b} 形式也会产生空段；这些条目未表达任何网段，不应被当作「非法配置」而 fail-fast，
     * 「是否存在有效网段」由 {@link #effectiveCidrs(List)} 判定。
     *
     * @param cidrs 网段清单
     * @return 问题清单，空表示通过
     */
    public static List<String> cidrErrors(List<String> cidrs) {
        List<String> errors = new ArrayList<>();
        if (cidrs == null) {
            return errors;
        }
        for (int i = 0; i < cidrs.size(); i++) {
            if (isBlank(cidrs.get(i))) {
                continue;
            }
            if (!Cidr.isValid(cidrs.get(i))) {
                errors.add("sgw.runtime.internal-cidrs[" + i + "]");
            }
        }
        return errors;
    }

    /**
     * 生效网段清单（剔除空白条目并去首尾空白，保持原顺序）
     *
     * @param cidrs 网段清单
     * @return 生效条目
     */
    public static List<String> effectiveCidrs(List<String> cidrs) {
        List<String> effective = new ArrayList<>();
        if (cidrs == null) {
            return effective;
        }
        for (String cidr : cidrs) {
            if (isBlank(cidr)) {
                continue;
            }
            effective.add(cidr.trim());
        }
        return effective;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /**
     * 内部域路由的路径必须落在已登记前缀内（禁止任意 {@code /api/service/**} 通配）
     *
     * @param route 路由
     * @return 越界路径，空表示通过
     */
    public static List<String> unregisteredPaths(RouteDefinition route) {
        List<String> unregistered = new ArrayList<>();
        RouteMatch match = route.getMatch();
        if (match == null) {
            return unregistered;
        }
        match.normalized();
        for (String path : match.getPaths()) {
            if (!SgwInternalDomain.isRegistered(path)) {
                unregistered.add(path);
            }
        }
        return unregistered;
    }

}
