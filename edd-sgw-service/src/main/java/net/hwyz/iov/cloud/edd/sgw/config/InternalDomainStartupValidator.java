package net.hwyz.iov.cloud.edd.sgw.config;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.sgw.domain.model.AuthPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.InternalDomainRules;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.AuthPolicyRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.RouteRepository;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 内部服务域启动校验（EDD-SGW-DSN-CR-003 R-7 / §19.3）。
 * <p>
 * 当且仅当存在 {@code accessMode=INTERNAL} 且启用的策略，并被启用且有效的路由引用时，
 * {@code sgw.runtime.internal-cidrs} 必须非空且每项可解析为合法 CIDR/IP；
 * 任一不满足 → 抛 {@link IllegalStateException}，进程以非 0 退出（不允许「空清单 = 跳过来源校验」的退化路径）。
 * <p>
 * 在快照激活协调器（{@link net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.SnapshotActivationCoordinator}）
 * 之前以同步方式执行，属启动前置检查；发布期由
 * {@link net.hwyz.iov.cloud.edd.sgw.domain.validation.ConfigurationValidator} 以同一口径拦截。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class InternalDomainStartupValidator implements ApplicationRunner, Ordered {

    private final SgwProperties properties;

    private final RouteRepository routeRepository;

    private final AuthPolicyRepository authPolicyRepository;

    public InternalDomainStartupValidator(SgwProperties properties, RouteRepository routeRepository,
                                          AuthPolicyRepository authPolicyRepository) {
        this.properties = properties;
        this.routeRepository = routeRepository;
        this.authPolicyRepository = authPolicyRepository;
        log.info("内部服务域判定链: internal-cidrs 生效条目数={}, 已登记内部客户端={}",
                properties.getRuntime().getInternalCidrs().size(),
                properties.getSecurity().getInternal().getClients().keySet());
    }

    @Override
    public void run(ApplicationArguments args) {
        List<RouteDefinition> routes = routeRepository.findAllValid();
        Map<String, AuthPolicy> policies = authPolicyRepository.findAllValid().stream()
                .collect(Collectors.toMap(AuthPolicy::getPolicyCode, policy -> policy,
                        (left, right) -> left, LinkedHashMap::new));
        verify(routes, policies);
    }

    /**
     * 启动期校验（可独立调用，便于测试）
     *
     * @param routes   已生效路由
     * @param policies 已生效策略索引
     */
    public void verify(List<RouteDefinition> routes, Map<String, AuthPolicy> policies) {
        List<String> cidrs = InternalDomainRules.effectiveCidrs(properties.getRuntime().getInternalCidrs());
        List<String> cidrErrors = InternalDomainRules.cidrErrors(cidrs);
        if (!cidrErrors.isEmpty()) {
            throw new IllegalStateException("配置项 sgw.runtime.internal-cidrs 存在非法条目: " + cidrErrors);
        }
        List<String> internalRoutes = InternalDomainRules.internalRouteCodes(routes, policies);
        if (internalRoutes.isEmpty()) {
            log.info("未启用内部服务域判定链（无 INTERNAL 路由）");
            return;
        }
        if (cidrs.isEmpty()) {
            String message = "存在 INTERNAL 路由但未配置 sgw.runtime.internal-cidrs（路由: "
                    + internalRoutes + "），进程拒绝启动；请先在配置中心补齐内部来源网段";
            if (!properties.getRuntime().isInternalDomainStrict()) {
                // 终审 R-1：仅显式关闭严格模式的迁移期环境允许降级；
                // 运行期仍为失败关闭（空清单下任何来源都不命中 → SGW-403001），不会放开权限。
                log.warn("{}（sgw.runtime.internal-domain-strict=false，降级为启动放行；运行期 INTERNAL 路由将全部 403）",
                        message);
                return;
            }
            throw new IllegalStateException(message);
        }
        log.info("内部服务域判定链已启用: internal-cidrs 生效条目数={}, 注册的内部客户端名={}, INTERNAL 路由={}",
                cidrs.size(), properties.getSecurity().getInternal().getClients().keySet(), internalRoutes);
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

}
