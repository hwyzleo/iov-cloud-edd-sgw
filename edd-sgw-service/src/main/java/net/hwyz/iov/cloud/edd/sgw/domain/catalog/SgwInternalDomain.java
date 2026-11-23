package net.hwyz.iov.cloud.edd.sgw.domain.catalog;

import java.util.List;

/**
 * 内部服务域前缀清单（EDD-SGW-DSN-CR-003 §19.5 R-9）。
 * <p>
 * 校验器要求「所有 {@code AccessMode.INTERNAL} 路由的 {@code match.paths} 必须落在本清单内」，
 * 禁止使用任意 {@code /api/service/**} 通配；新增前缀必须先评审再入清单。
 * 管理面 {@code /api/service/sgw/v1/**} 由 {@code AdminSecurityFilter} 自管，不在本清单内。
 *
 * @author hwyz_leo
 */
public final class SgwInternalDomain {

    /** SGW 管理面前缀（自我鉴权，不得登记为内部服务域路由） */
    public static final String ADMIN_PREFIX = "/api/service/sgw/v1/**";

    /** 内部服务域前缀（I1–I3） */
    public static final List<String> INTERNAL_DOMAIN_PREFIXES = List.of(
            "/api/service/activation/v1/**",
            "/api/service/deviceProof/v1/**",
            "/api/service/vehicleActivation/v1/**");

    private SgwInternalDomain() {
    }

    /**
     * 路径前缀是否已登记
     *
     * @param prefix 路径前缀（如 {@code /api/service/activation/v1/**}）
     * @return 是否已登记
     */
    public static boolean isRegistered(String prefix) {
        return prefix != null && INTERNAL_DOMAIN_PREFIXES.contains(prefix);
    }

}
