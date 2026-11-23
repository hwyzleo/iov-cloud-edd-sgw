package net.hwyz.iov.cloud.edd.sgw.domain.catalog;

import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;

import java.util.List;

/**
 * iOS App 在用路径前缀清单（EDD-SGW-DSN-CR-003 §19.2 BLK-6；终审修复 B-2）。
 * <p>
 * 唯一事实源：本清单与 {@code V3__sgw_route_baseline.sql} / {@code V4__sgw_app_route_coverage.sql}
 * 种子、以及 App 侧三个真实发起点同源：
 * <ul>
 *     <li>{@code mp/ios/iov-mp-ios-app/iov/iov/Data/Http/TspApi.swift}（全部 TspManager 调用）；</li>
 *     <li>{@code mp/ios/iov-mp-ios-app/iov/iov/Domain/Avatar/AvatarRemoteAPI.swift}（头像上传，路径在常量中）；</li>
 *     <li>{@code mp/ios/iov-mp-ios-app/iov/iov/Module/Vehicle/Service/VehicleBindingService.swift}（绑定编排，路径经 TspApi）。</li>
 * </ul>
 * App 新增任何经 SGW 的调用（不限 {@code /api/} 前缀）→ 同源门禁测试立即失败
 * → 必须同步更新本清单与新增迁移（V3 发布后不可改，符合 RD-003-1）。
 * <p>
 * 终审 B-2 教训：早期版本只登记 6 条 {@code /api/mobile/**}，而 App 实际还在用
 * {@code /unlockVehicle}、{@code /lockVehicle}、{@code /setWindow}、{@code /setTrunk}、
 * {@code /mp/rvc/**}、{@code /mp/account/**}、{@code /account/mp/account/**}，
 * 导致这些调用未被任何路由覆盖（404）且绕开认证策略。本清单已补齐。
 *
 * @author hwyz_leo
 */
public final class SgwAppPathCatalog {

    /**
     * 裁决强制登记、但当前 App 无调用点的前缀（豁免「清单项必须有调用点」的反向门禁，其他多出项即失败）
     */
    public static final List<String> FORCED_PREFIXES = List.of("/api/mobile/v1/risk");

    /**
     * App 在用前缀（A1–A6 为 V3 基线；A7–A13 为终审 B-2 补登）
     * <p>
     * {@code vehicleControl = true} 的条目为车控类：认证策略必须为
     * {@link AccessMode#AUTHENTICATED} + {@code allowed_client_types=MOBILE} + 权限点/scope，
     * 严禁 {@link AccessMode#ANONYMOUS}（终审 B-2 显式断言）。
     */
    public static final List<AppPrefix> APP_IN_USE_PREFIXES = List.of(
            // ---- V3 基线（A1–A6）----
            new AppPrefix("/api/mobile/auth/v1/**", "mobile-auth-v1", AccessMode.ANONYMOUS, "sec-ciam", false),
            new AppPrefix("/api/mobile/vso/v1/**", "mobile-vso-v1", AccessMode.AUTHENTICATED, "otd-vso", false),
            new AppPrefix("/api/mobile/saleModel/v1/**", "mobile-sale-model-v1", AccessMode.AUTHENTICATED, "otd-vso", false),
            new AppPrefix("/api/mobile/account/v1/**", "mobile-account-v1", AccessMode.AUTHENTICATED, "sec-ciam", false),
            new AppPrefix("/api/mobile/activation/v1/**", "mobile-activation-v1", AccessMode.AUTHENTICATED, "iov-tsp", false),
            new AppPrefix("/api/mobile/v1/risk", "mobile-risk-v1", AccessMode.AUTHENTICATED, "sec-ciam", false),
            // ---- 终审 B-2 补登（A7–A13）：车控类严禁匿名 ----
            new AppPrefix("/unlockVehicle", "mobile-vehicle-unlock", AccessMode.AUTHENTICATED, "rvc-service", true),
            new AppPrefix("/lockVehicle", "mobile-vehicle-lock", AccessMode.AUTHENTICATED, "rvc-service", true),
            new AppPrefix("/setWindow", "mobile-vehicle-window", AccessMode.AUTHENTICATED, "rvc-service", true),
            new AppPrefix("/setTrunk", "mobile-vehicle-trunk", AccessMode.AUTHENTICATED, "rvc-service", true),
            new AppPrefix("/mp/rvc/**", "mobile-rvc-v1", AccessMode.AUTHENTICATED, "rvc-service", true),
            // ---- 账号类（AUTHENTICATED + MOBILE）----
            new AppPrefix("/mp/account/**", "mobile-account-mp-v1", AccessMode.AUTHENTICATED, "tsp-account", false),
            new AppPrefix("/account/mp/account/**", "mobile-account-info-v1", AccessMode.AUTHENTICATED, "tsp-account", false));

    private SgwAppPathCatalog() {
    }

    /**
     * App 在用前缀条目
     *
     * @param prefix         路径前缀（可能为精确路径）
     * @param routeCode      期望命中的路由编码（与 V3/V4 种子一致）
     * @param accessMode     期望的访问模式
     * @param targetService  期望的目标服务 ID
     * @param vehicleControl 是否车控类（车控类严禁匿名）
     */
    public record AppPrefix(String prefix, String routeCode, AccessMode accessMode, String targetService,
                            boolean vehicleControl) {
    }

}
