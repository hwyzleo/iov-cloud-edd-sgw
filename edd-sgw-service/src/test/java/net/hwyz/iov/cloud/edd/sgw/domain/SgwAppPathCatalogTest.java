package net.hwyz.iov.cloud.edd.sgw.domain;

import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;
import net.hwyz.iov.cloud.edd.sgw.domain.catalog.SgwAppPathCatalog;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteMatch;
import net.hwyz.iov.cloud.edd.sgw.domain.model.SgwConfiguration;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.CompiledRoute;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.RouteMatcher;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.SnapshotCompiler;
import net.hwyz.iov.cloud.edd.sgw.support.AppPathScanner;
import net.hwyz.iov.cloud.edd.sgw.support.SeedSql;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * iOS App 在用路径同源门禁（EDD-SGW-DSN-CR-003 §19.2.6 TC-003-16 / TC-003-17；终审修复 B-2）。
 * <p>
 * 清单（{@link SgwAppPathCatalog}）、App 代码（{@code TspApi.swift} + {@code AvatarRemoteAPI.swift} +
 * {@code VehicleBindingService.swift}）与 V3/V4 种子三者同源：
 * <ul>
 *     <li>App 新增任何经 SGW 的调用（不限 {@code /api/} 前缀）→ 门禁立即失败；</li>
 *     <li>V4 中删掉任一清单前缀 → {@link #gateCatchesDeletedPrefix()} 立即失败（证明门禁有效）；</li>
 *     <li>车控类前缀不得匿名（{@link #vehicleControlRoutesMustNotBeAnonymous()}）。</li>
 * </ul>
 * 源文件缺失时测试失败（禁止 Skip/Assume）。
 *
 * @author hwyz_leo
 */
class SgwAppPathCatalogTest {

    @Test
    @DisplayName("TC-003-16：App 在用路径（三源全量字面量）⊆ 清单，且每个清单前缀在 V3/V4 种子中唯一覆盖")
    void appPathsCoveredBySeed() throws IOException {
        Set<String> fromApp = appPaths();
        Set<String> declared = SgwAppPathCatalog.APP_IN_USE_PREFIXES.stream()
                .map(SgwAppPathCatalog.AppPrefix::prefix)
                .collect(Collectors.toCollection(LinkedHashSet::new));

        assertThat(AppPathScanner.uncovered(fromApp, SgwAppPathCatalog.APP_IN_USE_PREFIXES))
                .as("App 在用路径必须被清单覆盖（终审 B-2：缺失即门禁失败）：全部调用点=%s", fromApp)
                .isEmpty();
        assertThat(declared).as("清单多出的前缀仅允许裁决强制项: %s", SgwAppPathCatalog.FORCED_PREFIXES)
                .allSatisfy(prefix -> assertThat(hasCallSite(fromApp, prefix)
                        || SgwAppPathCatalog.FORCED_PREFIXES.contains(prefix))
                        .as("清单前缀 %s 既无 App 调用点也不在 FORCED_PREFIXES 内", prefix).isTrue());

        List<CompiledRoute> seeded = seedRoutes();
        for (SgwAppPathCatalog.AppPrefix declaredPrefix : SgwAppPathCatalog.APP_IN_USE_PREFIXES) {
            String probe = probePath(declaredPrefix.prefix());
            List<String> matched = seeded.stream()
                    .filter(route -> matches(route, probe))
                    .map(CompiledRoute::routeCode)
                    .toList();
            assertThat(matched).as("前缀 %s（探针 %s）必须由唯一一条种子路由覆盖", declaredPrefix.prefix(), probe)
                    .containsExactly(declaredPrefix.routeCode());

            SeedSql.SeedRoute seed = SeedSql.allRoutes().stream()
                    .filter(route -> route.routeCode().equals(declaredPrefix.routeCode()))
                    .findFirst().orElseThrow(() -> new AssertionError(
                            "种子缺少路由 " + declaredPrefix.routeCode()));
            assertThat(seed.targetService()).isEqualTo(declaredPrefix.targetService());
            assertThat(seed.authPolicyCode()).as("路由 %s 必须引用认证策略", seed.routeCode()).isNotBlank();
        }
    }

    @Test
    @DisplayName("TC-003-16b：门禁扫描必须覆盖终审 B-2 指出的全部漏检路径")
    void gateCoversPreviouslyMissingPaths() throws IOException {
        Set<String> fromApp = appPaths();
        assertThat(fromApp).contains(
                "/unlockVehicle", "/lockVehicle", "/setWindow", "/setTrunk",
                "/mp/rvc/action/findVehicle", "/mp/rvc/cmd",
                "/mp/account/qrcode", "/mp/account/action/modifyNickname",
                "/account/mp/account/info",
                "/api/mobile/account/v1/profile/avatar/upload",
                "/api/mobile/account/v1/profile/avatar/complete",
                "/api/mobile/saleModel/v1", "/api/mobile/vso/v1/order",
                "/api/mobile/activation/v1/binding");
    }

    @Test
    @DisplayName("TC-003-19：门禁能捕获「故意删除的路径」（V4 删前缀 / App 加未登记调用）")
    void gateCatchesDeletedPrefix() {
        Set<String> fromApp = Set.of("/unlockVehicle", "/mp/rvc/cmd", "/api/mobile/account/v1/profile");
        List<SgwAppPathCatalog.AppPrefix> withoutVehicleControl = SgwAppPathCatalog.APP_IN_USE_PREFIXES.stream()
                .filter(prefix -> !prefix.vehicleControl())
                .toList();
        assertThat(AppPathScanner.uncovered(fromApp, withoutVehicleControl))
                .as("删掉车控前缀后门禁必须失败")
                .containsExactlyInAnyOrder("/unlockVehicle", "/mp/rvc/cmd");
        assertThat(AppPathScanner.uncovered(fromApp, SgwAppPathCatalog.APP_IN_USE_PREFIXES)).isEmpty();

        Set<String> withNewCall = Set.of("/newVehicleCmd", "/api/mobile/account/v1/profile");
        assertThat(AppPathScanner.uncovered(withNewCall, SgwAppPathCatalog.APP_IN_USE_PREFIXES))
                .as("App 新增未登记调用时门禁必须失败")
                .containsExactly("/newVehicleCmd");
    }

    @Test
    @DisplayName("TC-003-19b：扫描器能解析常量封装的路径，且不误收路径碎片")
    void scannerResolvesConstantsAndIgnoresFragments() {
        String avatar = """
                self.networkManager.requestPost(
                    path: self.baseURL() + Self.uploadPath,
                    parameters: parameters)
                self.networkManager.requestPost(
                    path: self.baseURL() + Self.completePath(uploadId: uploadId),
                    parameters: [:])

                static let uploadPath = "/api/mobile/account/v1/profile/avatar/upload"

                static func completePath(uploadId: String) -> String {
                    return "/api/mobile/account/v1/profile/avatar/\\(uploadId)/complete"
                }
                """;
        String tsp = """
                TspManager.requestPost(path: "/unlockVehicle", parameters: [:])
                TspManager.requestGet(path: "/api/mobile/saleModel/v1/" + saleCode + "/featureCodeRanges", parameters: [:])
                NetworkManager.shared.requestPost(path: AppGlobalState.shared.tspUrl + "/api/mobile/auth/v1/sms/send", parameters: parameters)
                """;
        Set<String> paths = AppPathScanner.scan(avatar, tsp);
        assertThat(paths).contains(
                "/api/mobile/account/v1/profile/avatar/upload",
                "/api/mobile/account/v1/profile/avatar/complete",
                "/unlockVehicle",
                "/api/mobile/saleModel/v1",
                "/api/mobile/auth/v1/sms/send");
        assertThat(paths).as("路径碎片不得被当作调用点").doesNotContain("/featureCodeRanges");
        assertThat(AppPathScanner.unresolvedPathReferences(avatar)).isEmpty();
        assertThat(AppPathScanner.unresolvedPathReferences(
                "requestPost(path: self.baseURL() + Self.mysteryPath, parameters: [:])"))
                .as("无法解析的路径来源必须被暴露，避免静默漏检")
                .containsExactly("mysteryPath");
    }

    @Test
    @DisplayName("TC-003-20：车控路由严禁 ANONYMOUS（显式断言策略为 AUTHENTICATED + MOBILE + 权限点/scope）")
    void vehicleControlRoutesMustNotBeAnonymous() {
        List<SgwAppPathCatalog.AppPrefix> vehicleControl = SgwAppPathCatalog.APP_IN_USE_PREFIXES.stream()
                .filter(SgwAppPathCatalog.AppPrefix::vehicleControl)
                .toList();
        assertThat(vehicleControl).as("车控前缀必须显式登记").isNotEmpty();

        for (SgwAppPathCatalog.AppPrefix prefix : vehicleControl) {
            assertThat(prefix.accessMode()).as("车控前缀 %s 期望访问模式", prefix.prefix())
                    .isEqualTo(AccessMode.AUTHENTICATED);
            assertThat(prefix.accessMode()).as("车控前缀 %s 严禁匿名", prefix.prefix())
                    .isNotEqualTo(AccessMode.ANONYMOUS);

            SeedSql.SeedRoute route = SeedSql.allRoutes().stream()
                    .filter(item -> item.routeCode().equals(prefix.routeCode()))
                    .findFirst().orElseThrow(() -> new AssertionError("车控种子路由缺失: " + prefix.routeCode()));
            SeedSql.SeedPolicy policy = SeedSql.allPolicies().stream()
                    .filter(item -> item.policyCode().equals(route.authPolicyCode()))
                    .findFirst().orElseThrow(() -> new AssertionError(
                            "车控路由 " + route.routeCode() + " 引用的策略缺失: " + route.authPolicyCode()));

            assertThat(policy.accessMode()).as("车控路由 %s 的策略访问模式", route.routeCode())
                    .isEqualTo(AccessMode.AUTHENTICATED.name());
            assertThat(policy.accessMode()).as("车控路由 %s 严禁 ANONYMOUS", route.routeCode())
                    .isNotEqualTo(AccessMode.ANONYMOUS.name());
            assertThat(policy.allowedClientTypes()).as("车控路由 %s 必须限定客户端类型", route.routeCode())
                    .isNotBlank();
            assertThat(policy.allowedClientTypes().toUpperCase(Locale.ROOT))
                    .as("车控路由 %s 必须允许 MOBILE", route.routeCode()).contains("MOBILE");
            assertThat(policy.requiredScopes()).as("车控路由 %s 必须登记必要 scope", route.routeCode())
                    .isNotBlank();
            assertThat(policy.requiredPermissions()).as("车控路由 %s 必须登记必要权限点", route.routeCode())
                    .isNotBlank();
        }
    }

    @Test
    @DisplayName("TC-003-17：精确/零段语义（** 覆盖无尾段，精确路径不扩面）")
    void pathPatternSemantics() {
        List<CompiledRoute> seeded = seedRoutes();
        assertThat(matches(seeded, "/api/mobile/saleModel/v1"))
                .as("/api/mobile/saleModel/v1/** 必须覆盖无尾段的精确路径")
                .containsExactly("mobile-sale-model-v1");
        assertThat(matches(seeded, "/api/mobile/saleModel/v1/quote"))
                .containsExactly("mobile-sale-model-v1");
        assertThat(matches(seeded, "/api/mobile/v1/risk")).containsExactly("mobile-risk-v1");
        assertThat(matches(seeded, "/api/mobile/v1/risk/events"))
                .as("精确路径不得扩面到子路径")
                .isEmpty();
        assertThat(matches(seeded, "/api/mobile/unknown/v1/x")).isEmpty();
        assertThat(matches(seeded, "/unlockVehicle")).containsExactly("mobile-vehicle-unlock");
        assertThat(matches(seeded, "/unlockVehicle/extra"))
                .as("车控精确路径不得扩面到子路径")
                .isEmpty();
        assertThat(matches(seeded, "/mp/rvc")).containsExactly("mobile-rvc-v1");
        assertThat(matches(seeded, "/mp/rvc/cmd")).containsExactly("mobile-rvc-v1");
        assertThat(matches(seeded, "/mp/rvcx/cmd")).as("前缀必须按段边界匹配").isEmpty();
    }

    @Test
    @DisplayName("反向门禁：清单中每个前缀都能在种子中命中期望路由编码")
    void declaredPrefixesAreReachable() {
        List<CompiledRoute> seeded = seedRoutes();
        SgwAppPathCatalog.APP_IN_USE_PREFIXES.forEach(prefix ->
                assertThat(matches(seeded, probePath(prefix.prefix())))
                        .as("前缀 %s 必须命中 %s", prefix.prefix(), prefix.routeCode())
                        .contains(prefix.routeCode()));
    }

    private Set<String> appPaths() throws IOException {
        List<Path> sources = new ArrayList<>();
        for (String relative : AppPathScanner.IOS_SOURCES) {
            sources.add(AppPathScanner.locate(relative));
        }
        return AppPathScanner.scanFiles(sources);
    }

    private boolean hasCallSite(Set<String> paths, String prefix) {
        return paths.stream().anyMatch(path -> AppPathScanner.matchesPrefix(path, prefix));
    }

    private String probePath(String prefix) {
        return prefix.endsWith("/**") ? prefix.substring(0, prefix.length() - 3) + "/probe" : prefix;
    }

    private List<CompiledRoute> seedRoutes() {
        SgwConfiguration configuration = SgwConfiguration.builder()
                .routes(SeedSql.allRoutes().stream()
                        .map(seed -> RouteDefinition.builder()
                                .routeCode(seed.routeCode())
                                .routeName(seed.routeCode())
                                .priority(100)
                                .enabled(true)
                                .match(RouteMatch.builder().paths(seed.paths()).build())
                                .authPolicyCode(seed.authPolicyCode())
                                .build())
                        .toList())
                .build();
        return new SnapshotCompiler().compile(1L, "seed", configuration).getRoutes();
    }

    private List<String> matches(List<CompiledRoute> routes, String path) {
        RouteMatcher matcher = new RouteMatcher();
        Optional<CompiledRoute> matched = matcher.match(
                new net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.CompiledSnapshot(
                        1L, "seed", SgwConfiguration.builder().build(), routes, java.time.Instant.now()),
                MockServerHttpRequest.get(path).build());
        return matched.map(route -> List.of(route.routeCode())).orElseGet(List::of);
    }

    private boolean matches(CompiledRoute route, String path) {
        RouteMatcher matcher = new RouteMatcher();
        return matcher.match(new net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.CompiledSnapshot(
                        1L, "seed", SgwConfiguration.builder().build(), List.of(route), java.time.Instant.now()),
                MockServerHttpRequest.get(path).build()).isPresent();
    }

}
