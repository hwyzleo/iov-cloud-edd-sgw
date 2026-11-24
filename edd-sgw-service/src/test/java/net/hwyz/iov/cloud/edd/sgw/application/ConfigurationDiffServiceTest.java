package net.hwyz.iov.cloud.edd.sgw.application;

import com.fasterxml.jackson.databind.JsonNode;
import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;
import net.hwyz.iov.cloud.edd.sgw.api.enums.CanaryStableKey;
import net.hwyz.iov.cloud.edd.sgw.api.enums.RouteTargetType;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigDiffItemVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigFieldDiffVo;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.domain.model.AuthPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryRule;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryTarget;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RateLimitRule;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteMatch;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteTarget;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteTransform;
import net.hwyz.iov.cloud.edd.sgw.domain.model.SgwConfiguration;
import net.hwyz.iov.cloud.edd.sgw.domain.model.TrafficPolicy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 结构化配置差异服务测试（EDD-SGW-DSN-CR-004，TC-004-1/2/3）。
 *
 * @author hwyz_leo
 */
class ConfigurationDiffServiceTest {

    private final ConfigurationDiffService service = new ConfigurationDiffService();

    @Test
    @DisplayName("四类对象的 ADDED、MODIFIED、REMOVED 返回类型、编码、变化类型与完整前后值")
    void comparesAllObjectTypes() {
        SgwConfiguration before = SgwConfiguration.builder()
                .routes(List.of(route("route-mod", 100), route("route-del", 100)))
                .authPolicies(List.of(authPolicy("auth-mod", "原-scope"), authPolicy("auth-del", "原-scope")))
                .trafficPolicies(List.of(trafficPolicy("traffic-mod", 1000), trafficPolicy("traffic-del", 1000)))
                .canaryPolicies(List.of(canaryPolicy("canary-mod", 10), canaryPolicy("canary-del", 10)))
                .build();
        SgwConfiguration after = SgwConfiguration.builder()
                .routes(List.of(route("route-mod", 200), route("route-add", 300)))
                .authPolicies(List.of(authPolicy("auth-mod", "新-scope"), authPolicy("auth-add", "新-scope")))
                .trafficPolicies(List.of(trafficPolicy("traffic-mod", 2000), trafficPolicy("traffic-add", 2000)))
                .canaryPolicies(List.of(canaryPolicy("canary-mod", 20), canaryPolicy("canary-add", 20)))
                .build();

        List<ConfigDiffItemVo> items = service.compare(before, after);

        assertThat(items).hasSize(12);
        assertThat(items).extracting(ConfigDiffItemVo::getObjectType)
                .containsExactly(
                        "ROUTE", "ROUTE", "ROUTE",
                        "AUTH_POLICY", "AUTH_POLICY", "AUTH_POLICY",
                        "TRAFFIC_POLICY", "TRAFFIC_POLICY", "TRAFFIC_POLICY",
                        "CANARY_POLICY", "CANARY_POLICY", "CANARY_POLICY");
        assertChange(items, "ROUTE", "route-mod", "MODIFIED");
        assertChange(items, "ROUTE", "route-del", "REMOVED");
        assertChange(items, "ROUTE", "route-add", "ADDED");
        assertChange(items, "AUTH_POLICY", "auth-mod", "MODIFIED");
        assertChange(items, "AUTH_POLICY", "auth-del", "REMOVED");
        assertChange(items, "AUTH_POLICY", "auth-add", "ADDED");
        assertChange(items, "TRAFFIC_POLICY", "traffic-mod", "MODIFIED");
        assertChange(items, "TRAFFIC_POLICY", "traffic-del", "REMOVED");
        assertChange(items, "TRAFFIC_POLICY", "traffic-add", "ADDED");
        assertChange(items, "CANARY_POLICY", "canary-mod", "MODIFIED");
        assertChange(items, "CANARY_POLICY", "canary-del", "REMOVED");
        assertChange(items, "CANARY_POLICY", "canary-add", "ADDED");

        ConfigDiffItemVo added = item(items, "ROUTE", "route-add");
        assertThat(added.getBefore()).isNull();
        assertThat(added.getAfter().get("routeCode").asText()).isEqualTo("route-add");
        assertThat(added.getAfter().get("priority").asInt()).isEqualTo(300);
        assertThat(added.getFields()).isEmpty();

        ConfigDiffItemVo removed = item(items, "ROUTE", "route-del");
        assertThat(removed.getAfter()).isNull();
        assertThat(removed.getBefore().get("routeCode").asText()).isEqualTo("route-del");
        assertThat(removed.getFields()).isEmpty();

        ConfigDiffItemVo modified = item(items, "ROUTE", "route-mod");
        assertThat(modified.getBefore().get("priority").asInt()).isEqualTo(100);
        assertThat(modified.getAfter().get("priority").asInt()).isEqualTo(200);
        assertThat(modified.getFields()).isNotEmpty();
        assertThat(modified.getFields()).extracting(ConfigFieldDiffVo::getPath)
                .containsExactly("/priority");
        assertThat(field(modified, "/priority").getBeforeValue().asInt()).isEqualTo(100);
        assertThat(field(modified, "/priority").getAfterValue().asInt()).isEqualTo(200);
        assertThat(field(modified, "/priority").getChangeType()).isEqualTo("MODIFIED");
    }

    @Test
    @DisplayName("嵌套对象、数组元素、字段新增删除返回 JSON Pointer 与原始 JSON 类型值")
    void reportsNestedFieldsWithJsonPointers() {
        Map<String, String> beforeHeaders = new LinkedHashMap<>();
        beforeHeaders.put("X/Debug~Flag", "off");
        Map<String, String> afterHeaders = new LinkedHashMap<>();
        afterHeaders.put("X/Debug~Flag", "on");

        RouteDefinition before = RouteDefinition.builder()
                .routeCode("vehicle-profile")
                .routeName("车辆画像")
                .description("发布前说明")
                .priority(100)
                .enabled(true)
                .match(RouteMatch.builder().paths(new ArrayList<>(List.of("/v1/vehicles"))).methods(List.of("GET"))
                        .clientTypes(List.of("MOBILE")).build())
                .target(RouteTarget.builder().type(RouteTargetType.SERVICE).serviceId("edd-vmd-service").build())
                .transform(RouteTransform.builder().headersToAdd(beforeHeaders)
                        .headersToRemove(new ArrayList<>(List.of("X-Legacy"))).build())
                .build();
        RouteDefinition after = RouteDefinition.builder()
                .routeCode("vehicle-profile")
                .routeName("车辆画像")
                .priority(200)
                .enabled(false)
                .match(RouteMatch.builder().paths(new ArrayList<>(List.of("/v2/vehicles"))).methods(List.of("GET", "POST"))
                        .clientTypes(List.of("MOBILE")).build())
                .target(RouteTarget.builder().type(RouteTargetType.SERVICE).serviceId("edd-vmd-service").build())
                .transform(RouteTransform.builder().headersToAdd(afterHeaders).build())
                .build();

        List<ConfigDiffItemVo> items = service.compare(
                SgwConfiguration.builder().routes(List.of(before)).build(),
                SgwConfiguration.builder().routes(List.of(after)).build());

        ConfigDiffItemVo item = item(items, "ROUTE", "vehicle-profile");
        assertThat(item.getChangeType()).isEqualTo("MODIFIED");
        assertThat(item.getFields()).extracting(ConfigFieldDiffVo::getPath).containsExactly(
                "/description",
                "/enabled",
                "/match/methods/1",
                "/match/paths/0",
                "/priority",
                "/transform/headersToAdd/X~1Debug~0Flag",
                "/transform/headersToRemove/0");

        assertThat(field(item, "/description").getChangeType()).isEqualTo("REMOVED");
        assertThat(field(item, "/description").getAfterValue()).isNull();
        assertThat(field(item, "/description").getBeforeValue().asText()).isEqualTo("发布前说明");

        assertThat(field(item, "/enabled").getChangeType()).isEqualTo("MODIFIED");
        assertThat(field(item, "/enabled").getBeforeValue().isBoolean()).isTrue();
        assertThat(field(item, "/enabled").getAfterValue().asBoolean()).isFalse();

        assertThat(field(item, "/match/methods/1").getChangeType()).isEqualTo("ADDED");
        assertThat(field(item, "/match/methods/1").getBeforeValue()).isNull();
        assertThat(field(item, "/match/methods/1").getAfterValue().asText()).isEqualTo("POST");

        assertThat(field(item, "/match/paths/0").getBeforeValue().asText()).isEqualTo("/v1/vehicles");
        assertThat(field(item, "/match/paths/0").getAfterValue().asText()).isEqualTo("/v2/vehicles");

        assertThat(field(item, "/priority").getBeforeValue().isInt()).isTrue();

        ConfigFieldDiffVo header = field(item, "/transform/headersToAdd/X~1Debug~0Flag");
        assertThat(header.getChangeType()).isEqualTo("MODIFIED");
        assertThat(header.getBeforeValue().asText()).isEqualTo("off");
        assertThat(header.getAfterValue().asText()).isEqualTo("on");

        ConfigFieldDiffVo removedHeader = field(item, "/transform/headersToRemove/0");
        assertThat(removedHeader.getChangeType()).isEqualTo("REMOVED");
        assertThat(removedHeader.getBeforeValue().asText()).isEqualTo("X-Legacy");
        assertThat(removedHeader.getAfterValue()).isNull();
    }

    @Test
    @DisplayName("类型不一致按单条字段差异报告，不递归展开")
    void reportsTypeMismatchAsSingleField() {
        List<ConfigFieldDiffVo> fields = service.fieldDiffs(
                Json.tree("{\"value\":{\"a\":1},\"flag\":1}"),
                Json.tree("{\"value\":\"text\",\"flag\":{\"b\":2}}"));
        assertThat(fields).extracting(ConfigFieldDiffVo::getPath).containsExactly("/flag", "/value");
        ConfigFieldDiffVo value = fields.get(1);
        assertThat(value.getChangeType()).isEqualTo("MODIFIED");
        assertThat(value.getBeforeValue().isObject()).isTrue();
        assertThat(value.getAfterValue().isTextual()).isTrue();
    }

    @Test
    @DisplayName("相同规范化配置返回空差异，数组顺序变化按索引解释且响应顺序稳定")
    void handlesIdenticalAndReorderedArrays() {
        SgwConfiguration left = SgwConfiguration.builder()
                .routes(List.of(route("stable", 100)))
                .trafficPolicies(List.of(trafficPolicy("traffic", 1000)))
                .build();
        SgwConfiguration right = SgwConfiguration.builder()
                .routes(List.of(route("stable", 100)))
                .trafficPolicies(List.of(trafficPolicy("traffic", 1000)))
                .build();
        assertThat(service.compare(left, right)).isEmpty();

        RouteDefinition reorderedBefore = RouteDefinition.builder()
                .routeCode("reorder")
                .match(RouteMatch.builder().paths(new ArrayList<>(List.of("/a", "/b", "/c"))).build())
                .build();
        RouteDefinition reorderedAfter = RouteDefinition.builder()
                .routeCode("reorder")
                .match(RouteMatch.builder().paths(new ArrayList<>(List.of("/b", "/a", "/c"))).build())
                .build();
        SgwConfiguration before = SgwConfiguration.builder().routes(List.of(reorderedBefore)).build();
        SgwConfiguration after = SgwConfiguration.builder().routes(List.of(reorderedAfter)).build();

        ConfigDiffItemVo item = item(service.compare(before, after), "ROUTE", "reorder");
        assertThat(item.getFields()).extracting(ConfigFieldDiffVo::getPath)
                .containsExactly("/match/paths/0", "/match/paths/1");

        List<String> first = service.compare(before, after).get(0).getFields().stream()
                .map(ConfigFieldDiffVo::getPath).toList();
        List<String> second = service.compare(before, after).get(0).getFields().stream()
                .map(ConfigFieldDiffVo::getPath).toList();
        assertThat(first).isEqualTo(second);
    }

    @Test
    @DisplayName("空基准配置将全部有效草稿对象报告为新增")
    void treatsEmptyBaseAsAllAdded() {
        SgwConfiguration draft = SgwConfiguration.builder()
                .routes(List.of(route("r1", 100)))
                .authPolicies(List.of(authPolicy("a1", "scope")))
                .trafficPolicies(List.of(trafficPolicy("t1", 1000)))
                .canaryPolicies(List.of(canaryPolicy("c1", 10)))
                .build();

        List<ConfigDiffItemVo> items = service.compare(null, draft);

        assertThat(items).extracting(ConfigDiffItemVo::getObjectType)
                .containsExactly("ROUTE", "AUTH_POLICY", "TRAFFIC_POLICY", "CANARY_POLICY");
        assertThat(items).allSatisfy(item -> {
            assertThat(item.getChangeType()).isEqualTo("ADDED");
            assertThat(item.getBefore()).isNull();
            assertThat(item.getAfter()).isNotNull();
            assertThat(item.getFields()).isEmpty();
        });
    }

    private void assertChange(List<ConfigDiffItemVo> items, String type, String code, String changeType) {
        ConfigDiffItemVo item = item(items, type, code);
        assertThat(item.getChangeType()).as(type + "/" + code).isEqualTo(changeType);
    }

    private ConfigDiffItemVo item(List<ConfigDiffItemVo> items, String type, String code) {
        return items.stream()
                .filter(item -> item.getObjectType().equals(type) && item.getCode().equals(code))
                .findFirst()
                .orElseThrow(() -> new AssertionError("缺少差异项: " + type + "/" + code));
    }

    private ConfigFieldDiffVo field(ConfigDiffItemVo item, String path) {
        return item.getFields().stream()
                .filter(field -> field.getPath().equals(path))
                .findFirst()
                .orElseThrow(() -> new AssertionError("缺少字段差异: " + path));
    }

    private RouteDefinition route(String code, int priority) {
        return RouteDefinition.builder()
                .routeCode(code)
                .routeName(code)
                .priority(priority)
                .enabled(true)
                .match(RouteMatch.builder().paths(new ArrayList<>(List.of("/" + code))).methods(List.of("GET"))
                        .clientTypes(List.of("MOBILE")).build())
                .target(RouteTarget.builder().type(RouteTargetType.SERVICE).serviceId("edd-vmd-service").build())
                .build();
    }

    private AuthPolicy authPolicy(String code, String scope) {
        return AuthPolicy.builder()
                .policyCode(code)
                .policyName(code)
                .accessMode(AccessMode.AUTHENTICATED)
                .allowedClientTypes(List.of("MOBILE"))
                .requiredScopes(List.of(scope))
                .enabled(true)
                .build();
    }

    private TrafficPolicy trafficPolicy(String code, int responseTimeoutMillis) {
        RateLimitRule rateLimit = RateLimitRule.builder()
                .replenishPerSecond(10)
                .burstCapacity(20)
                .build();
        return TrafficPolicy.builder()
                .policyCode(code)
                .policyName(code)
                .connectTimeoutMillis(500)
                .responseTimeoutMillis(responseTimeoutMillis)
                .rateLimits(List.of(rateLimit))
                .enabled(true)
                .build();
    }

    private CanaryPolicy canaryPolicy(String code, int weight) {
        CanaryTarget target = CanaryTarget.builder()
                .type(RouteTargetType.SERVICE)
                .serviceId("edd-vmd-service")
                .weight(weight)
                .build();
        return CanaryPolicy.builder()
                .policyCode(code)
                .policyName(code)
                .stableKey(CanaryStableKey.VEHICLE_ID)
                .rules(List.of(CanaryRule.builder().priority(1).targets(List.of(target)).build()))
                .enabled(true)
                .build();
    }

}
