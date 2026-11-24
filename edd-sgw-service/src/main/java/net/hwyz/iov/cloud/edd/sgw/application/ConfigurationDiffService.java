package net.hwyz.iov.cloud.edd.sgw.application;

import com.fasterxml.jackson.databind.JsonNode;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigDiffItemVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigFieldDiffVo;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.domain.model.AuthPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.SgwConfiguration;
import net.hwyz.iov.cloud.edd.sgw.domain.model.TrafficPolicy;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;

/**
 * 结构化配置差异服务（EDD-SGW-DSN-CR-004）。
 * <p>
 * 历史版本比较与待发布变更预览共用同一差异语义：对象级沿用 canonical JSON 相等判定，
 * 修改对象增量给出 JSON Pointer 字段级前后值。
 *
 * @author hwyz_leo
 */
@Service
public class ConfigurationDiffService {

    /** 对象类型：路由 */
    public static final String TYPE_ROUTE = "ROUTE";

    /** 对象类型：认证授权策略 */
    public static final String TYPE_AUTH_POLICY = "AUTH_POLICY";

    /** 对象类型：流量治理策略 */
    public static final String TYPE_TRAFFIC_POLICY = "TRAFFIC_POLICY";

    /** 对象类型：灰度策略 */
    public static final String TYPE_CANARY_POLICY = "CANARY_POLICY";

    /** 变化类型：新增 */
    public static final String CHANGE_ADDED = "ADDED";

    /** 变化类型：修改 */
    public static final String CHANGE_MODIFIED = "MODIFIED";

    /** 变化类型：删除 */
    public static final String CHANGE_REMOVED = "REMOVED";

    /**
     * 比较两份完整配置
     *
     * @param before 基准配置
     * @param after  目标配置
     * @return 差异项（按对象类型固定顺序，类型内按编码首次出现顺序）
     */
    public List<ConfigDiffItemVo> compare(SgwConfiguration before, SgwConfiguration after) {
        SgwConfiguration base = before == null ? empty() : before.normalized();
        SgwConfiguration target = after == null ? empty() : after.normalized();
        List<ConfigDiffItemVo> items = new ArrayList<>();
        compareObjects(TYPE_ROUTE, base.getRoutes(), target.getRoutes(), RouteDefinition::getRouteCode, items);
        compareObjects(TYPE_AUTH_POLICY, base.getAuthPolicies(), target.getAuthPolicies(),
                AuthPolicy::getPolicyCode, items);
        compareObjects(TYPE_TRAFFIC_POLICY, base.getTrafficPolicies(), target.getTrafficPolicies(),
                TrafficPolicy::getPolicyCode, items);
        compareObjects(TYPE_CANARY_POLICY, base.getCanaryPolicies(), target.getCanaryPolicies(),
                CanaryPolicy::getPolicyCode, items);
        return items;
    }

    /**
     * 计算两个 JSON 树的字段级差异
     *
     * @param before 基准内容
     * @param after  目标内容
     * @return 字段差异（按 JSON Pointer 字典序）
     */
    public List<ConfigFieldDiffVo> fieldDiffs(JsonNode before, JsonNode after) {
        List<ConfigFieldDiffVo> diffs = new ArrayList<>();
        collectFieldDiffs("", before, after, diffs);
        diffs.sort(Comparator.comparing(ConfigFieldDiffVo::getPath));
        return diffs;
    }

    private <T> void compareObjects(String type, List<T> before, List<T> after, Function<T, String> code,
                                    List<ConfigDiffItemVo> items) {
        Map<String, JsonNode> beforeMap = index(before, code);
        Map<String, JsonNode> afterMap = index(after, code);
        Set<String> codes = new LinkedHashSet<>(beforeMap.keySet());
        codes.addAll(afterMap.keySet());
        for (String code0 : codes) {
            JsonNode beforeNode = beforeMap.get(code0);
            JsonNode afterNode = afterMap.get(code0);
            if (beforeNode == null) {
                items.add(item(type, code0, CHANGE_ADDED, null, afterNode));
            } else if (afterNode == null) {
                items.add(item(type, code0, CHANGE_REMOVED, beforeNode, null));
            } else if (!beforeNode.equals(afterNode)) {
                List<ConfigFieldDiffVo> fields = fieldDiffs(beforeNode, afterNode);
                items.add(ConfigDiffItemVo.builder()
                        .objectType(type)
                        .code(code0)
                        .changeType(CHANGE_MODIFIED)
                        .before(beforeNode)
                        .after(afterNode)
                        .fields(fields)
                        .build());
            }
        }
    }

    private <T> Map<String, JsonNode> index(List<T> values, Function<T, String> code) {
        Map<String, JsonNode> result = new LinkedHashMap<>();
        if (values == null) {
            return result;
        }
        for (T value : values) {
            String key = code.apply(value);
            if (key == null) {
                continue;
            }
            result.put(key, Json.tree(Json.canonical(value)));
        }
        return result;
    }

    private ConfigDiffItemVo item(String type, String code, String changeType, JsonNode before, JsonNode after) {
        return ConfigDiffItemVo.builder()
                .objectType(type)
                .code(code)
                .changeType(changeType)
                .before(before)
                .after(after)
                .fields(new ArrayList<>())
                .build();
    }

    private void collectFieldDiffs(String path, JsonNode before, JsonNode after, List<ConfigFieldDiffVo> diffs) {
        if (before == null && after == null) {
            return;
        }
        if (before == null) {
            diffs.add(field(path, CHANGE_ADDED, null, after));
            return;
        }
        if (after == null) {
            diffs.add(field(path, CHANGE_REMOVED, before, null));
            return;
        }
        if (before.equals(after)) {
            return;
        }
        if (before.isObject() && after.isObject()) {
            Set<String> names = new TreeSet<>();
            before.fieldNames().forEachRemaining(names::add);
            after.fieldNames().forEachRemaining(names::add);
            for (String name : names) {
                collectFieldDiffs(path + "/" + escape(name), before.get(name), after.get(name), diffs);
            }
            return;
        }
        if (before.isArray() && after.isArray()) {
            int max = Math.max(before.size(), after.size());
            for (int i = 0; i < max; i++) {
                collectFieldDiffs(path + "/" + i, element(before, i), element(after, i), diffs);
            }
            return;
        }
        diffs.add(field(path, CHANGE_MODIFIED, before, after));
    }

    private JsonNode element(JsonNode array, int index) {
        return index < array.size() ? array.get(index) : null;
    }

    private ConfigFieldDiffVo field(String path, String changeType, JsonNode before, JsonNode after) {
        return ConfigFieldDiffVo.builder()
                .path(path)
                .changeType(changeType)
                .beforeValue(before)
                .afterValue(after)
                .build();
    }

    private String escape(String name) {
        return name.replace("~", "~0").replace("/", "~1");
    }

    private SgwConfiguration empty() {
        return SgwConfiguration.builder().build().normalized();
    }

}
