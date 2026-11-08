package net.hwyz.iov.cloud.edd.sgw.domain.validation;

import net.hwyz.iov.cloud.edd.sgw.api.enums.MatchType;
import net.hwyz.iov.cloud.edd.sgw.api.enums.RouteTargetType;
import net.hwyz.iov.cloud.edd.sgw.domain.model.HeaderMatch;
import net.hwyz.iov.cloud.edd.sgw.domain.model.QueryParamMatch;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RewritePath;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteMatch;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteTarget;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteTransform;
import net.hwyz.iov.cloud.framework.common.enums.ClientType;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

/**
 * 路由配置校验器。
 *
 * @author hwyz_leo
 */
@Component
public class RouteValidator {

    /** 编码格式 */
    public static final Pattern CODE_PATTERN = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9_-]{1,127}$");

    private static final Set<String> HTTP_METHODS = Set.of("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS");

    private static final Set<String> HOP_BY_HOP_HEADERS = Set.of("connection", "keep-alive", "transfer-encoding",
            "te", "trailer", "upgrade", "proxy-authenticate", "proxy-authorization", "host", "content-length", "expect");

    private static final Set<String> CLIENT_TYPES = Arrays.stream(ClientType.values())
            .map(Enum::name)
            .collect(Collectors.toUnmodifiableSet());

    /**
     * 校验路由配置
     *
     * @param route       路由
     * @param directHosts 获批直连主机
     * @return 校验结果
     */
    public ValidationResult validate(RouteDefinition route, Set<String> directHosts) {
        ValidationResult result = ValidationResult.ok();
        if (route == null) {
            return result.add("route", "路由不能为空");
        }
        validateCode("routeCode", route.getRouteCode(), result);
        if (isBlank(route.getRouteName())) {
            result.add("routeName", "路由名称不能为空");
        }
        if (route.getPriority() == null) {
            result.add("priority", "优先级不能为空");
        } else if (route.getPriority() < 0) {
            result.add("priority", "优先级不能为负数");
        }
        validateMatch(route.getMatch(), result);
        validateTarget("target", route.getTarget(), directHosts, result);
        validateTransform(route.getTransform(), result);
        return result;
    }

    /**
     * 校验编码
     *
     * @param field  字段
     * @param code   编码
     * @param result 结果
     */
    public static void validateCode(String field, String code, ValidationResult result) {
        if (isBlank(code)) {
            result.add(field, "编码不能为空");
        } else if (!CODE_PATTERN.matcher(code).matches()) {
            result.add(field, "编码仅允许字母、数字、下划线和连字符，且不能以连字符开头");
        }
    }

    /**
     * 校验路由目标
     *
     * @param field       字段前缀
     * @param target      目标
     * @param directHosts 获批直连主机
     * @param result      结果
     */
    public static void validateTarget(String field, RouteTarget target, Set<String> directHosts,
                                      ValidationResult result) {
        if (target == null || target.getType() == null) {
            result.add(field, "目标类型不能为空");
            return;
        }
        RouteTargetType type = target.getType();
        if (type == RouteTargetType.SERVICE) {
            if (isBlank(target.getServiceId())) {
                result.add(field + ".serviceId", "服务发现目标必须指定服务ID");
            }
            if (!isBlank(target.getUri())) {
                result.add(field + ".uri", "serviceId 与 uri 互斥");
            }
            return;
        }
        if (!isBlank(target.getServiceId())) {
            result.add(field + ".serviceId", "serviceId 与 uri 互斥");
        }
        if (isBlank(target.getUri())) {
            result.add(field + ".uri", "直连目标必须指定 URI");
            return;
        }
        URI uri;
        try {
            uri = URI.create(target.getUri());
        } catch (IllegalArgumentException e) {
            result.add(field + ".uri", "直连目标 URI 非法");
            return;
        }
        String expectedScheme = type.scheme();
        if (uri.getScheme() == null || !expectedScheme.equalsIgnoreCase(uri.getScheme())) {
            result.add(field + ".uri", "直连目标协议必须为 " + expectedScheme);
            return;
        }
        if (uri.getHost() == null) {
            result.add(field + ".uri", "直连目标缺少主机");
            return;
        }
        if (uri.getQuery() != null || uri.getFragment() != null) {
            result.add(field + ".uri", "直连目标不能包含查询参数或片段");
        }
        if (!hostAllowed(uri.getHost(), uri.getPort(), directHosts)) {
            result.add(field + ".uri", "直连目标主机未在获批清单中");
        }
    }

    private static boolean hostAllowed(String host, int port, Set<String> directHosts) {
        if (directHosts == null || directHosts.isEmpty()) {
            return false;
        }
        String hostWithPort = port > 0 ? host.toLowerCase(Locale.ROOT) + ":" + port : host.toLowerCase(Locale.ROOT);
        String plainHost = host.toLowerCase(Locale.ROOT);
        return directHosts.stream()
                .filter(entry -> entry != null && !entry.isBlank())
                .map(entry -> entry.trim().toLowerCase(Locale.ROOT))
                .anyMatch(entry -> matchesHostEntry(entry, plainHost, hostWithPort));
    }

    private static boolean matchesHostEntry(String entry, String host, String hostWithPort) {
        if (entry.equals(host) || entry.equals(hostWithPort)) {
            return true;
        }
        if (entry.startsWith("*.")) {
            String suffix = entry.substring(1);
            return host.endsWith(suffix) && host.length() > suffix.length();
        }
        return false;
    }

    private void validateMatch(RouteMatch match, ValidationResult result) {
        if (match == null) {
            result.add("match", "匹配条件不能为空");
            return;
        }
        match.normalized();
        if (match.getPaths().isEmpty()) {
            result.add("match.paths", "至少需要一个路径匹配规则");
        }
        for (int i = 0; i < match.getPaths().size(); i++) {
            String path = match.getPaths().get(i);
            if (isBlank(path) || !path.startsWith("/")) {
                result.add("match.paths[" + i + "]", "路径必须以 / 开头");
            }
        }
        for (int i = 0; i < match.getMethods().size(); i++) {
            String method = match.getMethods().get(i);
            if (method == null || !HTTP_METHODS.contains(method.toUpperCase(Locale.ROOT))) {
                result.add("match.methods[" + i + "]", "不支持的 HTTP 方法");
            }
        }
        for (int i = 0; i < match.getHosts().size(); i++) {
            String host = match.getHosts().get(i);
            if (isBlank(host) || host.contains("://") || host.contains("/")) {
                result.add("match.hosts[" + i + "]", "主机规则非法");
            }
        }
        List<HeaderMatch> headers = match.getHeaders();
        for (int i = 0; i < headers.size(); i++) {
            validateHeaderMatch("match.headers[" + i + "]", headers.get(i), result);
        }
        List<QueryParamMatch> queryParams = match.getQueryParams();
        for (int i = 0; i < queryParams.size(); i++) {
            QueryParamMatch queryParam = queryParams.get(i);
            String field = "match.queryParams[" + i + "]";
            if (queryParam == null || isBlank(queryParam.getName())) {
                result.add(field + ".name", "参数名称不能为空");
            }
            if (queryParam != null) {
                validateMatchType(field, queryParam.getMatchType(), queryParam.getValue(), result);
            }
        }
        for (int i = 0; i < match.getClientTypes().size(); i++) {
            String clientType = match.getClientTypes().get(i);
            if (clientType == null || !CLIENT_TYPES.contains(clientType.toUpperCase(Locale.ROOT))) {
                result.add("match.clientTypes[" + i + "]", "未知客户端类型");
            }
        }
    }

    private boolean hasIllegalHeaderChars(String value) {
        return value != null && value.chars().anyMatch(ch -> ch < 32 || ch == 127);
    }

    private void validateTransform(RouteTransform transform, ValidationResult result) {
        if (transform == null) {
            return;
        }
        transform.normalized();
        RewritePath rewritePath = transform.getRewritePath();
        if (rewritePath != null) {
            if (isBlank(rewritePath.getPattern())) {
                result.add("transform.rewritePath.pattern", "重写路径正则不能为空");
            } else if (!rewritePath.getPattern().startsWith("/")) {
                result.add("transform.rewritePath.pattern", "重写路径正则以 / 开头");
            } else {
                try {
                    Pattern.compile(rewritePath.getPattern());
                } catch (PatternSyntaxException e) {
                    result.add("transform.rewritePath.pattern", "重写路径正则非法");
                }
            }
            if (isBlank(rewritePath.getReplacement())) {
                result.add("transform.rewritePath.replacement", "重写替换表达式不能为空");
            }
        }
        transform.getHeadersToAdd().forEach((name, value) -> {
            if (isBlank(name)) {
                result.add("transform.headersToAdd", "请求头名称不能为空");
            } else if (HOP_BY_HOP_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                result.add("transform.headersToAdd." + name, "禁止变换逐跳请求头");
            } else if (hasIllegalHeaderChars(name) || hasIllegalHeaderChars(value)) {
                result.add("transform.headersToAdd." + name, "请求头名称或值包含非法控制字符");
            }
        });
        for (int i = 0; i < transform.getHeadersToRemove().size(); i++) {
            String name = transform.getHeadersToRemove().get(i);
            if (isBlank(name)) {
                result.add("transform.headersToRemove[" + i + "]", "请求头名称不能为空");
            } else if (HOP_BY_HOP_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                result.add("transform.headersToRemove[" + i + "]", "禁止移除逐跳请求头");
            }
        }
    }

    private void validateHeaderMatch(String field, HeaderMatch headerMatch, ValidationResult result) {
        if (headerMatch == null || isBlank(headerMatch.getName())) {
            result.add(field + ".name", "请求头名称不能为空");
            return;
        }
        validateMatchType(field, headerMatch.getMatchType(), headerMatch.getValue(), result);
    }

    private void validateMatchType(String field, MatchType matchType, String value, ValidationResult result) {
        if (matchType == null) {
            result.add(field + ".matchType", "匹配方式不能为空");
            return;
        }
        if (value == null) {
            result.add(field + ".value", "匹配值不能为空");
            return;
        }
        if (matchType == MatchType.REGEX) {
            try {
                Pattern.compile(value);
            } catch (PatternSyntaxException e) {
                result.add(field + ".value", "正则表达式非法");
            }
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

}
