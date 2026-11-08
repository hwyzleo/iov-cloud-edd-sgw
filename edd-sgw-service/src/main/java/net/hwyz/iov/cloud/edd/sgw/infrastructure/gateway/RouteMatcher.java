package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

import net.hwyz.iov.cloud.edd.sgw.api.enums.MatchType;
import net.hwyz.iov.cloud.edd.sgw.domain.model.HeaderMatch;
import net.hwyz.iov.cloud.edd.sgw.domain.model.QueryParamMatch;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteMatch;
import net.hwyz.iov.cloud.framework.common.constant.CustomHeaders;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.util.pattern.PathPattern;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * 路由匹配器：按优先级遍历已编译快照中的路由。
 *
 * @author hwyz_leo
 */
@Component
public class RouteMatcher {

    /**
     * 选择匹配的路由
     *
     * @param snapshot 快照
     * @param request  请求
     * @return 匹配结果
     */
    public Optional<CompiledRoute> match(CompiledSnapshot snapshot, ServerHttpRequest request) {
        String declaredClientType = request.getHeaders().getFirst(CustomHeaders.CLIENT_TYPE);
        for (CompiledRoute route : snapshot.getRoutes()) {
            if (matches(route, request, declaredClientType)) {
                return Optional.of(route);
            }
        }
        return Optional.empty();
    }

    private boolean matches(CompiledRoute compiledRoute, ServerHttpRequest request, String declaredClientType) {
        RouteDefinition route = compiledRoute.getDefinition();
        RouteMatch match = route.getMatch();
        if (match == null) {
            return false;
        }
        if (!matchPaths(compiledRoute, request)) {
            return false;
        }
        if (!match.getMethods().isEmpty()
                && match.getMethods().stream().noneMatch(method -> method.equalsIgnoreCase(request.getMethod().name()))) {
            return false;
        }
        if (!matchHosts(match.getHosts(), request)) {
            return false;
        }
        if (!matchHeaders(compiledRoute, match.getHeaders(), request)) {
            return false;
        }
        if (!matchQueryParams(compiledRoute, match.getQueryParams(), request)) {
            return false;
        }
        if (!match.getClientTypes().isEmpty()) {
            if (declaredClientType == null) {
                return false;
            }
            String normalized = declaredClientType.toUpperCase(Locale.ROOT);
            if (match.getClientTypes().stream().noneMatch(type -> type.equalsIgnoreCase(normalized))) {
                return false;
            }
        }
        return true;
    }

    private boolean matchPaths(CompiledRoute route, ServerHttpRequest request) {
        if (route.getPaths().isEmpty()) {
            return true;
        }
        for (PathPattern pathPattern : route.getPaths()) {
            if (pathPattern.matches(request.getPath().pathWithinApplication())) {
                return true;
            }
        }
        return false;
    }

    private boolean matchHosts(List<String> hosts, ServerHttpRequest request) {
        if (hosts.isEmpty()) {
            return true;
        }
        String host = request.getHeaders().getFirst(HttpHeaders.HOST);
        if (host == null) {
            host = request.getURI().getHost();
        }
        if (host == null) {
            return false;
        }
        int colon = host.lastIndexOf(':');
        if (colon > 0 && host.indexOf(':') == colon) {
            host = host.substring(0, colon);
        }
        String normalized = host.toLowerCase(Locale.ROOT);
        return hosts.stream().anyMatch(pattern -> hostMatches(pattern.toLowerCase(Locale.ROOT), normalized));
    }

    private boolean hostMatches(String pattern, String host) {
        if ("*".equals(pattern) || "**".equals(pattern)) {
            return true;
        }
        if (pattern.startsWith("**.")) {
            String suffix = pattern.substring(2);
            return host.endsWith(suffix);
        }
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1);
            if (!host.endsWith(suffix)) {
                return false;
            }
            String prefix = host.substring(0, host.length() - suffix.length());
            return !prefix.isEmpty() && !prefix.contains(".");
        }
        return pattern.equals(host);
    }

    private boolean matchHeaders(CompiledRoute compiledRoute, List<HeaderMatch> headers, ServerHttpRequest request) {
        for (int i = 0; i < headers.size(); i++) {
            HeaderMatch headerMatch = headers.get(i);
            String actual = request.getHeaders().getFirst(headerMatch.getName());
            if (actual == null) {
                return false;
            }
            if (headerMatch.getMatchType() == MatchType.EXACT) {
                if (!headerMatch.getValue().equals(actual)) {
                    return false;
                }
            } else if (!compiledRoute.getHeaderPatterns().get(i).matcher(actual).matches()) {
                return false;
            }
        }
        return true;
    }

    private boolean matchQueryParams(CompiledRoute compiledRoute, List<QueryParamMatch> queryParams,
                                     ServerHttpRequest request) {
        for (int i = 0; i < queryParams.size(); i++) {
            QueryParamMatch queryParam = queryParams.get(i);
            String actual = request.getQueryParams().getFirst(queryParam.getName());
            if (actual == null) {
                return false;
            }
            if (queryParam.getMatchType() == MatchType.EXACT) {
                if (!queryParam.getValue().equals(actual)) {
                    return false;
                }
            } else if (!compiledRoute.getQueryPatterns().get(i).matcher(actual).matches()) {
                return false;
            }
        }
        return true;
    }

}
