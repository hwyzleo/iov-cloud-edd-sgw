package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

import net.hwyz.iov.cloud.edd.sgw.api.enums.MatchType;
import net.hwyz.iov.cloud.edd.sgw.domain.model.HeaderMatch;
import net.hwyz.iov.cloud.edd.sgw.domain.model.QueryParamMatch;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RewritePath;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.SgwConfiguration;
import org.springframework.stereotype.Component;
import org.springframework.web.util.pattern.PathPatternParser;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 配置快照编译器。
 * <p>
 * 在侧路完成路径与正则编译，成功后由 {@link SnapshotManager} 原子激活。
 *
 * @author hwyz_leo
 */
@Component
public class SnapshotCompiler {

    private final PathPatternParser pathPatternParser = new PathPatternParser();

    /**
     * 编译配置快照
     *
     * @param versionNo     版本号
     * @param checksum      校验和
     * @param configuration 配置
     * @return 已编译快照
     */
    public CompiledSnapshot compile(long versionNo, String checksum, SgwConfiguration configuration) {
        configuration.normalized();
        List<CompiledRoute> routes = new ArrayList<>();
        for (RouteDefinition route : configuration.getRoutes()) {
            if (!route.effective()) {
                continue;
            }
            routes.add(compileRoute(route));
        }
        routes.sort(Comparator
                .comparing((CompiledRoute route) -> route.getDefinition().getPriority() == null
                        ? Integer.MAX_VALUE : route.getDefinition().getPriority())
                .thenComparing(CompiledRoute::routeCode));
        return new CompiledSnapshot(versionNo, checksum, configuration, routes, Instant.now());
    }

    private CompiledRoute compileRoute(RouteDefinition route) {
        List<org.springframework.web.util.pattern.PathPattern> paths = new ArrayList<>();
        if (route.getMatch() != null) {
            for (String path : route.getMatch().getPaths()) {
                paths.add(pathPatternParser.parse(path));
            }
        }
        List<Pattern> headerPatterns = new ArrayList<>();
        if (route.getMatch() != null) {
            for (HeaderMatch header : route.getMatch().getHeaders()) {
                headerPatterns.add(header.getMatchType() == MatchType.REGEX ? Pattern.compile(header.getValue()) : null);
            }
        }
        List<Pattern> queryPatterns = new ArrayList<>();
        if (route.getMatch() != null) {
            for (QueryParamMatch queryParam : route.getMatch().getQueryParams()) {
                queryPatterns.add(queryParam.getMatchType() == MatchType.REGEX
                        ? Pattern.compile(queryParam.getValue()) : null);
            }
        }
        Pattern rewritePattern = null;
        RewritePath rewritePath = route.getTransform() == null ? null : route.getTransform().getRewritePath();
        if (rewritePath != null) {
            rewritePattern = Pattern.compile(rewritePath.getPattern());
        }
        return new CompiledRoute(route, paths, headerPatterns, queryPatterns, rewritePattern);
    }

}
