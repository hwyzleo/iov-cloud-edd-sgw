package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

import lombok.Getter;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import org.springframework.web.util.pattern.PathPattern;

import java.util.List;
import java.util.regex.Pattern;

/**
 * 已编译的路由（路径模式与正则预编译，避免请求期重复解析）。
 *
 * @author hwyz_leo
 */
@Getter
public class CompiledRoute {

    private final RouteDefinition definition;

    private final List<PathPattern> paths;

    private final List<Pattern> headerPatterns;

    private final List<Pattern> queryPatterns;

    private final Pattern rewritePattern;

    public CompiledRoute(RouteDefinition definition, List<PathPattern> paths, List<Pattern> headerPatterns,
                         List<Pattern> queryPatterns, Pattern rewritePattern) {
        this.definition = definition;
        this.paths = paths;
        this.headerPatterns = headerPatterns;
        this.queryPatterns = queryPatterns;
        this.rewritePattern = rewritePattern;
    }

    /**
     * 路由编码
     *
     * @return 编码
     */
    public String routeCode() {
        return definition.getRouteCode();
    }

}
