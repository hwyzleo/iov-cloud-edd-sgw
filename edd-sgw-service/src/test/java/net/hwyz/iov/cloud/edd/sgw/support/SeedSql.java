package net.hwyz.iov.cloud.edd.sgw.support;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 路由/策略种子迁移解析工具（测试用）。
 * <p>
 * 直接解析 {@code db/migration/V3__sgw_route_baseline.sql} 与
 * {@code db/migration/V4__sgw_app_route_coverage.sql} 文本，保证「清单与种子同源」，
 * 避免在测试中复制一份路由/策略清单而与迁移漂移（EDD-SGW-DSN-CR-003 §19.2.6 TC-003-16）。
 * <p>
 * 终审修复 B-2：V3 之后的新增路由只能落在 V4，因此「全量路由」必须由
 * {@link #allRoutes()} 提供（V3 + V4），否则门禁会漏检 App 在用前缀。
 *
 * @author hwyz_leo
 */
public final class SeedSql {

    /** V3 基线迁移 */
    public static final String ROUTE_FILE = "db/migration/V3__sgw_route_baseline.sql";

    /** V4 终审修复迁移（App 在用路径全覆盖 + 存量回填） */
    public static final String V4_ROUTE_FILE = "db/migration/V4__sgw_app_route_coverage.sql";

    private static final Pattern ROUTE_CODE = Pattern.compile("SELECT\\s+'([A-Za-z0-9_-]+)'");

    private static final Pattern PATHS = Pattern.compile("\"paths\":\\[([^\\]]*)]");

    private static final Pattern PATH_ITEM = Pattern.compile("\"([^\"]+)\"");

    private static final Pattern TARGET = Pattern.compile("'SERVICE',\\s*'([^']+)'");

    private static final Pattern AUTH_POLICY = Pattern.compile("NULL,\\s*'(sgw-[A-Za-z0-9-]+)',\\s*NULL,\\s*NULL");

    private static final Pattern POLICY_CODE = Pattern.compile("SELECT\\s+'(sgw-[A-Za-z0-9-]+)'");

    private static final Pattern ACCESS_MODE = Pattern.compile("'(ANONYMOUS|AUTHENTICATED)'");

    /** 策略行的 required_* 提取（列序：code, name, description, access_mode, clients, scopes, permissions, ...） */
    private static final Pattern POLICY_ROW = Pattern.compile(
            "SELECT\\s+'(sgw-[A-Za-z0-9-]+)',\\s*'[^']*',\\s*'[^']*',\\s*'(ANONYMOUS|AUTHENTICATED)',"
                    + "\\s*(NULL|'([^']*)'),\\s*(NULL|'([^']*)'),\\s*(NULL|'([^']*)')");

    private SeedSql() {
    }

    /**
     * 读取 V3 迁移脚本
     *
     * @return 脚本文本
     */
    public static String load() {
        return loadFile(ROUTE_FILE);
    }

    /**
     * 读取 V4 迁移脚本
     *
     * @return 脚本文本
     */
    public static String loadV4() {
        return loadFile(V4_ROUTE_FILE);
    }

    /**
     * 读取指定迁移脚本
     *
     * @param resource classpath 资源路径
     * @return 脚本文本
     */
    public static String loadFile(String resource) {
        try (InputStream stream = SeedSql.class.getClassLoader().getResourceAsStream(resource)) {
            if (stream == null) {
                throw new IllegalStateException("未找到迁移脚本: " + resource);
            }
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("读取迁移脚本失败: " + resource, e);
        }
    }

    /**
     * V3 种子路由
     *
     * @return 路由清单（按脚本顺序）
     */
    public static List<SeedRoute> routes() {
        return routes(load());
    }

    /**
     * V4 新增路由
     *
     * @return 路由清单（按脚本顺序）
     */
    public static List<SeedRoute> routesV4() {
        return routes(loadV4());
    }

    /**
     * 全量路由（V3 基线 + V4 终审修复）
     *
     * @return 路由清单（V3 在前）
     */
    public static List<SeedRoute> allRoutes() {
        List<SeedRoute> all = new ArrayList<>(routes());
        all.addAll(routesV4());
        return all;
    }

    /**
     * 解析指定脚本文本中的路由 INSERT
     *
     * @param sql 脚本文本
     * @return 路由清单
     */
    public static List<SeedRoute> routes(String sql) {
        List<SeedRoute> routes = new ArrayList<>();
        String[] chunks = sql.split("INSERT INTO sgw_route \\(");
        for (int index = 1; index < chunks.length; index++) {
            String chunk = chunks[index];
            Matcher code = ROUTE_CODE.matcher(chunk);
            if (!code.find()) {
                continue;
            }
            Matcher paths = PATHS.matcher(chunk);
            List<String> pathList = new ArrayList<>();
            if (paths.find()) {
                Matcher item = PATH_ITEM.matcher(paths.group(1));
                while (item.find()) {
                    pathList.add(item.group(1));
                }
            }
            if (pathList.isEmpty()) {
                continue;
            }
            Matcher target = TARGET.matcher(chunk);
            Matcher policy = AUTH_POLICY.matcher(chunk);
            routes.add(new SeedRoute(code.group(1), pathList,
                    target.find() ? target.group(1) : null,
                    policy.find() ? policy.group(1) : null));
        }
        return routes;
    }

    /**
     * V3 种子认证策略
     *
     * @return 策略清单（按脚本顺序）
     */
    public static List<SeedPolicy> policies() {
        return policies(load());
    }

    /**
     * V4 新增认证策略
     *
     * @return 策略清单
     */
    public static List<SeedPolicy> policiesV4() {
        return policies(loadV4());
    }

    /**
     * 全量认证策略（V3 + V4）
     *
     * @return 策略清单（V3 在前）
     */
    public static List<SeedPolicy> allPolicies() {
        List<SeedPolicy> all = new ArrayList<>(policies());
        all.addAll(policiesV4());
        return all;
    }

    /**
     * 解析指定脚本文本中的策略 INSERT
     *
     * @param sql 脚本文本
     * @return 策略清单
     */
    public static List<SeedPolicy> policies(String sql) {
        List<SeedPolicy> policies = new ArrayList<>();
        String[] chunks = sql.split("INSERT INTO sgw_auth_policy \\(");
        for (int index = 1; index < chunks.length; index++) {
            String chunk = chunks[index];
            Matcher row = POLICY_ROW.matcher(chunk);
            if (row.find()) {
                policies.add(new SeedPolicy(row.group(1), row.group(2), row.group(4),
                        row.group(6), row.group(8)));
                continue;
            }
            Matcher code = POLICY_CODE.matcher(chunk);
            if (!code.find()) {
                continue;
            }
            Matcher mode = ACCESS_MODE.matcher(chunk);
            policies.add(new SeedPolicy(code.group(1), mode.find() ? mode.group(1) : null, null, null, null));
        }
        return policies;
    }

    /**
     * 种子路由条目
     *
     * @param routeCode      路由编码
     * @param paths          匹配路径
     * @param targetService  目标服务 ID
     * @param authPolicyCode 认证授权策略编码
     */
    public record SeedRoute(String routeCode, List<String> paths, String targetService, String authPolicyCode) {
    }

    /**
     * 种子策略条目
     *
     * @param policyCode         策略编码
     * @param accessMode         访问模式
     * @param allowedClientTypes 允许的客户端类型（NULL 表示不限）
     * @param requiredScopes     必需 scope（NULL 表示不校验）
     * @param requiredPermissions 必需权限点（NULL 表示不校验）
     */
    public record SeedPolicy(String policyCode, String accessMode, String allowedClientTypes,
                             String requiredScopes, String requiredPermissions) {
    }

}
