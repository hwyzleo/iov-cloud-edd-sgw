package net.hwyz.iov.cloud.edd.sgw.it;

import net.hwyz.iov.cloud.edd.sgw.support.SeedSql;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * V3 + V4 真实库迁移集成测试（EDD-SGW-DSN-CR-003 终审修复 B-2 / B-3）。
 * <p>
 * 在本地 MySQL 上真实执行 {@code V1}–{@code V4} Flyway 迁移并断言：
 * <ul>
 *     <li>V3 基线 6 策略 / 13 路由 + V4 补登 1 策略 / 7 路由全部落库；</li>
 *     <li>V4 可幂等重跑（重复执行脚本不再产生任何新行）；</li>
 *     <li>车控路由在库中为 AUTHENTICATED + MOBILE + scope/权限点，显式断言不是 ANONYMOUS；</li>
 *     <li>存量空策略路由按路径前缀被回填，运营已显式配置的行不被覆盖。</li>
 * </ul>
 * 使用独立库 {@code db_sgw_v4_it}，与 {@code SgwFoundationIT}（{@code db_sgw_it}）隔离；
 * MySQL 不可用时由 {@link InfrastructureCondition} 跳过（与既有 IT 模式一致）。
 *
 * @author hwyz_leo
 */
@ExtendWith(InfrastructureCondition.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SgwRouteMigrationIT {

    private static final String DATABASE = "db_sgw_v4_it";

    private static final String USERNAME = "root";

    private static final String PASSWORD = "9jpHx:G9NBM@Wst";

    private static final List<String> VEHICLE_CONTROL_ROUTES = List.of(
            "mobile-vehicle-unlock", "mobile-vehicle-lock", "mobile-vehicle-window",
            "mobile-vehicle-trunk", "mobile-rvc-v1");

    @BeforeAll
    void migrateFreshDatabase() throws SQLException {
        try (Connection connection = DriverManager.getConnection(serverUrl(), USERNAME, PASSWORD);
             Statement statement = connection.createStatement()) {
            statement.execute("DROP DATABASE IF EXISTS " + DATABASE);
            statement.execute("CREATE DATABASE " + DATABASE
                    + " DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci");
        }
        Flyway flyway = Flyway.configure()
                .dataSource(url(), USERNAME, PASSWORD)
                .locations("classpath:db/migration")
                .baselineOnMigrate(true)
                .baselineVersion("1")
                .validateOnMigrate(true)
                .load();
        assertThat(flyway.migrate().migrationsExecuted).as("V1..V4 应全部执行").isEqualTo(4);
    }

    @Test
    @Order(1)
    @DisplayName("B-2：V3 基线 + V4 补登的路由与策略全部落库")
    void seedsApplied() throws SQLException {
        assertThat(count("SELECT COUNT(*) FROM sgw_auth_policy")).as("V3 6 + V4 1 策略").isEqualTo(7);
        assertThat(count("SELECT COUNT(*) FROM sgw_route")).as("V3 13 + V4 7 路由").isEqualTo(20);
        assertThat(count("SELECT COUNT(*) FROM sgw_route WHERE auth_policy_code IS NULL OR TRIM(auth_policy_code) = ''"))
                .as("种子路由不得存在空策略").isZero();
        assertThat(count("SELECT COUNT(*) FROM sgw_auth_policy WHERE access_mode = 'ANONYMOUS'"))
                .as("匿名策略仅限认证入口与开放平台").isEqualTo(3);
        assertThat(count("SELECT COUNT(*) FROM sgw_route r JOIN sgw_auth_policy p ON p.policy_code = r.auth_policy_code "
                + "WHERE p.access_mode = 'ANONYMOUS' AND r.route_code LIKE 'mobile-vehicle-%'"))
                .as("车控路由不得命中匿名策略").isZero();
        for (String routeCode : VEHICLE_CONTROL_ROUTES) {
            assertThat(count("SELECT COUNT(*) FROM sgw_route WHERE route_code = '" + routeCode + "'"))
                    .as("车控路由 %s 必须存在", routeCode).isEqualTo(1);
        }
    }

    @Test
    @Order(2)
    @DisplayName("B-2：车控路由在库中为 AUTHENTICATED + MOBILE + scope/权限点（显式非 ANONYMOUS）")
    void vehicleControlRoutesAreAuthenticated() throws SQLException {
        for (String routeCode : VEHICLE_CONTROL_ROUTES) {
            Map<String, String> row = queryOne("SELECT p.access_mode, p.allowed_client_types, p.required_scopes, "
                    + "p.required_permissions FROM sgw_route r JOIN sgw_auth_policy p ON p.policy_code = r.auth_policy_code "
                    + "WHERE r.route_code = '" + routeCode + "'");
            assertThat(row).as("车控路由 %s 必须引用存在的策略", routeCode).isNotEmpty();
            assertThat(row.get("access_mode")).as("车控路由 %s 必须已认证", routeCode).isEqualTo("AUTHENTICATED");
            assertThat(row.get("access_mode")).as("车控路由 %s 严禁 ANONYMOUS", routeCode).isNotEqualTo("ANONYMOUS");
            assertThat(row.get("allowed_client_types")).as("车控路由 %s 必须允许 MOBILE", routeCode).contains("MOBILE");
            assertThat(row.get("required_scopes")).as("车控路由 %s 必须登记 scope", routeCode).isNotBlank();
            assertThat(row.get("required_permissions")).as("车控路由 %s 必须登记权限点", routeCode).isNotBlank();
        }
    }

    @Test
    @Order(3)
    @DisplayName("B-3：存量空策略路由按路径前缀回填，运营显式配置不被覆盖")
    void backfillOnlyFillsEmptyPolicies() throws SQLException {
        execute("INSERT INTO sgw_route (route_code, route_name, priority, enabled, match_json, target_type, "
                + "target_value, client_types, auth_policy_code, row_version, row_valid, create_by) VALUES "
                + "('legacy-unlock', '历史车控', 500, 1, '{\"paths\":[\"/unlockVehicle\"]}', 'SERVICE', "
                + "'rvc-service', NULL, NULL, 1, 1, 'operator')");
        execute("INSERT INTO sgw_route (route_code, route_name, priority, enabled, match_json, target_type, "
                + "target_value, client_types, auth_policy_code, row_version, row_valid, create_by) VALUES "
                + "('legacy-account', '历史账号', 501, 1, '{\"paths\":[\"/mp/account/info\"]}', 'SERVICE', "
                + "'tsp-account', 'MOBILE', '', 1, 1, 'operator')");
        execute("INSERT INTO sgw_route (route_code, route_name, priority, enabled, match_json, target_type, "
                + "target_value, client_types, auth_policy_code, row_version, row_valid, create_by) VALUES "
                + "('legacy-configured', '运营已配置', 502, 1, '{\"paths\":[\"/mp/rvc/cmd\"]}', 'SERVICE', "
                + "'rvc-service', NULL, 'sgw-anon-open-api', 1, 1, 'operator')");

        rerunV4();

        assertThat(text("SELECT auth_policy_code FROM sgw_route WHERE route_code = 'legacy-unlock'"))
                .as("历史车控路由必须回填到车控策略").isEqualTo("sgw-mobile-vehicle-control");
        assertThat(text("SELECT auth_policy_code FROM sgw_route WHERE route_code = 'legacy-account'"))
                .as("空串策略也必须视为未配置并回填").isEqualTo("sgw-mobile-user");
        assertThat(text("SELECT auth_policy_code FROM sgw_route WHERE route_code = 'legacy-configured'"))
                .as("运营已显式配置的行绝不能被覆盖").isEqualTo("sgw-anon-open-api");
        assertThat(text("SELECT client_types FROM sgw_route WHERE route_code = 'legacy-account'"))
                .as("运营已显式配置的 client_types 必须保留").isEqualTo("MOBILE");
        assertThat(text("SELECT modify_by FROM sgw_route WHERE route_code = 'legacy-unlock'"))
                .as("回填必须留痕，便于精确回滚").isEqualTo("flyway-v4-backfill");
        assertThat(count("SELECT COUNT(*) FROM sgw_route WHERE auth_policy_code IS NULL OR TRIM(auth_policy_code) = ''"))
                .as("回填后不得存在空策略路由").isZero();
    }

    @Test
    @Order(4)
    @DisplayName("B-3：V4 可幂等重跑（重复执行不产生新行、不改变回填结果）")
    void v4IsIdempotentOnRerun() throws SQLException {
        long policies = count("SELECT COUNT(*) FROM sgw_auth_policy");
        long routes = count("SELECT COUNT(*) FROM sgw_route");
        String fingerprint = fingerprint();

        rerunV4();

        assertThat(count("SELECT COUNT(*) FROM sgw_auth_policy")).isEqualTo(policies);
        assertThat(count("SELECT COUNT(*) FROM sgw_route")).isEqualTo(routes);
        assertThat(fingerprint()).as("回填结果必须稳定（重跑影响 0 行）").isEqualTo(fingerprint);
        assertThat(count("SELECT COUNT(*) FROM (SELECT policy_code FROM sgw_auth_policy "
                + "GROUP BY policy_code HAVING COUNT(*) > 1) t")).as("策略编码唯一").isZero();
        assertThat(count("SELECT COUNT(*) FROM (SELECT route_code FROM sgw_route "
                + "GROUP BY route_code HAVING COUNT(*) > 1) t")).as("路由编码唯一").isZero();
    }

    private void rerunV4() throws SQLException {
        // allowMultiQueries=true：整脚本一次性重放，模拟运维手工重跑迁移
        try (Connection connection = DriverManager.getConnection(url(), USERNAME, PASSWORD);
             Statement statement = connection.createStatement()) {
            statement.execute(SeedSql.loadV4());
        }
    }

    private String fingerprint() throws SQLException {
        List<String> rows = new ArrayList<>();
        try (Connection connection = DriverManager.getConnection(url(), USERNAME, PASSWORD);
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(
                     "SELECT route_code, auth_policy_code, client_types FROM sgw_route ORDER BY route_code")) {
            while (resultSet.next()) {
                rows.add(resultSet.getString(1) + "|" + resultSet.getString(2) + "|" + resultSet.getString(3));
            }
        }
        return String.join("\n", rows);
    }

    private void execute(String sql) throws SQLException {
        try (Connection connection = DriverManager.getConnection(url(), USERNAME, PASSWORD);
             Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    private long count(String sql) throws SQLException {
        try (Connection connection = DriverManager.getConnection(url(), USERNAME, PASSWORD);
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            assertThat(resultSet.next()).isTrue();
            return resultSet.getLong(1);
        }
    }

    private String text(String sql) throws SQLException {
        try (Connection connection = DriverManager.getConnection(url(), USERNAME, PASSWORD);
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            return resultSet.next() ? resultSet.getString(1) : null;
        }
    }

    private Map<String, String> queryOne(String sql) throws SQLException {
        Map<String, String> row = new LinkedHashMap<>();
        try (Connection connection = DriverManager.getConnection(url(), USERNAME, PASSWORD);
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            if (!resultSet.next()) {
                return row;
            }
            for (int index = 1; index <= resultSet.getMetaData().getColumnCount(); index++) {
                row.put(resultSet.getMetaData().getColumnLabel(index), resultSet.getString(index));
            }
        }
        return row;
    }

    private String serverUrl() {
        return "jdbc:mysql://" + InfrastructureCondition.MYSQL_HOST + ":" + InfrastructureCondition.MYSQL_PORT
                + "/?allowPublicKeyRetrieval=true&useSSL=false&connectionTimeZone=UTC"
                + "&forceConnectionTimeZoneToSession=true";
    }

    private String url() {
        return "jdbc:mysql://" + InfrastructureCondition.MYSQL_HOST + ":" + InfrastructureCondition.MYSQL_PORT
                + "/" + DATABASE + "?useUnicode=true&characterEncoding=utf8&allowMultiQueries=true"
                + "&allowPublicKeyRetrieval=true&useSSL=false&connectionTimeZone=UTC"
                + "&forceConnectionTimeZoneToSession=true&preserveInstants=true";
    }

}
