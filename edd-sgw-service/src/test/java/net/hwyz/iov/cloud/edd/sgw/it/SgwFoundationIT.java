package net.hwyz.iov.cloud.edd.sgw.it;

import com.fasterxml.jackson.databind.JsonNode;
import io.jsonwebtoken.Jwts;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.SnapshotManager;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.security.InternalHmacVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 服务网关基础设计集成测试（EDD-SGW-DSN-CR-001）。
 * <p>
 * 使用本机 MySQL(db_sgw_it) + Redis + 本地模拟上游与 JWKS。
 *
 * @author hwyz_leo
 */
@ExtendWith(InfrastructureCondition.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ActiveProfiles("it")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SgwFoundationIT {

    private static final String ISSUER = "https://issuer.it";

    private static final String SECRET = "it-secret";

    private static final String ADMIN_PREFIX = "/api/service/sgw/v1";

    private static final AtomicInteger COUNTER = new AtomicInteger();

    private static DisposableServer upstream;

    private static DisposableServer jwks;

    private static int upstreamPort;

    private static int jwksPort;

    private static KeyPair keyPair;

    @Autowired
    private WebTestClient client;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private SnapshotManager snapshotManager;

    @DynamicPropertySource
    static void prepare(DynamicPropertyRegistry registry) {
        try {
            createDatabase();
            startUpstream();
            startJwks();
            registry.add("sgw.runtime.direct-upstream-hosts",
                    () -> "127.0.0.1:" + upstreamPort + ",localhost:" + upstreamPort);
            registry.add("sgw.security.ciam.jwks-uri", () -> "http://127.0.0.1:" + jwksPort + "/jwks");
            registry.add("sgw.security.internal.clients.mpt", () -> SECRET);
            registry.add("spring.datasource.url", () -> "jdbc:mysql://" + InfrastructureCondition.MYSQL_HOST
                    + ":" + InfrastructureCondition.MYSQL_PORT + "/db_sgw_it"
                    + "?useUnicode=true&characterEncoding=utf8&allowMultiQueries=true"
                    + "&allowPublicKeyRetrieval=true&useSSL=false&connectionTimeZone=UTC"
                    + "&forceConnectionTimeZoneToSession=true&preserveInstants=true");
            registry.add("spring.datasource.username", () -> "root");
            registry.add("spring.datasource.password", () -> "9jpHx:G9NBM@Wst");
            registry.add("spring.data.redis.host", () -> InfrastructureCondition.REDIS_HOST);
            registry.add("spring.data.redis.port", () -> InfrastructureCondition.REDIS_PORT);
            registry.add("spring.cloud.nacos.config.enabled", () -> "false");
            registry.add("spring.cloud.nacos.discovery.enabled", () -> "false");
            registry.add("spring.cloud.service-registry.auto-registration.enabled", () -> "false");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @BeforeEach
    void resetState() {
        for (String table : List.of("sgw_config_change_log", "sgw_instance_publication", "sgw_publication",
                "sgw_config_version", "sgw_route", "sgw_auth_policy", "sgw_traffic_policy",
                "sgw_canary_policy", "sgw_instance_state")) {
            jdbcTemplate.execute("DELETE FROM " + table);
        }
        jdbcTemplate.execute("UPDATE sgw_config_workspace SET draft_revision = 0, target_version_no = NULL, "
                + "row_version = 1 WHERE id = 1");
    }

    @Test
    @Order(1)
    @DisplayName("未加载有效快照时就绪探针为未就绪")
    void readinessRequiresSnapshot() {
        EntityExchangeResult<String> result = client.get().uri("/actuator/health/readiness")
                .exchange().expectBody(String.class).returnResult();
        assertThat(result.getStatus().value()).isEqualTo(503);
        assertThat(result.getResponseBody()).contains("DOWN");
    }

    @Test
    @Order(2)
    @DisplayName("管理接口强制校验内部签名")
    void adminRequiresSignature() {
        client.get().uri(ADMIN_PREFIX + "/routes").exchange().expectStatus().isUnauthorized();
    }

    @Test
    @Order(3)
    @DisplayName("发布后受保护路由按验证声明转发并清洗身份头")
    void publishAndForwardWithIdentity() {
        String authCode = createAuthPolicy("user-policy", List.of("vehicle.read"), List.of("edd:vehicle:read"));
        String routeCode = "protected-echo-" + COUNTER.incrementAndGet();
        createRoute(Map.of(
                "routeCode", routeCode,
                "routeName", "受保护回显",
                "priority", 100,
                "enabled", true,
                "match", Map.of("paths", List.of("/echo"), "methods", List.of("GET"),
                        "clientTypes", List.of("MOBILE")),
                "target", Map.of("type", "HTTP", "uri", "http://127.0.0.1:" + upstreamPort + "/echo"),
                "authPolicyCode", authCode));
        JsonNode publication = publishAndWait();
        assertThat(publication.get("status").asText()).isEqualTo("SUCCEEDED");
        assertThat(publication.get("instances")).isNotEmpty();

        EntityExchangeResult<String> response = client.get().uri("/echo")
                .header("Authorization", "Bearer " + token("MOBILE", "VIN1",
                        "vehicle.read perm:edd:vehicle:read"))
                .header("X-Client-Type", "MOBILE")
                .header("X-User-Id", "forged-user")
                .header("X-Vin", "FORGED-VIN")
                .header("X-Scope", "forged.scope")
                .exchange().expectBody(String.class).returnResult();
        assertThat(response.getStatus().value()).as(response.getResponseBody()).isEqualTo(200);
        assertThat(response.getResponseBody()).isEqualTo("ok");
        assertThat(response.getResponseHeaders().getFirst("X-Echo-User")).isEqualTo("user-1");
        assertThat(response.getResponseHeaders().getFirst("X-Echo-Vin")).isEqualTo("VIN1");
        assertThat(response.getResponseHeaders().getFirst("X-Echo-Scope")).doesNotContain("forged");
        assertThat(response.getResponseHeaders().getFirst("X-Request-Id")).isNotBlank();
    }

    @Test
    @Order(4)
    @DisplayName("匿名路由不传播任何认证身份")
    void anonymousRouteStripsIdentity() {
        String routeCode = "anonymous-echo-" + COUNTER.incrementAndGet();
        createRoute(Map.of(
                "routeCode", routeCode,
                "routeName", "匿名回显",
                "priority", 100,
                "enabled", true,
                "match", Map.of("paths", List.of("/echo-anon"), "methods", List.of("GET")),
                "target", Map.of("type", "HTTP", "uri", "http://127.0.0.1:" + upstreamPort + "/echo-anon")));
        publishAndWait();

        EntityExchangeResult<String> response = client.get().uri("/echo-anon")
                .header("X-User-Id", "forged-user")
                .header("X-Vin", "FORGED-VIN")
                .exchange().expectBody(String.class).returnResult();
        assertThat(response.getStatus().value()).isEqualTo(200);
        assertThat(response.getResponseHeaders().getFirst("X-Echo-User")).isEqualTo("none");
        assertThat(response.getResponseHeaders().getFirst("X-Echo-Vin")).isEqualTo("none");
    }

    @Test
    @Order(5)
    @DisplayName("未匹配路由返回 404，缺失令牌返回 401，权限不足返回 403")
    void errorContract() {
        String authCode = createAuthPolicy("strict-policy", List.of("admin.write"), List.of("edd:admin:write"));
        String routeCode = "strict-echo-" + COUNTER.incrementAndGet();
        createRoute(Map.of(
                "routeCode", routeCode,
                "routeName", "严格路由",
                "priority", 100,
                "enabled", true,
                "match", Map.of("paths", List.of("/echo-strict"), "methods", List.of("GET")),
                "target", Map.of("type", "HTTP", "uri", "http://127.0.0.1:" + upstreamPort + "/echo"),
                "authPolicyCode", authCode));
        publishAndWait();

        assertError(client.get().uri("/no-such-route").exchange(), 404, "SGW-404001");
        assertError(client.get().uri("/echo-strict").exchange(), 401, "SGW-401001");
        assertError(client.get().uri("/echo-strict")
                .header("Authorization", "Bearer " + token("MOBILE", "VIN1", "vehicle.read"))
                .exchange(), 403, "SGW-403001");
        assertError(client.get().uri("/echo-strict")
                .header("Authorization", "Bearer " + token("MOBILE", "VIN1", "admin.write perm:edd:admin:write"))
                .header("X-Client-Type", "IDCM")
                .exchange(), 401, "SGW-401001");
    }

    @Test
    @Order(6)
    @DisplayName("集群限流超限返回 429")
    void rateLimited() {
        String authCode = createAuthPolicy("rate-policy", List.of(), List.of());
        String trafficCode = createTrafficPolicy("burst-" + COUNTER.incrementAndGet(), 300, 3000,
                List.of(Map.of("dimension", "ROUTE", "replenishPerSecond", 1,
                        "burstCapacity", 1, "failureMode", "FAIL_CLOSED")), null);
        String routeCode = "rate-echo-" + COUNTER.incrementAndGet();
        createRoute(Map.of(
                "routeCode", routeCode,
                "routeName", "限流路由",
                "priority", 100,
                "enabled", true,
                "match", Map.of("paths", List.of("/echo-rate"), "methods", List.of("GET")),
                "target", Map.of("type", "HTTP", "uri", "http://127.0.0.1:" + upstreamPort + "/echo"),
                "authPolicyCode", authCode,
                "trafficPolicyCode", trafficCode));
        publishAndWait();

        String token = token("MOBILE", "VIN1", "");
        assertThat(client.get().uri("/echo-rate").header("Authorization", "Bearer " + token)
                .exchange().expectBody(String.class).returnResult().getStatus().value()).isEqualTo(200);
        assertError(client.get().uri("/echo-rate").header("Authorization", "Bearer " + token).exchange(),
                429, "SGW-429001");
    }

    @Test
    @Order(7)
    @DisplayName("上游响应超时返回 504")
    void upstreamTimeout() {
        String trafficCode = createTrafficPolicy("timeout-" + COUNTER.incrementAndGet(), 300, 300, List.of(), null);
        String routeCode = "slow-echo-" + COUNTER.incrementAndGet();
        createRoute(Map.of(
                "routeCode", routeCode,
                "routeName", "慢路由",
                "priority", 100,
                "enabled", true,
                "match", Map.of("paths", List.of("/slow"), "methods", List.of("GET")),
                "target", Map.of("type", "HTTP", "uri", "http://127.0.0.1:" + upstreamPort + "/slow"),
                "trafficPolicyCode", trafficCode));
        publishAndWait();
        assertError(client.get().uri("/slow").exchange(), 504, "SGW-504001");
    }

    @Test
    @Order(8)
    @DisplayName("灰度策略将稳定键确定性分配到加权目标")
    void canaryRouting() {
        String canaryCode = "canary-" + COUNTER.incrementAndGet();
        adminJson(HttpMethod.POST, ADMIN_PREFIX + "/policies/canary", Map.of(
                "policyCode", canaryCode,
                "policyName", "灰度",
                "stableKey", "SOURCE_IP",
                "enabled", true,
                "rules", List.of(Map.of(
                        "priority", 10,
                        "conditions", Map.of("clientTypes", List.of("MOBILE")),
                        "targets", List.of(
                                Map.of("type", "HTTP", "uri", "http://127.0.0.1:" + upstreamPort + "/v2", "weight", 100))))));
        String authCode = createAuthPolicy("canary-policy", List.of(), List.of());
        String routeCode = "canary-echo-" + COUNTER.incrementAndGet();
        createRoute(Map.of(
                "routeCode", routeCode,
                "routeName", "灰度路由",
                "priority", 100,
                "enabled", true,
                "match", Map.of("paths", List.of("/canary"), "methods", List.of("GET"),
                        "clientTypes", List.of("MOBILE")),
                "target", Map.of("type", "HTTP", "uri", "http://127.0.0.1:" + upstreamPort + "/v1"),
                "authPolicyCode", authCode,
                "canaryPolicyCode", canaryCode));
        publishAndWait();
        String token = token("MOBILE", "VIN1", "");
        for (int i = 0; i < 3; i++) {
            EntityExchangeResult<String> response = client.get().uri("/canary")
                    .header("Authorization", "Bearer " + token)
                    .header("X-Client-Type", "MOBILE")
                    .exchange().expectBody(String.class).returnResult();
            assertThat(response.getStatus().value()).isEqualTo(200);
            assertThat(response.getResponseBody()).isEqualTo("v2");
        }
    }

    @Test
    @Order(9)
    @DisplayName("草稿不影响线上，发布切换版本，回滚恢复历史行为并可对比版本差异")
    void draftPublishRollbackAndDiff() {
        String routeCode = "rollback-echo";
        createRoute(Map.of(
                "routeCode", routeCode,
                "routeName", "回滚路由",
                "priority", 100,
                "enabled", true,
                "match", Map.of("paths", List.of("/echo"), "methods", List.of("GET")),
                "target", Map.of("type", "HTTP", "uri", "http://127.0.0.1:" + upstreamPort + "/echo")));
        publishAndWait();
        assertThat(client.get().uri("/echo").exchange().expectBody(String.class)
                .returnResult().getStatus().value()).isEqualTo(200);

        JsonNode route = getRoute(routeCode);
        updateRoute(routeCode, Map.of(
                "routeCode", routeCode,
                "routeName", "回滚路由",
                "priority", 100,
                "enabled", true,
                "match", Map.of("paths", List.of("/echo-anon"), "methods", List.of("GET")),
                "target", Map.of("type", "HTTP", "uri", "http://127.0.0.1:" + upstreamPort + "/echo-anon"),
                "rowVersion", route.get("rowVersion").asInt()));
        assertThat(client.get().uri("/echo").exchange().expectBody(String.class)
                .returnResult().getStatus().value()).isEqualTo(200);
        assertError(client.get().uri("/echo-anon").exchange(), 404, "SGW-404001");

        JsonNode second = publishAndWait();
        long secondVersion = second.get("targetVersionNo").asLong();
        assertThat(client.get().uri("/echo").exchange().expectBody(String.class)
                .returnResult().getStatus().value()).isEqualTo(404);
        assertThat(client.get().uri("/echo-anon").exchange().expectBody(String.class)
                .returnResult().getStatus().value()).isEqualTo(200);

        JsonNode diff = adminJson(HttpMethod.GET,
                ADMIN_PREFIX + "/config-versions/diff?from=1&to=" + secondVersion, null);
        assertThat(diff.get("items").toString()).contains("MODIFIED");

        long draftRevision = workspace().get("draftRevision").asLong();
        JsonNode rollback = adminJson(HttpMethod.POST,
                ADMIN_PREFIX + "/config-versions/1/rollback", Map.of("draftRevision", draftRevision));
        rollback = waitPublication(rollback.get("publicationId").asText());
        assertThat(rollback.get("type").asText()).isEqualTo("ROLLBACK");
        assertThat(rollback.get("status").asText()).isEqualTo("SUCCEEDED");
        assertThat(client.get().uri("/echo").exchange().expectBody(String.class)
                .returnResult().getStatus().value()).isEqualTo(200);
        assertThat(client.get().uri("/echo-anon").exchange().expectBody(String.class)
                .returnResult().getStatus().value()).isEqualTo(404);

        JsonNode detail = adminJson(HttpMethod.GET, ADMIN_PREFIX + "/config-versions/1", null);
        assertThat(detail.get("checksum").asText()).isNotBlank();
        assertThat(detail.get("snapshot").get("routes")).isNotEmpty();
    }

    @Test
    @Order(9)
    @DisplayName("上游 5xx 达到熔断条件后返回 503")
    void circuitBreakerOpens() {
        String trafficCode = "cb-" + COUNTER.incrementAndGet();
        adminJson(HttpMethod.POST, ADMIN_PREFIX + "/policies/traffic", Map.of(
                "policyCode", trafficCode,
                "policyName", "熔断",
                "connectTimeoutMillis", 300,
                "responseTimeoutMillis", 3000,
                "circuitBreaker", Map.of(
                        "slidingWindowSize", 2,
                        "minimumNumberOfCalls", 2,
                        "failureRateThreshold", 50,
                        "slowCallRateThreshold", 100,
                        "slowCallDurationMillis", 1000,
                        "waitDurationInOpenStateMillis", 10000,
                        "permittedCallsInHalfOpenState", 1),
                "enabled", true));
        createRoute(Map.of(
                "routeCode", "cb-route-" + COUNTER.incrementAndGet(),
                "routeName", "熔断路由",
                "priority", 100,
                "enabled", true,
                "match", Map.of("paths", List.of("/fail"), "methods", List.of("GET")),
                "target", Map.of("type", "HTTP", "uri", "http://127.0.0.1:" + upstreamPort + "/fail"),
                "trafficPolicyCode", trafficCode));
        publishAndWait();
        for (int i = 0; i < 2; i++) {
            assertThat(client.get().uri("/fail").exchange().expectBody(String.class)
                    .returnResult().getStatus().value()).isEqualTo(500);
        }
        assertError(client.get().uri("/fail").exchange(), 503, "SGW-503002");
    }

    @Test
    @Order(10)
    @DisplayName("非失败发布不允许重试")
    void retryRejectsSucceededPublication() {
        createRoute(Map.of(
                "routeCode", "retry-route",
                "routeName", "重试路由",
                "priority", 100,
                "enabled", true,
                "match", Map.of("paths", List.of("/echo"), "methods", List.of("GET")),
                "target", Map.of("type", "HTTP", "uri", "http://127.0.0.1:" + upstreamPort + "/echo")));
        JsonNode publication = publishAndWait();
        assertError(signed(HttpMethod.POST, ADMIN_PREFIX + "/publications",
                Map.of("publicationId", publication.get("publicationId").asText())),
                409, "SGW-409001");
    }

    @Test
    @Order(11)
    @DisplayName("管理请求 nonce 不可重放")
    void replayRejected() {
        String timestamp = String.valueOf(System.currentTimeMillis());
        String nonce = UUID.randomUUID().toString();
        String signature = sign("GET", ADMIN_PREFIX + "/workspace", "", timestamp, nonce);
        WebTestClient.ResponseSpec first = client.get().uri(ADMIN_PREFIX + "/workspace")
                .header("X-Internal-Client", "mpt")
                .header("X-Internal-Timestamp", timestamp)
                .header("X-Internal-Nonce", nonce)
                .header("X-Internal-Signature", signature)
                .exchange();
        first.expectStatus().isOk();
        assertError(client.get().uri(ADMIN_PREFIX + "/workspace")
                .header("X-Internal-Client", "mpt")
                .header("X-Internal-Timestamp", timestamp)
                .header("X-Internal-Nonce", nonce)
                .header("X-Internal-Signature", signature)
                .exchange(), 401, "SGW-401001");
    }

    @Test
    @Order(12)
    @DisplayName("导出结构化配置且不包含任何密钥")
    void exportExcludesSecrets() {
        createRoute(Map.of(
                "routeCode", "export-route",
                "routeName", "导出路由",
                "priority", 100,
                "enabled", true,
                "match", Map.of("paths", List.of("/echo"), "methods", List.of("GET")),
                "target", Map.of("type", "HTTP", "uri", "http://127.0.0.1:" + upstreamPort + "/echo")));
        JsonNode export = adminJson(HttpMethod.GET, ADMIN_PREFIX + "/exports/config", null);
        String content = export.get("content").asText();
        assertThat(content).contains("export-route");
        assertThat(content).doesNotContain(SECRET);
        assertThat(content.toLowerCase()).doesNotContain("password");
    }

    private String createAuthPolicy(String code, List<String> scopes, List<String> permissions) {
        adminJson(HttpMethod.POST, ADMIN_PREFIX + "/policies/auth", Map.of(
                "policyCode", code,
                "policyName", "策略-" + code,
                "accessMode", "AUTHENTICATED",
                "allowedClientTypes", List.of("MOBILE", "IDCM"),
                "requiredScopes", scopes,
                "requiredPermissions", permissions,
                "enabled", true));
        return code;
    }

    private String createTrafficPolicy(String code, int connectTimeout, int responseTimeout,
                                       List<Map<String, Object>> rateLimits, Map<String, Object> retry) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("policyCode", code);
        body.put("policyName", "流量-" + code);
        body.put("connectTimeoutMillis", connectTimeout);
        body.put("responseTimeoutMillis", responseTimeout);
        body.put("rateLimits", rateLimits);
        body.put("enabled", true);
        if (retry != null) {
            body.put("retry", retry);
        }
        adminJson(HttpMethod.POST, ADMIN_PREFIX + "/policies/traffic", body);
        return code;
    }

    private void createRoute(Map<String, Object> body) {
        adminJson(HttpMethod.POST, ADMIN_PREFIX + "/routes", body);
    }

    private void updateRoute(String routeCode, Map<String, Object> body) {
        adminJson(HttpMethod.PUT, ADMIN_PREFIX + "/routes/" + routeCode, body);
    }

    private JsonNode getRoute(String routeCode) {
        return adminJson(HttpMethod.GET, ADMIN_PREFIX + "/routes/" + routeCode, null);
    }

    private JsonNode workspace() {
        return adminJson(HttpMethod.GET, ADMIN_PREFIX + "/workspace", null);
    }

    private JsonNode publishAndWait() {
        long draftRevision = workspace().get("draftRevision").asLong();
        JsonNode publication = adminJson(HttpMethod.POST, ADMIN_PREFIX + "/config-versions",
                Map.of("draftRevision", draftRevision));
        String publicationId = publication.get("publicationId").asText();
        long targetVersion = publication.get("targetVersionNo").asLong();
        JsonNode latest = publication;
        for (int i = 0; i < 50; i++) {
            latest = adminJson(HttpMethod.GET, ADMIN_PREFIX + "/publications/" + publicationId, null);
            if (latest.get("status").asText().equals("SUCCEEDED")
                    && Long.valueOf(targetVersion).equals(snapshotManager.activeVersionNo())) {
                break;
            }
            sleep(100);
        }
        assertThat(latest.get("status").asText()).as(latest.toString()).isEqualTo("SUCCEEDED");
        return latest;
    }

    private JsonNode waitPublication(String publicationId) {
        JsonNode latest = null;
        for (int i = 0; i < 50; i++) {
            latest = adminJson(HttpMethod.GET, ADMIN_PREFIX + "/publications/" + publicationId, null);
            if (latest.get("status").asText().equals("SUCCEEDED")) {
                break;
            }
            sleep(100);
        }
        return latest;
    }

    private void assertError(WebTestClient.ResponseSpec response, int status, String code) {
        EntityExchangeResult<String> result = response.expectBody(String.class).returnResult();
        assertThat(result.getStatus().value()).as(result.getResponseBody()).isEqualTo(status);
        assertThat(result.getResponseBody()).contains(code);
        assertThat(result.getResponseHeaders().getFirst("X-Request-Id")).isNotBlank();
    }

    private JsonNode adminJson(HttpMethod method, String path, Object body) {
        EntityExchangeResult<String> result = signed(method, path, body)
                .expectBody(String.class).returnResult();
        assertThat(result.getStatus().value())
                .as("管理接口响应: %s %s -> %s", method, path, result.getResponseBody())
                .isEqualTo(200);
        return Json.tree(result.getResponseBody()).get("data");
    }

    private WebTestClient.ResponseSpec signed(HttpMethod method, String path, Object body) {
        String json = body == null ? "" : Json.write(body);
        String timestamp = String.valueOf(System.currentTimeMillis());
        String nonce = UUID.randomUUID().toString();
        String canonicalPath = path.contains("?") ? path.substring(0, path.indexOf('?')) : path;
        String signature = sign(method.name(), canonicalPath, json, timestamp, nonce);
        WebTestClient.RequestBodySpec spec = client.method(method).uri(path)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Internal-Client", "mpt")
                .header("X-Internal-Timestamp", timestamp)
                .header("X-Internal-Nonce", nonce)
                .header("X-Internal-Signature", signature)
                .header("X-Internal-Actor", "it-admin");
        if (body == null) {
            return spec.exchange();
        }
        return spec.bodyValue(json).exchange();
    }

    private String sign(String method, String path, String body, String timestamp, String nonce) {
        String canonical = method + "\n" + path + "\n" + Json.sha256(body) + "\n"
                + timestamp + "\n" + nonce + "\nmpt";
        return InternalHmacVerifier.hmacSha256Hex(SECRET, canonical);
    }

    private String token(String clientType, String vehicleId, String scope) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", "user-1");
        claims.put("client_id", "client-1");
        claims.put("client_type", clientType);
        claims.put("device_id", "device-1");
        claims.put("session_id", "session-1");
        claims.put("scope", scope);
        if (vehicleId != null) {
            claims.put("vehicle_id", vehicleId);
        }
        return Jwts.builder()
                .header().keyId("it-kid").and()
                .claims(claims)
                .issuer(ISSUER)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 600_000))
                .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
                .compact();
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void createDatabase() throws Exception {
        try (java.sql.Connection connection = java.sql.DriverManager.getConnection(
                "jdbc:mysql://" + InfrastructureCondition.MYSQL_HOST + ":" + InfrastructureCondition.MYSQL_PORT
                        + "/?allowPublicKeyRetrieval=true&useSSL=false", "root",
                "9jpHx:G9NBM@Wst");
             java.sql.Statement statement = connection.createStatement()) {
            statement.execute("DROP DATABASE IF EXISTS db_sgw_it");
            statement.execute("CREATE DATABASE db_sgw_it DEFAULT CHARSET utf8mb4");
        }
    }

    private static void startUpstream() {
        upstream = HttpServer.create()
                .port(0)
                .handle((request, response) -> {
                    String path = request.uri().split("\\?")[0];
                    String user = request.requestHeaders().get("X-User-Id", "none");
                    String vin = request.requestHeaders().get("X-Vin", "none");
                    String scope = request.requestHeaders().get("X-Scope", "none");
                    response.header("X-Echo-User", user);
                    response.header("X-Echo-Vin", vin);
                    response.header("X-Echo-Scope", scope);
                    if (path.startsWith("/slow")) {
                        return response.sendString(Mono.delay(Duration.ofSeconds(2)).map(ignored -> "slow")).then();
                    }
                    if (path.startsWith("/fail")) {
                        return response.status(500).sendString(Mono.just("fail")).then();
                    }
                    if (path.startsWith("/v1/")) {
                        return response.sendString(Mono.just("v1")).then();
                    }
                    if (path.startsWith("/v2/")) {
                        return response.sendString(Mono.just("v2")).then();
                    }
                    return response.sendString(Mono.just("ok")).then();
                })
                .bindNow();
        upstreamPort = upstream.port();
    }

    private static void startJwks() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        String body = Json.write(Map.of("keys", List.of(Map.of(
                "kty", "RSA",
                "kid", "it-kid",
                "alg", "RS256",
                "n", base64Url(publicKey.getModulus()),
                "e", base64Url(publicKey.getPublicExponent())))));
        jwks = HttpServer.create()
                .port(0)
                .handle((request, response) -> response
                        .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                        .sendString(Mono.just(body)))
                .bindNow();
        jwksPort = jwks.port();
    }

    private static String base64Url(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

}
