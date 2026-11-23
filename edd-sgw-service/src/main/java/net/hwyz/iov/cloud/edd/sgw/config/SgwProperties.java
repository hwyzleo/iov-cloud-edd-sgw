package net.hwyz.iov.cloud.edd.sgw.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 服务网关配置项。
 *
 * @author hwyz_leo
 */
@Data
@ConfigurationProperties(prefix = "sgw")
public class SgwProperties {

    /** 实例ID，未配置时由主机地址与端口推导 */
    private String instanceId;

    private Runtime runtime = new Runtime();

    private Publication publication = new Publication();

    private Security security = new Security();

    /**
     * 运行时配置
     */
    @Data
    public static class Runtime {

        /**
         * 获批直连主机集合
         *
         * @return 主机清单
         */
        public java.util.Set<String> allowedDirectHosts() {
            return new java.util.LinkedHashSet<>(directUpstreamHosts);
        }


        /** 获批的内部直连主机清单（支持 *.domain 通配） */
        private List<String> directUpstreamHosts = new ArrayList<>();

        /** 可信代理网段 */
        private List<String> trustedProxyCidrs = new ArrayList<>();

        /**
         * 内部服务域来源网段（EDD-SGW-DSN-CR-003 R-7）。
         * <p>
         * 无缺省值：存在 {@code accessMode=INTERNAL} 且被有效路由引用时必须非空，
         * 否则启动 fail-fast；{@code AccessMode.INTERNAL} 路由的判定链要求来源 IP 命中本清单。
         * <p>
         * 空白条目（如 {@code SGW_INTERNAL_CIDRS} 未设置时展开出的空串、或 {@code a,,b} 中的空段）
         * 在解析前统一过滤，不视为「已配置」。
         */
        private List<String> internalCidrs = new ArrayList<>();

        /**
         * 内部服务域严格模式（EDD-SGW-DSN-CR-003 R-7 终审 R-1），默认 {@code true}。
         * <p>
         * {@code true}：存在 {@code INTERNAL} 路由而 {@code internal-cidrs} 生效条目为空时启动 fail-fast；
         * {@code false}：降级为 WARN 并放行启动（仅供明确知情的迁移期环境使用，运行期仍为失败关闭：
         * 空清单下任何来源 IP 都不命中 → {@code SGW-403001}）。
         */
        private boolean internalDomainStrict = true;

        /** 服务发现中的网关服务名 */
        private String discoveryServiceName = "edd-sgw";

        /** 请求ID响应头 */
        private String requestIdHeader = "X-Request-Id";

        /** 默认连接超时（毫秒） */
        private int defaultConnectTimeoutMillis = 1000;

        /** 默认响应超时（毫秒） */
        private int defaultResponseTimeoutMillis = 5000;

    }

    /**
     * 发布协议配置
     */
    @Data
    public static class Publication {

        /** Nacos 版本指针 Data ID */
        private String dataId = "edd-sgw-config-version";

        /** Nacos 分组 */
        private String group = "DEFAULT_GROUP";

        /** 实例 ACK 超时（秒） */
        private int deadlineSeconds = 60;

        /** 超时扫描间隔（毫秒） */
        private long timeoutSweepIntervalMillis = 5000;

        /** 超时扫描批量大小 */
        private int timeoutSweepBatchSize = 200;

    }

    /**
     * 安全配置
     */
    @Data
    public static class Security {

        private Ciam ciam = new Ciam();

        private Internal internal = new Internal();

    }

    /**
     * CIAM 令牌校验配置
     */
    @Data
    public static class Ciam {

        /** 受信签发者 */
        private String issuer = "https://account.openiov.top";

        /** JWKS 地址，支持 lb:// 前缀 */
        private String jwksUri = "lb://sec-ciam/api/open/oidc/v1/jwks";

        /** 时钟偏移容忍（秒） */
        private long clockSkewSeconds = 30;

        /** 密钥主动刷新间隔（秒） */
        private long keyRefreshIntervalSeconds = 300;

        /** 拉取失败时缓存密钥的可用时限（秒） */
        private long keyStaleDeadlineSeconds = 3600;

        /** 连接超时（毫秒） */
        private int connectTimeoutMillis = 1000;

        /** 响应超时（毫秒） */
        private int responseTimeoutMillis = 3000;

    }

    /**
     * 内部管理请求签名配置
     */
    @Data
    public static class Internal {

        /** 已登记的内部客户端及其密钥 */
        private Map<String, String> clients = new LinkedHashMap<>();

        /** 时间戳容忍窗口（秒） */
        private long clockSkewSeconds = 60;

        /** nonce 防重放保留时长（秒） */
        private long nonceTtlSeconds = 120;

        /** 管理面 nonce 键前缀（EDD-SGW-DSN-CR-003 R-8，保持既有键空间不变） */
        private String nonceKeyPrefixAdmin = "sgw:admin:nonce:";

        /** 业务面（内部服务域）nonce 键前缀（EDD-SGW-DSN-CR-003 R-8，与管理面隔离，防跨面重放） */
        private String nonceKeyPrefixService = "sgw:svc:nonce:";

        /** 内部服务域请求体缓存上限（字节），超限按签名失败处理 */
        private int maxBodyBytes = 1024 * 1024;

        private String clientHeader = "X-Internal-Client";

        private String timestampHeader = "X-Internal-Timestamp";

        private String nonceHeader = "X-Internal-Nonce";

        private String signatureHeader = "X-Internal-Signature";

        private String actorHeader = "X-Internal-Actor";

    }

}
