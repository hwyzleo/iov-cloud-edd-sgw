package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

/**
 * 运行时交换属性键。
 *
 * @author hwyz_leo
 */
public final class RequestAttributes {

    /** 请求ID */
    public static final String REQUEST_ID = "sgw.requestId";

    /** 请求开始时捕获的配置快照 */
    public static final String SNAPSHOT = "sgw.snapshot";

    /** 匹配到的已编译路由 */
    public static final String ROUTE = "sgw.route";

    /** 认证身份（匿名请求为空） */
    public static final String IDENTITY = "sgw.identity";

    /** 来源IP */
    public static final String SOURCE_IP = "sgw.sourceIp";

    /** 上游响应状态码 */
    public static final String UPSTREAM_STATUS = "sgw.upstreamStatus";

    /** 管理端操作者 */
    public static final String ADM_ACTOR = "sgw.admin.actor";

    private RequestAttributes() {
    }

}
