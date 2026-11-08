package net.hwyz.iov.cloud.edd.sgw.api.enums;

/**
 * 路由目标类型。
 * <p>
 * 仅支持内部服务发现与受控的内部直连目标，WebSocket 与 forward 目标被明确排除。
 *
 * @author hwyz_leo
 */
public enum RouteTargetType {

    /** 服务发现目标 */
    SERVICE,
    /** 内部 HTTP 直连目标 */
    HTTP,
    /** 内部 HTTPS 直连目标 */
    HTTPS;

    /**
     * 直连目标协议前缀
     *
     * @return 协议前缀，服务发现目标返回 null
     */
    public String scheme() {
        return switch (this) {
            case HTTP -> "http";
            case HTTPS -> "https";
            case SERVICE -> null;
        };
    }

    /**
     * 判断是否为直连目标
     *
     * @return 是否直连
     */
    public boolean isDirect() {
        return this == HTTP || this == HTTPS;
    }

}
