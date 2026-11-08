package net.hwyz.iov.cloud.edd.sgw.common;

import org.springframework.http.HttpStatus;

/**
 * 网关错误码契约（EDD-SGW-SPEC 设计 §5.3）。
 *
 * @author hwyz_leo
 */
public enum SgwErrorCode {

    /** 缺失、无效、过期或与客户端不匹配的 CIAM 凭据 */
    UNAUTHORIZED("SGW-401001", HttpStatus.UNAUTHORIZED, "认证凭据无效或缺失"),
    /** 客户端类型、scope 或权限点校验失败 */
    FORBIDDEN("SGW-403001", HttpStatus.FORBIDDEN, "无权访问该路由"),
    /** 未匹配到已发布且启用的路由 */
    ROUTE_NOT_FOUND("SGW-404001", HttpStatus.NOT_FOUND, "未匹配到可用路由"),
    /** 触发限流 */
    RATE_LIMITED("SGW-429001", HttpStatus.TOO_MANY_REQUESTS, "请求过于频繁"),
    /** 触发并发限制 */
    CONCURRENCY_LIMITED("SGW-429002", HttpStatus.TOO_MANY_REQUESTS, "并发请求过多"),
    /** 无可用上游实例或治理依赖不可用 */
    UPSTREAM_UNAVAILABLE("SGW-503001", HttpStatus.SERVICE_UNAVAILABLE, "上游服务不可用"),
    /** 熔断器打开 */
    CIRCUIT_OPEN("SGW-503002", HttpStatus.SERVICE_UNAVAILABLE, "上游服务已熔断"),
    /** 上游响应超时 */
    UPSTREAM_TIMEOUT("SGW-504001", HttpStatus.GATEWAY_TIMEOUT, "上游响应超时"),
    /** 管理端校验失败 */
    VALIDATION_FAILED("SGW-400001", HttpStatus.BAD_REQUEST, "配置校验失败"),
    /** 草稿或乐观锁版本冲突 */
    CONFLICT("SGW-409001", HttpStatus.CONFLICT, "配置版本冲突"),
    /** 策略仍被路由引用 */
    POLICY_REFERENCED("SGW-409002", HttpStatus.CONFLICT, "策略仍被路由引用"),
    /** 发布分发失败 */
    DISPATCH_FAILED("SGW-503003", HttpStatus.SERVICE_UNAVAILABLE, "配置发布分发失败");

    private final String code;
    private final HttpStatus httpStatus;
    private final String message;

    SgwErrorCode(String code, HttpStatus httpStatus, String message) {
        this.code = code;
        this.httpStatus = httpStatus;
        this.message = message;
    }

    public String code() {
        return code;
    }

    public HttpStatus httpStatus() {
        return httpStatus;
    }

    public String message() {
        return message;
    }

}
