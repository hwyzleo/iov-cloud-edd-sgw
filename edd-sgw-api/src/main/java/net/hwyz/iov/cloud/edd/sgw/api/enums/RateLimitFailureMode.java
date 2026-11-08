package net.hwyz.iov.cloud.edd.sgw.api.enums;

/**
 * 限流组件不可用时的失败模式。
 *
 * @author hwyz_leo
 */
public enum RateLimitFailureMode {

    /** 拒绝请求（503） */
    FAIL_CLOSED,
    /** 放行请求并记录脱敏本地日志 */
    FAIL_OPEN

}
