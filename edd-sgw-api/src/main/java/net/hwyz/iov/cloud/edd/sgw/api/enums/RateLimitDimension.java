package net.hwyz.iov.cloud.edd.sgw.api.enums;

/**
 * 集群限流维度。
 *
 * @author hwyz_leo
 */
public enum RateLimitDimension {

    /** 按路由 */
    ROUTE,
    /** 按客户端类型 */
    CLIENT_TYPE,
    /** 按客户端ID */
    CLIENT_ID,
    /** 按认证主体 */
    AUTHENTICATED_SUBJECT,
    /** 按车辆标识 */
    VEHICLE_ID,
    /** 按来源IP */
    SOURCE_IP

}
