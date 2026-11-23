package net.hwyz.iov.cloud.edd.sgw.api.enums;

/**
 * 路由访问模式。
 * <p>
 * EDD-SGW-DSN-CR-003 D-003-1：新增 {@link #INTERNAL} 承载内部服务域
 * （内网来源 + 内部 HMAC 签名，任一不满足即拒绝）。
 * 该取值为对外契约增量：MPT / MPT-UI 必须同批次认识该枚举，且未知取值不得导致 5xx。
 *
 * @author hwyz_leo
 */
public enum AccessMode {

    /** 匿名访问（无令牌，仍剔除伪造受信头，身份来源标记为 DECLARED） */
    ANONYMOUS,
    /** 需要认证（CIAM 令牌验签 + 客户端类型/scope/权限点校验） */
    AUTHENTICATED,
    /** 内部服务域（内网来源校验 + 内部 HMAC 签名，不注入任何身份头） */
    INTERNAL

}
