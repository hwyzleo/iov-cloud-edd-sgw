package net.hwyz.iov.cloud.edd.sgw.infrastructure.security;

/**
 * 鉴权拒绝原因（EDD-SGW-DSN-CR-003 §7.1 / §7.2）。
 * <p>
 * 仅用于指标标签与脱敏审计字段，不进入响应体（对外语义统一收敛为 {@code SGW-403001}）。
 *
 * @author hwyz_leo
 */
public enum RejectReason {

    /** 受保护路由缺少访问令牌 */
    NO_TOKEN,
    /** 访问令牌缺失、无效、过期或与客户端声明不匹配 */
    INVALID_TOKEN,
    /** 客户端类型不被该路由允许 */
    CLIENT_TYPE,
    /** 缺少必需 scope */
    SCOPE,
    /** 缺少必需权限点 */
    PERMISSION,
    /** 路由未绑定认证授权策略（策略编码为空或策略不存在或访问模式缺失） */
    NO_POLICY,
    /** 认证授权策略被禁用 */
    POLICY_DISABLED,
    /** 内部服务域签名或来源校验失败 */
    INTERNAL_AUTH

}
