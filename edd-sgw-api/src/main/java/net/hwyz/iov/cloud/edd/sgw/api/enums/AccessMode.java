package net.hwyz.iov.cloud.edd.sgw.api.enums;

/**
 * 路由访问模式。
 * <p>
 * 取值恒定只有匿名与已认证两种：内部服务间的调用全部经 Nacos + Feign 直连各微服务，
 * 不经过服务网关，因此网关侧不存在「内部服务域」访问模式
 * （EDD-SGW-DSN-CR-003【设计纠错】）。
 * <p>
 * {@code access_mode} 在策略上为必填：为空或未知取值一律 fail-closed（{@code SGW-403001}），
 * 不会回落为匿名；管理端提交未知取值由管理接口收敛为 400 {@code SGW-400001}。
 *
 * @author hwyz_leo
 */
public enum AccessMode {

    /** 匿名访问（无令牌，仍剔除伪造受信头，身份来源标记为 DECLARED） */
    ANONYMOUS,
    /** 需要认证（CIAM 令牌验签 + 客户端类型/scope/权限点校验） */
    AUTHENTICATED

}
