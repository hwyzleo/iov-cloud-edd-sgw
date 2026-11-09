package net.hwyz.iov.cloud.edd.sgw.infrastructure.security;

/**
 * 网关自有请求头常量（EDD-SGW-DSN-CR-002）。
 * <p>
 * 仅由网关产生并在转发前重新写入，入站同名头一律删除，调用方无法伪造。
 *
 * @author hwyz_leo
 */
public final class SgwHeaders {

    /**
     * 身份来源标记头：描述转发头中的身份信息来自已验证令牌还是客户端声明
     */
    public static final String IDENTITY_SOURCE = "X-Identity-Source";

    /**
     * 身份来源：来自已验签 CIAM 令牌声明
     */
    public static final String IDENTITY_SOURCE_CIAM = "CIAM";

    /**
     * 身份来源：来自客户端声明，下游不得作为可信身份使用
     */
    public static final String IDENTITY_SOURCE_DECLARED = "DECLARED";

    private SgwHeaders() {
    }

}
