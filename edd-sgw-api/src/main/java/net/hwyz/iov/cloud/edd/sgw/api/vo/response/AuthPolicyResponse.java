package net.hwyz.iov.cloud.edd.sgw.api.vo.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;

import java.time.Instant;
import java.util.List;

/**
 * 认证授权策略详情。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthPolicyResponse {

    /** 策略编码 */
    private String policyCode;

    /** 策略名称 */
    private String policyName;

    /** 说明 */
    private String description;

    /** 访问模式 */
    private AccessMode accessMode;

    /** 允许的客户端类型 */
    private List<String> allowedClientTypes;

    /** 必需的 scope */
    private List<String> requiredScopes;

    /** 必需的权限点 */
    private List<String> requiredPermissions;

    /** 是否启用 */
    private Boolean enabled;

    /** 记录版本 */
    private Integer rowVersion;

    /** 创建者 */
    private String createBy;

    /** 创建时间 */
    private Instant createTime;

    /** 修改者 */
    private String modifyBy;

    /** 修改时间 */
    private Instant modifyTime;

}
