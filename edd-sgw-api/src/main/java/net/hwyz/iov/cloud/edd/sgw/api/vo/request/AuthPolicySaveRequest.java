package net.hwyz.iov.cloud.edd.sgw.api.vo.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;

import java.util.List;

/**
 * 认证授权策略草稿保存请求。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthPolicySaveRequest {

    /** 策略编码（不可变，永不复用） */
    private String policyCode;

    /** 策略名称 */
    @NotBlank(message = "策略名称不能为空")
    private String policyName;

    /** 说明 */
    private String description;

    /** 访问模式 */
    private AccessMode accessMode;

    /** 允许的客户端类型（或语义） */
    private List<String> allowedClientTypes;

    /** 必需的 OAuth scope（与语义） */
    private List<String> requiredScopes;

    /** 必需的权限点（与语义，匹配 perm: 前缀 scope） */
    private List<String> requiredPermissions;

    /** 是否启用 */
    private Boolean enabled;

    /** 记录版本（更新时必填） */
    private Integer rowVersion;

}
