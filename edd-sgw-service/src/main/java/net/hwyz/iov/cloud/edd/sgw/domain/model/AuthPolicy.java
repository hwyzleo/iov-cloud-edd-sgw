package net.hwyz.iov.cloud.edd.sgw.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;

import java.util.ArrayList;
import java.util.List;

/**
 * 认证授权策略。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthPolicy {

    private String policyCode;

    private String policyName;

    private String description;

    private AccessMode accessMode;

    private List<String> allowedClientTypes;

    private List<String> requiredScopes;

    private List<String> requiredPermissions;

    private Boolean enabled;

    private Integer rowVersion;

    /**
     * 是否生效
     *
     * @return 是否启用
     */
    public boolean effective() {
        return Boolean.TRUE.equals(enabled);
    }

    /**
     * 归一化集合字段
     *
     * @return 自身
     */
    public AuthPolicy normalized() {
        allowedClientTypes = allowedClientTypes == null ? new ArrayList<>() : allowedClientTypes;
        requiredScopes = requiredScopes == null ? new ArrayList<>() : requiredScopes;
        requiredPermissions = requiredPermissions == null ? new ArrayList<>() : requiredPermissions;
        return this;
    }

}
