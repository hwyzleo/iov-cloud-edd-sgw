package net.hwyz.iov.cloud.edd.sgw.api.vo.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.edd.sgw.api.enums.CanaryStableKey;
import net.hwyz.iov.cloud.edd.sgw.api.vo.CanaryRuleVo;

import java.util.List;

/**
 * 灰度策略草稿保存请求。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CanaryPolicySaveRequest {

    /** 策略编码（不可变，永不复用） */
    private String policyCode;

    /** 策略名称 */
    @NotBlank(message = "策略名称不能为空")
    private String policyName;

    /** 说明 */
    private String description;

    /** 稳定灰度键 */
    private CanaryStableKey stableKey;

    /** 灰度规则 */
    private List<CanaryRuleVo> rules;

    /** 是否启用 */
    private Boolean enabled;

    /** 记录版本（更新时必填） */
    private Integer rowVersion;

}
