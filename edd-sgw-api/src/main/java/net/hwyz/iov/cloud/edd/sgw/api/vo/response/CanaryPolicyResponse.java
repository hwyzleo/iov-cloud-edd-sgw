package net.hwyz.iov.cloud.edd.sgw.api.vo.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.edd.sgw.api.enums.CanaryStableKey;
import net.hwyz.iov.cloud.edd.sgw.api.vo.CanaryRuleVo;

import java.time.Instant;
import java.util.List;

/**
 * 灰度策略详情。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CanaryPolicyResponse {

    /** 策略编码 */
    private String policyCode;

    /** 策略名称 */
    private String policyName;

    /** 说明 */
    private String description;

    /** 稳定灰度键 */
    private CanaryStableKey stableKey;

    /** 灰度规则 */
    private List<CanaryRuleVo> rules;

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
