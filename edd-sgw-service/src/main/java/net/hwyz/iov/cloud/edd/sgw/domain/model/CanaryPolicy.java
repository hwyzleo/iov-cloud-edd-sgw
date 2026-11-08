package net.hwyz.iov.cloud.edd.sgw.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.edd.sgw.api.enums.CanaryStableKey;

import java.util.ArrayList;
import java.util.List;

/**
 * 灰度策略。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CanaryPolicy {

    private String policyCode;

    private String policyName;

    private String description;

    private CanaryStableKey stableKey;

    private List<CanaryRule> rules;

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
     * 归一化集合并按优先级排序
     *
     * @return 自身
     */
    public CanaryPolicy normalized() {
        rules = rules == null ? new ArrayList<>() : new ArrayList<>(rules);
        rules.forEach(rule -> {
            if (rule != null) {
                rule.normalized();
            }
        });
        rules.sort(java.util.Comparator.comparing(rule -> rule.getPriority() == null ? Integer.MAX_VALUE : rule.getPriority()));
        return this;
    }

}
