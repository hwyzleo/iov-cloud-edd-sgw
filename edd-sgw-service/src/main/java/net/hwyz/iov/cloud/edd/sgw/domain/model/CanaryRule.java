package net.hwyz.iov.cloud.edd.sgw.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

/**
 * 灰度规则。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CanaryRule {

    private Integer priority;

    private CanaryConditions conditions;

    private List<CanaryTarget> targets;

    /**
     * 归一化集合字段
     *
     * @return 自身
     */
    public CanaryRule normalized() {
        if (conditions != null) {
            conditions.normalized();
        }
        targets = targets == null ? new ArrayList<>() : targets;
        return this;
    }

}
