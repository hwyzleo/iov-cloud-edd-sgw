package net.hwyz.iov.cloud.edd.sgw.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

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
public class CanaryRuleVo {

    /** 规则优先级（策略内唯一，数值小者优先） */
    private Integer priority;

    /** 匹配条件 */
    private CanaryConditionsVo conditions;

    /** 加权目标 */
    private List<CanaryTargetVo> targets;

}
