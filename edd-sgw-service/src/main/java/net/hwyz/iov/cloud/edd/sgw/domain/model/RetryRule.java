package net.hwyz.iov.cloud.edd.sgw.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

/**
 * 重试规则。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RetryRule {

    private Integer maxAttempts;

    private Long backoffMillis;

    private List<String> methods;

    private List<Integer> statuses;

    /**
     * 归一化集合字段
     *
     * @return 自身
     */
    public RetryRule normalized() {
        methods = methods == null ? new ArrayList<>() : methods;
        statuses = statuses == null ? new ArrayList<>() : statuses;
        return this;
    }

}
