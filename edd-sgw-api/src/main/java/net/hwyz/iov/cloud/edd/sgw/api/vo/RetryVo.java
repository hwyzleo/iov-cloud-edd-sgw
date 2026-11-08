package net.hwyz.iov.cloud.edd.sgw.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * 重试配置。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RetryVo {

    /** 最大尝试次数（含首次请求） */
    private Integer maxAttempts;

    /** 退避时长（毫秒） */
    private Long backoffMillis;

    /** 允许重试的方法 */
    private List<String> methods;

    /** 触发重试的上游状态码 */
    private List<Integer> statuses;

}
