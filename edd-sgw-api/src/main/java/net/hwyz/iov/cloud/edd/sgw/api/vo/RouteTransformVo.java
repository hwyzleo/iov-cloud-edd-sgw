package net.hwyz.iov.cloud.edd.sgw.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * 请求变换配置。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RouteTransformVo {

    /** 路径重写 */
    private RewritePathVo rewritePath;

    /** 需要添加或覆盖的请求头 */
    private Map<String, String> headersToAdd;

    /** 需要移除的请求头 */
    private List<String> headersToRemove;

}
