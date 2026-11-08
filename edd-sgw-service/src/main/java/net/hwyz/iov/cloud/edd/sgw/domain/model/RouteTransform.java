package net.hwyz.iov.cloud.edd.sgw.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.LinkedHashMap;
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
public class RouteTransform {

    private RewritePath rewritePath;

    private Map<String, String> headersToAdd;

    private List<String> headersToRemove;

    /**
     * 归一化集合字段
     *
     * @return 自身
     */
    public RouteTransform normalized() {
        if (headersToAdd == null) {
            headersToAdd = new LinkedHashMap<>();
        }
        if (headersToRemove == null) {
            headersToRemove = new java.util.ArrayList<>();
        }
        return this;
    }

}
