package net.hwyz.iov.cloud.edd.sgw.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * 路由匹配条件。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RouteMatchVo {

    /** 路径模式 */
    private List<String> paths;

    /** HTTP 方法 */
    private List<String> methods;

    /** 主机名 */
    private List<String> hosts;

    /** 请求头条件 */
    private List<HeaderMatchVo> headers;

    /** 查询参数条件 */
    private List<QueryParamMatchVo> queryParams;

    /** 客户端类型（声明式元数据，仅用于候选路由选择） */
    private List<String> clientTypes;

}
