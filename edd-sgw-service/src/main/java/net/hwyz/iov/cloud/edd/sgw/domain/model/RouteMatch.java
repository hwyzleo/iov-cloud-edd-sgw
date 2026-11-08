package net.hwyz.iov.cloud.edd.sgw.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
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
public class RouteMatch {

    private List<String> paths;

    private List<String> methods;

    private List<String> hosts;

    private List<HeaderMatch> headers;

    private List<QueryParamMatch> queryParams;

    private List<String> clientTypes;

    /**
     * 归一化集合字段，避免空指针并保证顺序稳定
     *
     * @return 自身
     */
    public RouteMatch normalized() {
        paths = paths == null ? new ArrayList<>() : paths;
        methods = methods == null ? new ArrayList<>() : methods;
        hosts = hosts == null ? new ArrayList<>() : hosts;
        headers = headers == null ? new ArrayList<>() : headers;
        queryParams = queryParams == null ? new ArrayList<>() : queryParams;
        clientTypes = clientTypes == null ? new ArrayList<>() : clientTypes;
        return this;
    }

}
