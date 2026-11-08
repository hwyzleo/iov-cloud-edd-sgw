package net.hwyz.iov.cloud.edd.sgw.api.service;

import net.hwyz.iov.cloud.edd.sgw.api.vo.response.UpstreamOptionsResponse;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.constant.ServiceNameConstants;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * 服务网关上游可选项接口（由 MPT 调用）。
 *
 * @author hwyz_leo
 */
@FeignClient(contextId = "sgwUpstreamService", value = ServiceNameConstants.EDD_SGW, path = "/api/service/sgw/v1")
public interface SgwUpstreamService {

    /**
     * 查询注册中心服务与获批直连主机
     *
     * @return 上游可选项
     */
    @GetMapping("/upstreams/options")
    ApiResponse<UpstreamOptionsResponse> options();

}
