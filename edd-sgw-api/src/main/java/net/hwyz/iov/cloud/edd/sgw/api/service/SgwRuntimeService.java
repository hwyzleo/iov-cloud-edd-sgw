package net.hwyz.iov.cloud.edd.sgw.api.service;

import net.hwyz.iov.cloud.edd.sgw.api.vo.response.RuntimeInstanceResponse;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.constant.ServiceNameConstants;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;

/**
 * 服务网关运行时状态接口（由 MPT 调用）。
 *
 * @author hwyz_leo
 */
@FeignClient(contextId = "sgwRuntimeService", value = ServiceNameConstants.EDD_SGW, path = "/api/service/sgw/v1")
public interface SgwRuntimeService {

    /**
     * 查询服务发现中的实例及其配置版本状态
     *
     * @return 实例状态列表
     */
    @GetMapping("/runtime/instances")
    ApiResponse<List<RuntimeInstanceResponse>> instances();

}
