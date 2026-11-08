package net.hwyz.iov.cloud.edd.sgw.api.service;

import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ExportResponseVo;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.constant.ServiceNameConstants;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

/**
 * 服务网关配置导出接口（由 MPT 调用）。
 * <p>
 * 导出内容为结构化配置，不包含任何密钥或令牌签发凭据。
 *
 * @author hwyz_leo
 */
@FeignClient(contextId = "sgwExportService", value = ServiceNameConstants.EDD_SGW, path = "/api/service/sgw/v1")
public interface SgwExportService {

    /**
     * 导出结构化配置
     *
     * @param type 导出类型：routes、auth-policies、traffic-policies、canary-policies、config
     * @return 导出内容
     */
    @GetMapping("/exports/{type}")
    ApiResponse<ExportResponseVo> export(@PathVariable("type") String type);

}
