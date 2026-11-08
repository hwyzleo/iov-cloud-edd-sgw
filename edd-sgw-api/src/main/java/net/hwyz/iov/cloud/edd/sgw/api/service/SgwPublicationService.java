package net.hwyz.iov.cloud.edd.sgw.api.service;

import net.hwyz.iov.cloud.edd.sgw.api.enums.PublicationStatus;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.RetryPublicationRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.PublicationResponse;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.bean.PageResult;
import net.hwyz.iov.cloud.framework.common.constant.ServiceNameConstants;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * 服务网关发布记录接口（由 MPT 调用）。
 *
 * @author hwyz_leo
 */
@FeignClient(contextId = "sgwPublicationService", value = ServiceNameConstants.EDD_SGW, path = "/api/service/sgw/v1")
public interface SgwPublicationService {

    /**
     * 分页查询发布记录
     *
     * @param page            页码
     * @param size            每页条数
     * @param status          发布状态筛选
     * @param targetVersionNo 目标版本筛选
     * @return 发布记录分页
     */
    @GetMapping("/publications")
    ApiResponse<PageResult<PublicationResponse>> page(@RequestParam("page") int page,
                                                     @RequestParam("size") int size,
                                                     @RequestParam(value = "status", required = false) PublicationStatus status,
                                                     @RequestParam(value = "targetVersionNo", required = false) Long targetVersionNo);

    /**
     * 重试失败的发布（不改变目标版本的不可变内容）
     *
     * @param request 重试请求
     * @return 新的发布记录
     */
    @PostMapping("/publications")
    ApiResponse<PublicationResponse> retry(@RequestBody RetryPublicationRequest request);

    /**
     * 查询发布记录与逐实例结果
     *
     * @param publicationId 发布ID
     * @return 发布记录
     */
    @GetMapping("/publications/{publicationId}")
    ApiResponse<PublicationResponse> get(@PathVariable("publicationId") String publicationId);

}
