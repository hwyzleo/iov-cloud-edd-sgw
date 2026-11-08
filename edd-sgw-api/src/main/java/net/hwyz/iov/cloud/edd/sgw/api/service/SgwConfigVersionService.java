package net.hwyz.iov.cloud.edd.sgw.api.service;

import net.hwyz.iov.cloud.edd.sgw.api.vo.request.PublishConfigRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.RollbackRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigDiffResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigVersionDetailResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigVersionResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.PublicationResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.WorkspaceResponse;
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
 * 服务网关配置版本与发布接口（由 MPT 调用）。
 *
 * @author hwyz_leo
 */
@FeignClient(contextId = "sgwConfigVersionService", value = ServiceNameConstants.EDD_SGW, path = "/api/service/sgw/v1")
public interface SgwConfigVersionService {

    /**
     * 查询当前草稿修订号与目标版本
     *
     * @return 工作区状态
     */
    @GetMapping("/workspace")
    ApiResponse<WorkspaceResponse> workspace();

    /**
     * 校验并发布当前草稿修订
     *
     * @param request 发布请求
     * @return 发布记录
     */
    @PostMapping("/config-versions")
    ApiResponse<PublicationResponse> publish(@RequestBody PublishConfigRequest request);

    /**
     * 分页查询版本历史
     *
     * @param page 页码
     * @param size 每页条数
     * @return 版本分页
     */
    @GetMapping("/config-versions")
    ApiResponse<PageResult<ConfigVersionResponse>> history(@RequestParam("page") int page, @RequestParam("size") int size);

    /**
     * 查询不可变版本详情
     *
     * @param versionNo 版本号
     * @return 版本详情
     */
    @GetMapping("/config-versions/{versionNo}")
    ApiResponse<ConfigVersionDetailResponse> detail(@PathVariable("versionNo") Long versionNo);

    /**
     * 版本结构化差异
     *
     * @param from 起始版本
     * @param to   目标版本
     * @return 差异
     */
    @GetMapping("/config-versions/diff")
    ApiResponse<ConfigDiffResponse> diff(@RequestParam("from") Long from, @RequestParam("to") Long to);

    /**
     * 创建并发布回滚版本
     *
     * @param versionNo 目标历史版本
     * @param request   回滚请求
     * @return 发布记录
     */
    @PostMapping("/config-versions/{versionNo}/rollback")
    ApiResponse<PublicationResponse> rollback(@PathVariable("versionNo") Long versionNo, @RequestBody RollbackRequest request);

}
