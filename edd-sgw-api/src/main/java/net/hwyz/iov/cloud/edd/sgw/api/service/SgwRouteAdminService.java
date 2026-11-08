package net.hwyz.iov.cloud.edd.sgw.api.service;

import net.hwyz.iov.cloud.edd.sgw.api.vo.request.CopyRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.RouteSaveRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.RouteResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ValidationResultVo;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.bean.PageResult;
import net.hwyz.iov.cloud.framework.common.constant.ServiceNameConstants;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * 服务网关路由管理接口（由 MPT 调用）。
 *
 * @author hwyz_leo
 */
@FeignClient(contextId = "sgwRouteAdminService", value = ServiceNameConstants.EDD_SGW, path = "/api/service/sgw/v1")
public interface SgwRouteAdminService {

    /**
     * 物理分页查询路由草稿
     *
     * @param page       页码，从1开始
     * @param size       每页条数
     * @param name       名称模糊匹配
     * @param enabled    启用状态
     * @param target     目标（服务ID或直连主机）
     * @param clientType 客户端类型
     * @return 分页结果
     */
    @GetMapping("/routes")
    ApiResponse<PageResult<RouteResponse>> page(@RequestParam("page") int page,
                                                @RequestParam("size") int size,
                                                @RequestParam(value = "name", required = false) String name,
                                                @RequestParam(value = "enabled", required = false) Boolean enabled,
                                                @RequestParam(value = "target", required = false) String target,
                                                @RequestParam(value = "clientType", required = false) String clientType);

    /**
     * 新增结构化路由草稿
     *
     * @param request 路由请求
     * @return 路由详情
     */
    @PostMapping("/routes")
    ApiResponse<RouteResponse> create(@RequestBody RouteSaveRequest request);

    /**
     * 查询路由详情
     *
     * @param routeCode 路由编码
     * @return 路由详情
     */
    @GetMapping("/routes/{routeCode}")
    ApiResponse<RouteResponse> get(@PathVariable("routeCode") String routeCode);

    /**
     * 乐观更新路由草稿
     *
     * @param routeCode 路由编码
     * @param request   路由请求
     * @return 路由详情
     */
    @PutMapping("/routes/{routeCode}")
    ApiResponse<RouteResponse> update(@PathVariable("routeCode") String routeCode, @RequestBody RouteSaveRequest request);

    /**
     * 复制路由为独立草稿
     *
     * @param routeCode 源路由编码
     * @param request   复制请求
     * @return 新路由详情
     */
    @PostMapping("/routes/{routeCode}/copy")
    ApiResponse<RouteResponse> copy(@PathVariable("routeCode") String routeCode, @RequestBody CopyRequest request);

    /**
     * 逻辑删除路由草稿
     *
     * @param routeCode 路由编码
     * @return 空响应
     */
    @DeleteMapping("/routes/{routeCode}")
    ApiResponse<Void> delete(@PathVariable("routeCode") String routeCode);

    /**
     * 校验路由配置但不发布
     *
     * @param request 路由请求
     * @return 校验结果
     */
    @PostMapping("/routes/validate")
    ApiResponse<ValidationResultVo> validate(@RequestBody RouteSaveRequest request);

}
