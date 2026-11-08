package net.hwyz.iov.cloud.edd.sgw.api.service;

import net.hwyz.iov.cloud.edd.sgw.api.vo.request.CopyRequest;
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
 * 服务网关治理策略管理接口（由 MPT 调用）。
 * <p>
 * 策略类型取值为 auth、traffic、canary；请求与响应体分别对应
 * {@code AuthPolicySaveRequest}/{@code AuthPolicyResponse}、
 * {@code TrafficPolicySaveRequest}/{@code TrafficPolicyResponse}、
 * {@code CanaryPolicySaveRequest}/{@code CanaryPolicyResponse}。
 *
 * @author hwyz_leo
 */
@FeignClient(contextId = "sgwPolicyAdminService", value = ServiceNameConstants.EDD_SGW, path = "/api/service/sgw/v1")
public interface SgwPolicyAdminService {

    /**
     * 分页查询策略
     *
     * @param type    策略类型
     * @param page    页码
     * @param size    每页条数
     * @param name    名称模糊匹配
     * @param enabled 启用状态
     * @return 分页结果
     */
    @GetMapping("/policies/{type}")
    ApiResponse<PageResult<Object>> page(@PathVariable("type") String type,
                                         @RequestParam("page") int page,
                                         @RequestParam("size") int size,
                                         @RequestParam(value = "name", required = false) String name,
                                         @RequestParam(value = "enabled", required = false) Boolean enabled);

    /**
     * 新增策略草稿
     *
     * @param type    策略类型
     * @param request 结构化策略请求
     * @return 策略详情
     */
    @PostMapping("/policies/{type}")
    ApiResponse<Object> create(@PathVariable("type") String type, @RequestBody Object request);

    /**
     * 查询策略详情
     *
     * @param type       策略类型
     * @param policyCode 策略编码
     * @return 策略详情
     */
    @GetMapping("/policies/{type}/{policyCode}")
    ApiResponse<Object> get(@PathVariable("type") String type, @PathVariable("policyCode") String policyCode);

    /**
     * 乐观更新策略
     *
     * @param type       策略类型
     * @param policyCode 策略编码
     * @param request    结构化策略请求
     * @return 策略详情
     */
    @PutMapping("/policies/{type}/{policyCode}")
    ApiResponse<Object> update(@PathVariable("type") String type,
                               @PathVariable("policyCode") String policyCode,
                               @RequestBody Object request);

    /**
     * 复制策略
     *
     * @param type       策略类型
     * @param policyCode 策略编码
     * @param request    复制请求
     * @return 新策略详情
     */
    @PostMapping("/policies/{type}/{policyCode}/copy")
    ApiResponse<Object> copy(@PathVariable("type") String type,
                             @PathVariable("policyCode") String policyCode,
                             @RequestBody CopyRequest request);

    /**
     * 删除未被引用的策略
     *
     * @param type       策略类型
     * @param policyCode 策略编码
     * @return 空响应
     */
    @DeleteMapping("/policies/{type}/{policyCode}")
    ApiResponse<Void> delete(@PathVariable("type") String type, @PathVariable("policyCode") String policyCode);

    /**
     * 校验策略配置
     *
     * @param type    策略类型
     * @param request 结构化策略请求
     * @return 校验结果
     */
    @PostMapping("/policies/{type}/validate")
    ApiResponse<ValidationResultVo> validate(@PathVariable("type") String type, @RequestBody Object request);

}
