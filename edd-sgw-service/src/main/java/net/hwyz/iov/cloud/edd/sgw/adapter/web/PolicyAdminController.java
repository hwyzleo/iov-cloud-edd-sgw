package net.hwyz.iov.cloud.edd.sgw.adapter.web;

import com.fasterxml.jackson.databind.JsonNode;
import net.hwyz.iov.cloud.edd.sgw.application.PolicyAdminService;
import net.hwyz.iov.cloud.edd.sgw.api.enums.PolicyType;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.AuthPolicySaveRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.CanaryPolicySaveRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.CopyRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.TrafficPolicySaveRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ValidationResultVo;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.common.PageSlice;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.bean.PageResult;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 治理策略管理接口。
 *
 * @author hwyz_leo
 */
@RestController
@RequestMapping("/api/service/sgw/v1/policies/{type}")
public class PolicyAdminController {

    private final PolicyAdminService policyAdminService;

    public PolicyAdminController(PolicyAdminService policyAdminService) {
        this.policyAdminService = policyAdminService;
    }

    @GetMapping
    public Mono<ApiResponse<PageResult<Object>>> page(
            @PathVariable String type,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String name,
            @RequestParam(required = false) Boolean enabled) {
        int normalizedPage = AdminWebSupport.normalizePage(page);
        int normalizedSize = AdminWebSupport.normalizeSize(size);
        return AdminWebSupport.async(() -> {
            PageSlice<Object> slice = policyAdminService.page(type, normalizedPage, normalizedSize, name, enabled);
            return AdminWebSupport.pageResult(slice.items(), slice.total(), slice.page(), slice.size());
        });
    }

    @PostMapping
    public Mono<ApiResponse<Object>> create(@PathVariable String type, @RequestBody JsonNode body,
                                            ServerWebExchange exchange) {
        return AdminWebSupport.async(() -> policyAdminService.create(type, convert(type, body),
                AdminWebSupport.context(exchange)));
    }

    @GetMapping("/{policyCode}")
    public Mono<ApiResponse<Object>> get(@PathVariable String type, @PathVariable String policyCode) {
        return AdminWebSupport.async(() -> policyAdminService.get(type, policyCode));
    }

    @PutMapping("/{policyCode}")
    public Mono<ApiResponse<Object>> update(@PathVariable String type, @PathVariable String policyCode,
                                            @RequestBody JsonNode body, ServerWebExchange exchange) {
        return AdminWebSupport.async(() -> policyAdminService.update(type, policyCode, convert(type, body),
                AdminWebSupport.context(exchange)));
    }

    @PostMapping("/{policyCode}/copy")
    public Mono<ApiResponse<Object>> copy(@PathVariable String type, @PathVariable String policyCode,
                                          @RequestBody CopyRequest request, ServerWebExchange exchange) {
        return AdminWebSupport.async(() -> policyAdminService.copy(type, policyCode, request,
                AdminWebSupport.context(exchange)));
    }

    @DeleteMapping("/{policyCode}")
    public Mono<ApiResponse<Void>> delete(@PathVariable String type, @PathVariable String policyCode,
                                          ServerWebExchange exchange) {
        return AdminWebSupport.asyncVoid(() -> policyAdminService.delete(type, policyCode,
                AdminWebSupport.context(exchange)));
    }

    @PostMapping("/validate")
    public Mono<ApiResponse<ValidationResultVo>> validate(@PathVariable String type, @RequestBody JsonNode body) {
        return AdminWebSupport.async(() -> policyAdminService.validate(type, convert(type, body)));
    }

    private Object convert(String type, JsonNode body) {
        PolicyType policyType = PolicyType.valOf(type);
        if (policyType == null) {
            throw new SgwException(SgwErrorCode.VALIDATION_FAILED, "未知策略类型: " + type);
        }
        return switch (policyType) {
            case AUTH -> Json.convert(body, AuthPolicySaveRequest.class);
            case TRAFFIC -> Json.convert(body, TrafficPolicySaveRequest.class);
            case CANARY -> Json.convert(body, CanaryPolicySaveRequest.class);
        };
    }

}
