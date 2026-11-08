package net.hwyz.iov.cloud.edd.sgw.adapter.web;

import jakarta.validation.Valid;
import net.hwyz.iov.cloud.edd.sgw.application.RouteAdminService;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.CopyRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.RouteSaveRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.RouteResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ValidationResultVo;
import net.hwyz.iov.cloud.edd.sgw.common.PageSlice;
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
 * 路由管理接口。
 *
 * @author hwyz_leo
 */
@RestController
@RequestMapping("/api/service/sgw/v1/routes")
public class RouteAdminController {

    private final RouteAdminService routeAdminService;

    public RouteAdminController(RouteAdminService routeAdminService) {
        this.routeAdminService = routeAdminService;
    }

    @GetMapping
    public Mono<ApiResponse<PageResult<RouteResponse>>> page(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String name,
            @RequestParam(required = false) Boolean enabled,
            @RequestParam(required = false) String target,
            @RequestParam(required = false) String clientType) {
        int normalizedPage = AdminWebSupport.normalizePage(page);
        int normalizedSize = AdminWebSupport.normalizeSize(size);
        return AdminWebSupport.async(() -> {
            PageSlice<RouteResponse> slice = routeAdminService.page(normalizedPage, normalizedSize,
                    name, enabled, target, clientType);
            return AdminWebSupport.pageResult(slice.items(), slice.total(), slice.page(), slice.size());
        });
    }

    @PostMapping
    public Mono<ApiResponse<RouteResponse>> create(@Valid @RequestBody RouteSaveRequest request,
                                                   ServerWebExchange exchange) {
        return AdminWebSupport.async(() -> {
            var route = routeAdminService.create(request, AdminWebSupport.context(exchange));
            return net.hwyz.iov.cloud.edd.sgw.application.Assembler.toResponse(route);
        });
    }

    @GetMapping("/{routeCode}")
    public Mono<ApiResponse<RouteResponse>> get(@PathVariable String routeCode) {
        return AdminWebSupport.async(() ->
                net.hwyz.iov.cloud.edd.sgw.application.Assembler.toResponse(routeAdminService.get(routeCode)));
    }

    @PutMapping("/{routeCode}")
    public Mono<ApiResponse<RouteResponse>> update(@PathVariable String routeCode,
                                                   @Valid @RequestBody RouteSaveRequest request,
                                                   ServerWebExchange exchange) {
        return AdminWebSupport.async(() -> {
            var route = routeAdminService.update(routeCode, request, AdminWebSupport.context(exchange));
            return net.hwyz.iov.cloud.edd.sgw.application.Assembler.toResponse(route);
        });
    }

    @PostMapping("/{routeCode}/copy")
    public Mono<ApiResponse<RouteResponse>> copy(@PathVariable String routeCode,
                                                 @Valid @RequestBody CopyRequest request,
                                                 ServerWebExchange exchange) {
        return AdminWebSupport.async(() -> {
            var route = routeAdminService.copy(routeCode, request, AdminWebSupport.context(exchange));
            return net.hwyz.iov.cloud.edd.sgw.application.Assembler.toResponse(route);
        });
    }

    @DeleteMapping("/{routeCode}")
    public Mono<ApiResponse<Void>> delete(@PathVariable String routeCode, ServerWebExchange exchange) {
        return AdminWebSupport.asyncVoid(() ->
                routeAdminService.delete(routeCode, AdminWebSupport.context(exchange)));
    }

    @PostMapping("/validate")
    public Mono<ApiResponse<ValidationResultVo>> validate(@RequestBody RouteSaveRequest request) {
        return AdminWebSupport.async(() -> routeAdminService.validate(request));
    }

}
