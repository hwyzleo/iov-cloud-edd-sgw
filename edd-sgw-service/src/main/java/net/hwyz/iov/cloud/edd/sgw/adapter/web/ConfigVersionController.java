package net.hwyz.iov.cloud.edd.sgw.adapter.web;

import jakarta.validation.Valid;
import net.hwyz.iov.cloud.edd.sgw.application.ConfigVersionService;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.PublishConfigRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.RollbackRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigDiffResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigVersionDetailResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ConfigVersionResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.PublicationResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.WorkspaceResponse;
import net.hwyz.iov.cloud.edd.sgw.common.PageSlice;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.bean.PageResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 配置版本与发布接口。
 *
 * @author hwyz_leo
 */
@RestController
@RequestMapping("/api/service/sgw/v1")
public class ConfigVersionController {

    private final ConfigVersionService configVersionService;

    public ConfigVersionController(ConfigVersionService configVersionService) {
        this.configVersionService = configVersionService;
    }

    @GetMapping("/workspace")
    public Mono<ApiResponse<WorkspaceResponse>> workspace() {
        return AdminWebSupport.async(configVersionService::workspace);
    }

    @PostMapping("/config-versions")
    public Mono<ApiResponse<PublicationResponse>> publish(@Valid @RequestBody PublishConfigRequest request,
                                                          ServerWebExchange exchange) {
        return AdminWebSupport.async(() -> configVersionService.publish(request, AdminWebSupport.context(exchange)));
    }

    @GetMapping("/config-versions")
    public Mono<ApiResponse<PageResult<ConfigVersionResponse>>> history(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int size) {
        int normalizedPage = AdminWebSupport.normalizePage(page);
        int normalizedSize = AdminWebSupport.normalizeSize(size);
        return AdminWebSupport.async(() -> {
            PageSlice<ConfigVersionResponse> slice = configVersionService.history(normalizedPage, normalizedSize);
            return AdminWebSupport.pageResult(slice.items(), slice.total(), slice.page(), slice.size());
        });
    }

    @GetMapping("/config-versions/diff")
    public Mono<ApiResponse<ConfigDiffResponse>> diff(@RequestParam("from") Long from,
                                                      @RequestParam("to") Long to) {
        return AdminWebSupport.async(() -> configVersionService.diff(from, to));
    }

    @GetMapping("/config-versions/{versionNo}")
    public Mono<ApiResponse<ConfigVersionDetailResponse>> detail(@PathVariable Long versionNo) {
        return AdminWebSupport.async(() -> configVersionService.detail(versionNo));
    }

    @PostMapping("/config-versions/{versionNo}/rollback")
    public Mono<ApiResponse<PublicationResponse>> rollback(@PathVariable Long versionNo,
                                                            @Valid @RequestBody RollbackRequest request,
                                                            ServerWebExchange exchange) {
        return AdminWebSupport.async(() -> configVersionService.rollback(versionNo, request,
                AdminWebSupport.context(exchange)));
    }

}
