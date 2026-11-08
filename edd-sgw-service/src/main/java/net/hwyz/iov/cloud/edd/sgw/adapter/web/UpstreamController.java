package net.hwyz.iov.cloud.edd.sgw.adapter.web;

import net.hwyz.iov.cloud.edd.sgw.application.UpstreamAdminService;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.UpstreamOptionsResponse;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * 上游可选项接口。
 *
 * @author hwyz_leo
 */
@RestController
@RequestMapping("/api/service/sgw/v1/upstreams")
public class UpstreamController {

    private final UpstreamAdminService upstreamAdminService;

    public UpstreamController(UpstreamAdminService upstreamAdminService) {
        this.upstreamAdminService = upstreamAdminService;
    }

    @GetMapping("/options")
    public Mono<ApiResponse<UpstreamOptionsResponse>> options() {
        return AdminWebSupport.async(upstreamAdminService::options);
    }

}
