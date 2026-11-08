package net.hwyz.iov.cloud.edd.sgw.adapter.web;

import net.hwyz.iov.cloud.edd.sgw.application.RuntimeStateService;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.RuntimeInstanceResponse;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * 运行时状态接口。
 *
 * @author hwyz_leo
 */
@RestController
@RequestMapping("/api/service/sgw/v1/runtime")
public class RuntimeController {

    private final RuntimeStateService runtimeStateService;

    public RuntimeController(RuntimeStateService runtimeStateService) {
        this.runtimeStateService = runtimeStateService;
    }

    @GetMapping("/instances")
    public Mono<ApiResponse<List<RuntimeInstanceResponse>>> instances() {
        return AdminWebSupport.async(runtimeStateService::instances);
    }

}
