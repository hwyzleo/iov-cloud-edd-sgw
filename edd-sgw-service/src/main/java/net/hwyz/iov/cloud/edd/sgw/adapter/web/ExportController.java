package net.hwyz.iov.cloud.edd.sgw.adapter.web;

import net.hwyz.iov.cloud.edd.sgw.application.ExportService;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ExportResponseVo;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * 配置导出接口。
 *
 * @author hwyz_leo
 */
@RestController
@RequestMapping("/api/service/sgw/v1/exports")
public class ExportController {

    private final ExportService exportService;

    public ExportController(ExportService exportService) {
        this.exportService = exportService;
    }

    @GetMapping("/{type}")
    public Mono<ApiResponse<ExportResponseVo>> export(@PathVariable String type) {
        return AdminWebSupport.async(() -> exportService.export(type));
    }

}
