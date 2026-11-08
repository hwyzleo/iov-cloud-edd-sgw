package net.hwyz.iov.cloud.edd.sgw.adapter.web;

import jakarta.validation.Valid;
import net.hwyz.iov.cloud.edd.sgw.api.enums.PublicationStatus;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.RetryPublicationRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.PublicationResponse;
import net.hwyz.iov.cloud.edd.sgw.application.PublicationService;
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
 * 发布记录接口。
 *
 * @author hwyz_leo
 */
@RestController
@RequestMapping("/api/service/sgw/v1/publications")
public class PublicationController {

    private final PublicationService publicationService;

    public PublicationController(PublicationService publicationService) {
        this.publicationService = publicationService;
    }

    @GetMapping
    public Mono<ApiResponse<PageResult<PublicationResponse>>> page(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) PublicationStatus status,
            @RequestParam(required = false) Long targetVersionNo) {
        int normalizedPage = AdminWebSupport.normalizePage(page);
        int normalizedSize = AdminWebSupport.normalizeSize(size);
        return AdminWebSupport.async(() -> {
            PageSlice<PublicationResponse> slice = publicationService.page(normalizedPage, normalizedSize,
                    status, targetVersionNo);
            return AdminWebSupport.pageResult(slice.items(), slice.total(), slice.page(), slice.size());
        });
    }

    @PostMapping
    public Mono<ApiResponse<PublicationResponse>> retry(@Valid @RequestBody RetryPublicationRequest request,
                                                        ServerWebExchange exchange) {
        return AdminWebSupport.async(() -> publicationService.retry(request, AdminWebSupport.context(exchange)));
    }

    @GetMapping("/{publicationId}")
    public Mono<ApiResponse<PublicationResponse>> get(@PathVariable String publicationId) {
        return AdminWebSupport.async(() -> publicationService.get(publicationId));
    }

}
