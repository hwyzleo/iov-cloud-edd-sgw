package net.hwyz.iov.cloud.edd.sgw.adapter.web;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.RequestAttributes;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebInputException;

/**
 * 管理接口错误映射。
 *
 * @author hwyz_leo
 */
@Slf4j
@RestControllerAdvice
public class AdminExceptionHandler {

    @ExceptionHandler(SgwException.class)
    public ResponseEntity<ApiResponse<Void>> handleSgw(SgwException exception, ServerWebExchange exchange) {
        return ResponseEntity.status(exception.errorCode().httpStatus())
                .body(body(exception.errorCode().code(), exception.getMessage(), exchange));
    }

    @ExceptionHandler(ServerWebInputException.class)
    public ResponseEntity<ApiResponse<Void>> handleInput(ServerWebInputException exception,
                                                         ServerWebExchange exchange) {
        String message = exception.getReason() == null ? "请求参数非法" : exception.getReason();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(body(SgwErrorCode.VALIDATION_FAILED.code(), message, exchange));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleOther(Exception exception, ServerWebExchange exchange) {
        log.error("管理接口处理异常", exception);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(body("SGW-500001", "服务网关内部错误", exchange));
    }

    private ApiResponse<Void> body(String code, String message, ServerWebExchange exchange) {
        Object requestId = exchange.getAttributes().get(RequestAttributes.REQUEST_ID);
        return ApiResponse.<Void>builder()
                .code(code)
                .message(message)
                .traceId(requestId == null ? null : requestId.toString())
                .timestamp(System.currentTimeMillis())
                .build();
    }

}
