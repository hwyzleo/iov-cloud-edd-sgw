package net.hwyz.iov.cloud.edd.sgw.adapter.web;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.RequestAttributes;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import org.springframework.core.codec.CodecException;
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

    /**
     * 请求体编解码失败（如未知枚举取值）：按业务校验错误返回，不得暴露 5xx。
     * <p>
     * EDD-SGW-DSN-CR-003 D-003-5：SGW 与 MPT 的 {@code AccessMode} 版本错配时，
     * 调用方应收到结构化 400（等价 {@code SGW-400001}），提示版本不匹配而非内部错误。
     */
    @ExceptionHandler(CodecException.class)
    public ResponseEntity<ApiResponse<Void>> handleCodec(CodecException exception, ServerWebExchange exchange) {
        log.warn("管理接口请求体解析失败（可能是枚举版本错配）: {}", exception.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(body(SgwErrorCode.VALIDATION_FAILED.code(), "请求体解析失败：枚举取值未知或格式不匹配", exchange));
    }

    /**
     * 枚举/字段转换失败（如 {@code accessMode=FUTURE_MODE}）：按业务校验错误返回 400，不得 5xx。
     * <p>
     * EDD-SGW-DSN-CR-003 D-003-5：管理端 DTO 由 JsonNode 转换而来，未知枚举以
     * {@link IllegalArgumentException} 形式暴露；此处收敛为 {@code SGW-400001} 并提示版本不匹配。
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponse<Void>> handleIllegalArgument(IllegalArgumentException exception,
                                                                  ServerWebExchange exchange) {
        log.warn("管理接口请求取值非法（可能是枚举版本错配）: {}", exception.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(body(SgwErrorCode.VALIDATION_FAILED.code(),
                        "请求取值非法：枚举取值未知或格式不匹配（请确认 SGW 与 MPT 版本一致）", exchange));
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
