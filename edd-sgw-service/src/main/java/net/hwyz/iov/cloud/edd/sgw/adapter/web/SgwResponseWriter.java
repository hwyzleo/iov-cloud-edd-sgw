package net.hwyz.iov.cloud.edd.sgw.adapter.web;

import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.RequestAttributes;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * 统一错误响应写出器。
 *
 * @author hwyz_leo
 */
@Component
public class SgwResponseWriter {

    /**
     * 写出网关错误响应
     *
     * @param exchange 交换
     * @param error    错误码
     * @return 完成信号
     */
    public Mono<Void> write(ServerWebExchange exchange, SgwErrorCode error) {
        return write(exchange, error, error.message());
    }

    /**
     * 写出网关错误响应
     *
     * @param exchange 交换
     * @param error    错误码
     * @param message  脱敏消息
     * @return 完成信号
     */
    public Mono<Void> write(ServerWebExchange exchange, SgwErrorCode error, String message) {
        return write(exchange, error.httpStatus(), error.code(), message);
    }

    /**
     * 写出统一响应
     *
     * @param exchange 交换
     * @param status   HTTP 状态
     * @param code     业务码
     * @param message  消息
     * @return 完成信号
     */
    public Mono<Void> write(ServerWebExchange exchange, HttpStatus status, String code, String message) {
        ServerHttpResponse response = exchange.getResponse();
        if (response.isCommitted()) {
            return Mono.empty();
        }
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        String requestId = requestId(exchange);
        response.getHeaders().set("X-Request-Id", requestId);
        ApiResponse<Void> body = ApiResponse.<Void>builder()
                .code(code)
                .message(message)
                .traceId(requestId)
                .timestamp(System.currentTimeMillis())
                .build();
        byte[] bytes = Json.write(body).getBytes(StandardCharsets.UTF_8);
        return response.writeWith(Mono.just(response.bufferFactory().wrap(bytes)));
    }

    private String requestId(ServerWebExchange exchange) {
        Object requestId = exchange.getAttributes().get(RequestAttributes.REQUEST_ID);
        if (requestId != null) {
            return requestId.toString();
        }
        String generated = UUID.randomUUID().toString();
        exchange.getAttributes().put(RequestAttributes.REQUEST_ID, generated);
        return generated;
    }

}
