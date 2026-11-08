package net.hwyz.iov.cloud.edd.sgw.adapter.web;

import io.github.resilience4j.bulkhead.BulkheadFullException;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebExceptionHandler;
import reactor.core.publisher.Mono;

import java.util.concurrent.TimeoutException;

/**
 * 网关统一异常处理：保证错误响应包含请求ID与时间戳且不泄露内部信息。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
@Order(-2)
public class SgwExceptionHandler implements WebExceptionHandler {

    private final SgwResponseWriter responseWriter;

    public SgwExceptionHandler(SgwResponseWriter responseWriter) {
        this.responseWriter = responseWriter;
    }

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        if (exchange.getResponse().isCommitted()) {
            return Mono.error(ex);
        }
        Throwable mapped = unwrap(ex);
        if (mapped instanceof SgwException sgwException) {
            return responseWriter.write(exchange, sgwException.errorCode(), sgwException.getMessage());
        }
        if (mapped instanceof TimeoutException
                || mapped instanceof io.netty.handler.timeout.ReadTimeoutException) {
            return responseWriter.write(exchange, SgwErrorCode.UPSTREAM_TIMEOUT);
        }
        if (mapped instanceof BulkheadFullException) {
            return responseWriter.write(exchange, SgwErrorCode.CONCURRENCY_LIMITED);
        }
        if (mapped instanceof CallNotPermittedException) {
            return responseWriter.write(exchange, SgwErrorCode.CIRCUIT_OPEN);
        }
        if (mapped instanceof ResponseStatusException responseStatusException
                && responseStatusException.getStatusCode().value() == HttpStatus.NOT_FOUND.value()) {
            return responseWriter.write(exchange, SgwErrorCode.ROUTE_NOT_FOUND);
        }
        log.error("网关请求处理异常", ex);
        return responseWriter.write(exchange, SgwErrorCode.UPSTREAM_UNAVAILABLE, "网关处理请求失败");
    }

    private Throwable unwrap(Throwable error) {
        Throwable current = error;
        while (current != null && current.getCause() != null
                && !(current instanceof SgwException)
                && current.getClass().getName().startsWith("reactor.")) {
            current = current.getCause();
        }
        return current;
    }

}
