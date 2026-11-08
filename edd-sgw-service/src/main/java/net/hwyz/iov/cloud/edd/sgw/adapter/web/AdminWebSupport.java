package net.hwyz.iov.cloud.edd.sgw.adapter.web;

import net.hwyz.iov.cloud.edd.sgw.application.AdminContext;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.RequestAttributes;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.bean.PageResult;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.List;
import java.util.function.Supplier;

/**
 * 管理端控制器公共支持。
 *
 * @author hwyz_leo
 */
public final class AdminWebSupport {

    private static final int MAX_PAGE_SIZE = 200;

    private AdminWebSupport() {
    }

    /**
     * 在弹性线程池执行阻塞用例
     *
     * @param supplier 用例
     * @param <T>      类型
     * @return 响应
     */
    public static <T> Mono<ApiResponse<T>> async(Supplier<T> supplier) {
        return Mono.fromSupplier(supplier)
                .subscribeOn(Schedulers.boundedElastic())
                .map(ApiResponse::ok);
    }

    /**
     * 在弹性线程池执行无返回值用例
     *
     * @param runnable 用例
     * @return 响应
     */
    public static Mono<ApiResponse<Void>> asyncVoid(Runnable runnable) {
        return Mono.fromRunnable(runnable)
                .subscribeOn(Schedulers.boundedElastic())
                .then(Mono.fromSupplier(ApiResponse::ok));
    }

    /**
     * 归一化分页参数
     *
     * @param page 页码
     * @param size 每页条数
     * @return 归一化后的大小
     */
    public static int normalizeSize(int size) {
        if (size < 1) {
            return 20;
        }
        return Math.min(size, MAX_PAGE_SIZE);
    }

    /**
     * 归一化页码
     *
     * @param page 页码
     * @return 归一化页码
     */
    public static int normalizePage(int page) {
        return Math.max(page, 1);
    }

    /**
     * 构造分页结果
     *
     * @param items 数据
     * @param total 总数
     * @param page  页码
     * @param size  每页条数
     * @param <T>   类型
     * @return 分页结果
     */
    public static <T> PageResult<T> pageResult(List<T> items, long total, int page, int size) {
        return PageResult.<T>builder().items(items).total(total).page(page).size(size).build();
    }

    /**
     * 管理操作上下文
     *
     * @param exchange 交换
     * @return 上下文
     */
    public static AdminContext context(ServerWebExchange exchange) {
        Object actor = exchange.getAttributes().get(RequestAttributes.ADM_ACTOR);
        Object requestId = exchange.getAttributes().get(RequestAttributes.REQUEST_ID);
        return new AdminContext(actor == null ? "unknown" : actor.toString(),
                requestId == null ? null : requestId.toString());
    }

}
