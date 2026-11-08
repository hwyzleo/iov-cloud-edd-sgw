package net.hwyz.iov.cloud.edd.sgw.application;

/**
 * 管理操作上下文。
 *
 * @param actor     操作者
 * @param requestId 请求ID
 * @author hwyz_leo
 */
public record AdminContext(String actor, String requestId) {

    /**
     * 未知操作者
     *
     * @return 上下文
     */
    public static AdminContext system() {
        return new AdminContext("system", null);
    }

}
