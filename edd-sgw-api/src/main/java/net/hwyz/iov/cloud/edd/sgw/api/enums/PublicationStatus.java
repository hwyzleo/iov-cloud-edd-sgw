package net.hwyz.iov.cloud.edd.sgw.api.enums;

/**
 * 发布状态。
 *
 * @author hwyz_leo
 */
public enum PublicationStatus {

    /** 校验中 */
    VALIDATING,
    /** 分发中 */
    DISPATCHING,
    /** 等待实例确认 */
    WAITING_ACK,
    /** 全部成功 */
    SUCCEEDED,
    /** 部分失败 */
    PARTIAL_FAILED,
    /** 失败 */
    FAILED;

    /**
     * 是否为终态
     *
     * @return 是否终态
     */
    public boolean isTerminal() {
        return this == SUCCEEDED || this == PARTIAL_FAILED || this == FAILED;
    }

}
