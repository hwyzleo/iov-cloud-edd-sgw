package net.hwyz.iov.cloud.edd.sgw.api.enums;

/**
 * 单个实例的发布结果状态。
 *
 * @author hwyz_leo
 */
public enum InstancePublicationStatus {

    /** 待确认 */
    PENDING,
    /** 成功 */
    SUCCEEDED,
    /** 失败 */
    FAILED,
    /** 超时 */
    TIMEOUT

}
