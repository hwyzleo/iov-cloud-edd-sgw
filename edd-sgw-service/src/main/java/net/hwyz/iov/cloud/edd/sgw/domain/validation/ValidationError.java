package net.hwyz.iov.cloud.edd.sgw.domain.validation;

/**
 * 校验错误项。
 *
 * @param field   字段路径
 * @param message 错误说明
 * @author hwyz_leo
 */
public record ValidationError(String field, String message) {
}
