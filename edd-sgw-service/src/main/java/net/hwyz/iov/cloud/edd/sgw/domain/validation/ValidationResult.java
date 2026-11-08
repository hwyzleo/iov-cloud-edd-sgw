package net.hwyz.iov.cloud.edd.sgw.domain.validation;

import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 校验结果。
 *
 * @author hwyz_leo
 */
public class ValidationResult {

    private final List<ValidationError> errors = new ArrayList<>();

    public static ValidationResult ok() {
        return new ValidationResult();
    }

    /**
     * 追加错误
     *
     * @param field   字段路径
     * @param message 错误说明
     * @return 自身
     */
    public ValidationResult add(String field, String message) {
        errors.add(new ValidationError(field, message));
        return this;
    }

    /**
     * 合并另一结果
     *
     * @param other 另一结果
     * @return 自身
     */
    public ValidationResult merge(ValidationResult other) {
        if (other != null) {
            errors.addAll(other.errors);
        }
        return this;
    }

    public boolean valid() {
        return errors.isEmpty();
    }

    public List<ValidationError> errors() {
        return Collections.unmodifiableList(errors);
    }

    /**
     * 汇总错误说明
     *
     * @return 汇总文本
     */
    public String message() {
        return errors.stream()
                .map(error -> error.field() + ": " + error.message())
                .collect(Collectors.joining("; "));
    }

    /**
     * 校验失败时抛出异常
     *
     * @param errorCode 错误码
     * @return 自身
     */
    public ValidationResult throwIfInvalid(SgwErrorCode errorCode) {
        if (!valid()) {
            throw new SgwException(errorCode, message());
        }
        return this;
    }

}
