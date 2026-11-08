package net.hwyz.iov.cloud.edd.sgw.common;

/**
 * 携带网关错误码的异常。
 *
 * @author hwyz_leo
 */
public class SgwException extends RuntimeException {

    private final SgwErrorCode errorCode;

    public SgwException(SgwErrorCode errorCode) {
        super(errorCode.message());
        this.errorCode = errorCode;
    }

    public SgwException(SgwErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public SgwException(SgwErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public SgwErrorCode errorCode() {
        return errorCode;
    }

}
