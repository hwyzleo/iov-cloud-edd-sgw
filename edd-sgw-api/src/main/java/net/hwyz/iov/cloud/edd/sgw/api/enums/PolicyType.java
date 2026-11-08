package net.hwyz.iov.cloud.edd.sgw.api.enums;

import java.util.Arrays;

/**
 * 治理策略类型。
 *
 * @author hwyz_leo
 */
public enum PolicyType {

    /** 认证与授权策略 */
    AUTH("auth"),
    /** 流量治理策略 */
    TRAFFIC("traffic"),
    /** 灰度策略 */
    CANARY("canary");

    private final String value;

    PolicyType(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    /**
     * 根据路径片段解析策略类型
     *
     * @param value 路径片段
     * @return 策略类型
     */
    public static PolicyType valOf(String value) {
        return Arrays.stream(values())
                .filter(type -> type.value.equalsIgnoreCase(value) || type.name().equalsIgnoreCase(value))
                .findFirst()
                .orElse(null);
    }

}
