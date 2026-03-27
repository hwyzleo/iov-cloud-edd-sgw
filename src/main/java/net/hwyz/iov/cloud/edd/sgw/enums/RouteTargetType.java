package net.hwyz.iov.cloud.edd.sgw.enums;

import lombok.AllArgsConstructor;

import java.util.Arrays;

/**
 * 路由目标类型枚举类
 *
 * @author hwyz_leo
 */
@AllArgsConstructor
public enum RouteTargetType {

    /** 注册中心负载均衡 **/
    LB("lb://"),
    /** HTTP **/
    HTTP("http://"),
    /** HTTPS **/
    HTTPS("https://"),
    /** WebSocket **/
    WS("ws://"),
    /** 内部转发 **/
    FORWARD("forward:/");

    public final String protocol;
    public static RouteTargetType valOf(String val) {
        return Arrays.stream(RouteTargetType.values())
                .filter(routeTargetType -> routeTargetType.name().equals(val))
                .findFirst()
                .orElse(null);
    }

}
