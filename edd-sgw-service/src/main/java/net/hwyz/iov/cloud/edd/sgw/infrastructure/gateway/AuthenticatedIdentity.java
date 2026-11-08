package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

import java.util.List;

/**
 * 由已验签 CIAM 令牌建立的认证身份。
 *
 * @param subject   认证主体
 * @param clientId  客户端ID
 * @param clientType 客户端类型
 * @param deviceId  设备标识
 * @param sessionId 会话标识
 * @param vehicleId 车辆标识
 * @param scopes    scope 集合
 * @author hwyz_leo
 */
public record AuthenticatedIdentity(String subject, String clientId, String clientType, String deviceId,
                                    String sessionId, String vehicleId, List<String> scopes) {
}
