package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.net.InetSocketAddress;

/**
 * 来源IP解析：仅当直连对端属于可信代理时才采用转发头。
 *
 * @author hwyz_leo
 */
@Component
public class SourceIpResolver {

    private final SgwProperties properties;

    public SourceIpResolver(SgwProperties properties) {
        this.properties = properties;
    }

    /**
     * 解析来源IP
     *
     * @param request 请求
     * @return 来源IP
     */
    public String resolve(ServerHttpRequest request) {
        InetSocketAddress remote = request.getRemoteAddress();
        String peer = remote == null || remote.getAddress() == null
                ? null : remote.getAddress().getHostAddress();
        if (peer != null && trusted(peer)) {
            String forwarded = request.getHeaders().getFirst("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                return forwarded.split(",")[0].trim();
            }
        }
        return peer;
    }

    private boolean trusted(String peer) {
        return properties.getRuntime().getTrustedProxyCidrs().stream().anyMatch(cidr -> matches(cidr, peer));
    }

    private boolean matches(String cidr, String ip) {
        if (cidr == null || cidr.isBlank()) {
            return false;
        }
        String entry = cidr.trim();
        if (!entry.contains("/")) {
            return entry.equals(ip);
        }
        String[] parts = entry.split("/");
        byte[] network = toBytes(parts[0]);
        byte[] address = toBytes(ip);
        if (network.length == 0 || network.length != address.length) {
            return false;
        }
        int prefix;
        try {
            prefix = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            return false;
        }
        int bits = network.length * 8;
        if (prefix < 0 || prefix > bits) {
            return false;
        }
        for (int i = 0; i < network.length; i++) {
            int maskBits = Math.min(8, Math.max(0, prefix - i * 8));
            int mask = maskBits == 0 ? 0 : (0xFF << (8 - maskBits)) & 0xFF;
            if ((network[i] & mask) != (address[i] & mask)) {
                return false;
            }
        }
        return true;
    }

    private byte[] toBytes(String ip) {
        try {
            java.net.InetAddress address = java.net.InetAddress.getByName(ip);
            return address.getAddress();
        } catch (Exception e) {
            return new byte[0];
        }
    }

}
