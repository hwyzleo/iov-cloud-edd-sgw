package net.hwyz.iov.cloud.edd.sgw.common;

import java.net.InetAddress;

/**
 * CIDR / 单 IP 匹配工具（EDD-SGW-DSN-CR-003 R-7）。
 * <p>
 * 支持 IPv4、IPv6 与不带掩码的单 IP。非法条目在启动/发布校验阶段即被拒绝，不进入运行期。
 * <p>
 * 终审 R-2：单 IP 条目改为 <b>{@link InetAddress} 字节比较</b>，不再用字符串相等。原因：
 * <ul>
 *     <li>{@code ::1} 与 {@code 0:0:0:0:0:0:0:1} 是同一地址的不同写法；</li>
 *     <li>IPv4-mapped IPv6（{@code ::ffff:127.0.0.1}）与 {@code 127.0.0.1} 是同一来源；</li>
 *     <li>容器/双栈环境里 {@code ::1}、{@code 0:0:0:0:0:0:0:1}、{@code ::ffff:127.0.0.1} 会混用。</li>
 * </ul>
 * 字符串比较会导致「配置了却不命中」→ INTERNAL 路由全量 403。CIDR 分支同样先归一化，
 * 使 {@code 127.0.0.0/8} 也能命中 {@code ::ffff:127.0.0.1}。
 *
 * @author hwyz_leo
 */
public final class Cidr {

    private Cidr() {
    }

    /**
     * 条目是否合法（合法 IPv4/IPv6 单地址，或前缀长度合法的 CIDR）
     *
     * @param cidr 条目
     * @return 是否合法
     */
    public static boolean isValid(String cidr) {
        if (cidr == null || cidr.isBlank()) {
            return false;
        }
        String entry = cidr.trim();
        if (!entry.contains("/")) {
            return isAddress(entry);
        }
        String[] parts = entry.split("/");
        if (parts.length != 2 || !isAddress(parts[0])) {
            return false;
        }
        byte[] network = normalize(toBytes(parts[0]));
        try {
            int prefix = Integer.parseInt(parts[1]);
            return prefix > 0 && prefix <= network.length * 8;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * 地址是否命中条目
     *
     * @param cidr 条目（CIDR 或单 IP，支持 IPv4/IPv6，允许 ::1 / 展开形式 / IPv4-mapped 混用）
     * @param ip   待匹配地址
     * @return 是否命中
     */
    public static boolean matches(String cidr, String ip) {
        if (cidr == null || cidr.isBlank() || ip == null || ip.isBlank()) {
            return false;
        }
        String entry = cidr.trim();
        String address = ip.trim();
        byte[] addressBytes = normalize(toBytes(address));
        if (addressBytes.length == 0) {
            return false;
        }
        if (!entry.contains("/")) {
            // 终审 R-2：单 IP 用字节比较（覆盖 ::1 / 展开 / IPv4-mapped 等价写法）
            byte[] entryBytes = normalize(toBytes(entry));
            return entryBytes.length > 0 && java.util.Arrays.equals(entryBytes, addressBytes);
        }
        String[] parts = entry.split("/");
        if (parts.length != 2) {
            return false;
        }
        byte[] network = normalize(toBytes(parts[0]));
        if (network.length == 0 || network.length != addressBytes.length) {
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
            if ((network[i] & mask) != (addressBytes[i] & mask)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 归一化地址字节：IPv4-mapped IPv6（{@code ::ffff:a.b.c.d}）折叠为 4 字节 IPv4，
     * 使 {@code ::ffff:127.0.0.1} 与 {@code 127.0.0.1} 可比较（终审 R-2）。
     * <p>
     * {@code ::1} 与 {@code 0:0:0:0:0:0:0:1} 由 {@link InetAddress#getAddress()} 天然归一为同一 16 字节序列。
     *
     * @param address 地址字节
     * @return 归一化后的字节（无法识别时原样返回）
     */
    private static byte[] normalize(byte[] address) {
        if (address == null) {
            return new byte[0];
        }
        if (address.length == 16) {
            boolean mappedPrefix = true;
            for (int i = 0; i < 10; i++) {
                if (address[i] != 0) {
                    mappedPrefix = false;
                    break;
                }
            }
            if (mappedPrefix && (address[10] & 0xFF) == 0xFF && (address[11] & 0xFF) == 0xFF) {
                byte[] ipv4 = new byte[4];
                System.arraycopy(address, 12, ipv4, 0, 4);
                return ipv4;
            }
        }
        return address;
    }

    private static boolean isAddress(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        try {
            return InetAddress.getByName(value.trim()).getAddress().length > 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] toBytes(String ip) {
        try {
            return InetAddress.getByName(ip).getAddress();
        } catch (Exception e) {
            return new byte[0];
        }
    }

}
