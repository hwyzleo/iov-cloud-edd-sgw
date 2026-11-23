package net.hwyz.iov.cloud.edd.sgw.common;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CIDR / 单 IP 匹配测试（EDD-SGW-DSN-CR-003 R-7 终审 R-2）。
 * <p>
 * 重点覆盖：单 IP 条目不得用字符串相等比较 —— {@code ::1}、{@code 0:0:0:0:0:0:0:1}、
 * {@code ::ffff:127.0.0.1} 与 {@code 127.0.0.1} 的等价关系。
 *
 * @author hwyz_leo
 */
class CidrTest {

    @Test
    @DisplayName("R-2：IPv6 回环不同写法互相命中（::1 / 展开形式 / 大写）")
    void loopbackIpv6EquivalentForms() {
        assertThat(Cidr.matches("::1", "0:0:0:0:0:0:0:1")).isTrue();
        assertThat(Cidr.matches("0:0:0:0:0:0:0:1", "::1")).isTrue();
        assertThat(Cidr.matches("::1", "::1")).isTrue();
        assertThat(Cidr.matches("::1", "0:0:0:0:0:0:0:2")).isFalse();
    }

    @Test
    @DisplayName("R-2：IPv4-mapped IPv6 与 IPv4 互相命中")
    void ipv4MappedEquivalent() {
        assertThat(Cidr.matches("::ffff:127.0.0.1", "127.0.0.1")).isTrue();
        assertThat(Cidr.matches("127.0.0.1", "::ffff:127.0.0.1")).isTrue();
        assertThat(Cidr.matches("127.0.0.1", "127.0.0.2")).isFalse();
        assertThat(Cidr.matches("::1", "::ffff:127.0.0.1")).isFalse();
    }

    @Test
    @DisplayName("R-2：CIDR 分支同样归一化（127.0.0.0/8 命中 IPv4-mapped 来源）")
    void cidrMatchesMappedAddress() {
        assertThat(Cidr.matches("127.0.0.0/8", "::ffff:127.0.0.1")).isTrue();
        assertThat(Cidr.matches("10.0.0.0/8", "::ffff:10.1.2.3")).isTrue();
        assertThat(Cidr.matches("10.0.0.0/8", "::ffff:11.1.2.3")).isFalse();
        assertThat(Cidr.matches("::1/128", "0:0:0:0:0:0:0:1")).isTrue();
        assertThat(Cidr.matches("fd00::/8", "fd00::1")).isTrue();
        assertThat(Cidr.matches("fd00::/8", "fe80::1")).isFalse();
    }

    @Test
    @DisplayName("空白/非法输入不命中且不抛异常（终审 R-1 配合项）")
    void blankInputsNeverMatch() {
        assertThat(Cidr.matches("", "127.0.0.1")).isFalse();
        assertThat(Cidr.matches("   ", "127.0.0.1")).isFalse();
        assertThat(Cidr.matches(null, "127.0.0.1")).isFalse();
        assertThat(Cidr.matches("127.0.0.1", "")).isFalse();
        assertThat(Cidr.matches("127.0.0.1", null)).isFalse();
        assertThat(Cidr.matches("not-an-ip", "127.0.0.1")).isFalse();
        assertThat(Cidr.matches("10.0.0.0/8", "not-an-ip")).isFalse();
        assertThat(Cidr.matches("10.0.0.0/33", "10.0.0.1")).isFalse();
    }

    @Test
    @DisplayName("isValid：单 IP 与 CIDR 前缀长度校验")
    void isValidContract() {
        assertThat(Cidr.isValid("127.0.0.1")).isTrue();
        assertThat(Cidr.isValid("::1")).isTrue();
        assertThat(Cidr.isValid("::ffff:127.0.0.1")).isTrue();
        assertThat(Cidr.isValid("10.0.0.0/8")).isTrue();
        assertThat(Cidr.isValid("fd00::/8")).isTrue();
        assertThat(Cidr.isValid("::/0")).isFalse();
        assertThat(Cidr.isValid("10.0.0.0/33")).isFalse();
        assertThat(Cidr.isValid("999.1.1.1")).isFalse();
        assertThat(Cidr.isValid("")).isFalse();
        assertThat(Cidr.isValid(null)).isFalse();
    }

}
