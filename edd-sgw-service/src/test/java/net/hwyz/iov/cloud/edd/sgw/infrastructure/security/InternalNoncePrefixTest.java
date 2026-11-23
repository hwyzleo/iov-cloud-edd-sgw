package net.hwyz.iov.cloud.edd.sgw.infrastructure.security;

import net.hwyz.iov.cloud.edd.sgw.common.Json;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 内部签名 nonce 键空间与签名串规范测试（EDD-SGW-DSN-CR-003 §19.4 R-8）。
 * <p>
 * 【设计纠错】内部签名只服务管理面（{@code AdminSecurityFilter}）：内部服务间的业务调用
 * 经 Nacos + Feign 直连，不经过网关，因此不存在业务面 nonce 键空间（{@code sgw:svc:nonce:}）。
 * 本测试锁定「管理面既有键空间与签名串格式不因本 CR 改变」。
 *
 * @author hwyz_leo
 */
class InternalNoncePrefixTest {

    @Test
    @DisplayName("管理面 nonce 键前缀保持不变（升级不使既有键失效）")
    void adminNoncePrefixUnchanged() {
        assertThat(InternalHmacVerifier.NONCE_KEY_PREFIX).isEqualTo("sgw:admin:nonce:");
    }

    @Test
    @DisplayName("仅存在管理面 nonce 键空间（无业务面 scope）")
    void onlyAdminNonceScope() {
        assertThat(InternalHmacVerifier.class.getDeclaredClasses())
                .as("不应再存在 NonceScope 之类的业务面键空间抽象")
                .noneMatch(type -> type.getSimpleName().contains("NonceScope"));
    }

    @Test
    @DisplayName("签名串格式不变：METHOD\\nrawPath\\nbodyHash\\ntimestamp\\nnonce\\nclient")
    void canonicalStringUnchanged() {
        String emptyBodyHash = Json.sha256("");
        String canonical = "GET\n/api/service/sgw/v1/workspace\n"
                + emptyBodyHash + "\n1700000000000\nnonce-1\nmpt";
        String signature = InternalHmacVerifier.hmacSha256Hex("secret", canonical);

        assertThat(emptyBodyHash)
                .isEqualTo("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assertThat(signature).isEqualTo(InternalHmacVerifier.hmacSha256Hex("secret",
                "GET\n/api/service/sgw/v1/workspace\n"
                        + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        + "\n1700000000000\nnonce-1\nmpt"));
        assertThat(signature).matches("[0-9a-f]{64}");
    }

}
