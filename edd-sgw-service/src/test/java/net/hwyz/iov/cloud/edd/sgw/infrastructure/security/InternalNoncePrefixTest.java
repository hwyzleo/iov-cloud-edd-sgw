package net.hwyz.iov.cloud.edd.sgw.infrastructure.security;

import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 内部签名 nonce 键空间与 bodyHash 规范测试（EDD-SGW-DSN-CR-003 §19.4 R-8）。
 *
 * @author hwyz_leo
 */
class InternalNoncePrefixTest {

    @Test
    @DisplayName("管理面与业务面 nonce 键空间默认前缀互不挤占")
    void defaultNoncePrefixes() {
        InternalHmacVerifier verifier = new InternalHmacVerifier(new SgwProperties(), null);

        assertThat(verifier.nonceKeyPrefix(InternalHmacVerifier.NonceScope.ADMIN))
                .as("管理面沿用既有键空间，升级窗口内既有键不失效")
                .isEqualTo("sgw:admin:nonce:");
        assertThat(verifier.nonceKeyPrefix(InternalHmacVerifier.NonceScope.SERVICE))
                .isEqualTo("sgw:svc:nonce:");
        assertThat(InternalHmacVerifier.NonceScope.ADMIN.defaultPrefix())
                .isNotEqualTo(InternalHmacVerifier.NonceScope.SERVICE.defaultPrefix());
    }

    @Test
    @DisplayName("nonce 键前缀可配置")
    void configurableNoncePrefixes() {
        SgwProperties properties = new SgwProperties();
        properties.getSecurity().getInternal().setNonceKeyPrefixAdmin("custom:admin:");
        properties.getSecurity().getInternal().setNonceKeyPrefixService("custom:svc:");
        InternalHmacVerifier verifier = new InternalHmacVerifier(properties, null);

        assertThat(verifier.nonceKeyPrefix(InternalHmacVerifier.NonceScope.ADMIN)).isEqualTo("custom:admin:");
        assertThat(verifier.nonceKeyPrefix(InternalHmacVerifier.NonceScope.SERVICE)).isEqualTo("custom:svc:");
    }

    @Test
    @DisplayName("空体 bodyHash 固定为 sha256(\"\")")
    void emptyBodyHash() {
        assertThat(InternalHmacVerifier.EMPTY_BODY_HASH)
                .isEqualTo("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assertThat(InternalHmacVerifier.bodyHash(null)).isEqualTo(InternalHmacVerifier.EMPTY_BODY_HASH);
        assertThat(InternalHmacVerifier.bodyHash(new byte[0])).isEqualTo(InternalHmacVerifier.EMPTY_BODY_HASH);
        assertThat(InternalHmacVerifier.bodyHash("".getBytes(StandardCharsets.UTF_8)))
                .isEqualTo(InternalHmacVerifier.EMPTY_BODY_HASH);
    }

    @Test
    @DisplayName("bodyHash 为原始请求体字节的小写十六进制摘要")
    void nonEmptyBodyHash() {
        assertThat(InternalHmacVerifier.bodyHash("{}".getBytes(StandardCharsets.UTF_8)))
                .isEqualTo(Json.sha256("{}"));
    }

    @Test
    @DisplayName("签名串格式不变：METHOD\\nrawPath\\nbodyHash\\ntimestamp\\nnonce\\nclient")
    void canonicalStringUnchanged() {
        String canonical = "GET\n/api/service/activation/v1/login-ticket\n"
                + InternalHmacVerifier.EMPTY_BODY_HASH + "\n1700000000000\nnonce-1\niov-tsp";
        String signature = InternalHmacVerifier.hmacSha256Hex("secret", canonical);

        assertThat(signature).isEqualTo(InternalHmacVerifier.hmacSha256Hex("secret",
                "GET\n/api/service/activation/v1/login-ticket\n"
                        + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        + "\n1700000000000\nnonce-1\niov-tsp"));
        assertThat(signature).matches("[0-9a-f]{64}");
    }

}
