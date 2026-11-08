package net.hwyz.iov.cloud.edd.sgw.security;

import io.jsonwebtoken.Jwts;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.AuthenticatedIdentity;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.security.CiamTokenVerifier;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.security.JwksKeyStore;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * CIAM 令牌本地验签测试（使用本地 JWKS 服务）。
 *
 * @author hwyz_leo
 */
class CiamTokenVerifierTest {

    private static final String ISSUER = "https://issuer.test";

    private static final String KID = "kid-1";

    private static DisposableServer jwksServer;

    private static KeyPair keyPair;

    private static int jwksPort;

    @BeforeAll
    static void startJwksServer() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("kid", KID);
        jwk.put("alg", "RS256");
        jwk.put("n", base64Url(publicKey.getModulus()));
        jwk.put("e", base64Url(publicKey.getPublicExponent()));
        String body = Json.write(Map.of("data", Map.of("keys", java.util.List.of(jwk))));
        jwksServer = HttpServer.create()
                .port(0)
                .handle((request, response) -> response
                        .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                        .sendString(Mono.just(body)))
                .bindNow();
        jwksPort = jwksServer.port();
    }

    @AfterAll
    static void stopJwksServer() {
        if (jwksServer != null) {
            jwksServer.disposeNow();
        }
    }

    @Test
    @DisplayName("有效令牌建立认证身份")
    void validToken() {
        AuthenticatedIdentity identity = verifier().verify(token(baseClaims("MOBILE", "VIN1"), new Date(System.currentTimeMillis() + 60_000)))
                .block();
        assertThat(identity).isNotNull();
        assertThat(identity.subject()).isEqualTo("user-1");
        assertThat(identity.clientType()).isEqualTo("MOBILE");
        assertThat(identity.scopes()).contains("vehicle.read", "perm:edd:vehicle:read");
        assertThat(identity.vehicleId()).isEqualTo("VIN1");
    }

    @Test
    @DisplayName("错误签发者、过期令牌与缺失声明均被拒绝")
    void invalidTokens() {
        Map<String, Object> wrongIssuer = baseClaims("MOBILE", "VIN1");
        String wrongIssuerToken = Jwts.builder()
                .header().keyId(KID).and()
                .claims(wrongIssuer)
                .issuer("https://evil.test")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
                .compact();
        assertThatThrownBy(() -> verifier().verify(wrongIssuerToken).block())
                .isInstanceOf(SgwException.class);

        assertThatThrownBy(() -> verifier().verify(token(baseClaims("MOBILE", "VIN1"),
                new Date(System.currentTimeMillis() - 60_000))).block())
                .isInstanceOf(SgwException.class);

        Map<String, Object> missingDevice = baseClaims("MOBILE", "VIN1");
        missingDevice.remove("device_id");
        assertThatThrownBy(() -> verifier().verify(token(missingDevice,
                new Date(System.currentTimeMillis() + 60_000))).block())
                .isInstanceOf(SgwException.class);
    }

    @Test
    @DisplayName("车辆会话缺少车辆标识时被拒绝")
    void vehicleClaimRequired() {
        assertThatThrownBy(() -> verifier().verify(token(baseClaims("TBOX", null),
                new Date(System.currentTimeMillis() + 60_000))).block())
                .isInstanceOf(SgwException.class);
    }

    @Test
    @DisplayName("未知签名密钥被拒绝")
    void unknownKid() {
        String token = Jwts.builder()
                .header().keyId("unknown-kid").and()
                .claims(baseClaims("MOBILE", "VIN1"))
                .issuer(ISSUER)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
                .compact();
        assertThatThrownBy(() -> verifier().verify(token).block())
                .isInstanceOf(SgwException.class);
    }

    private CiamTokenVerifier verifier() {
        SgwProperties properties = new SgwProperties();
        properties.getSecurity().getCiam().setIssuer(ISSUER);
        properties.getSecurity().getCiam().setJwksUri("http://127.0.0.1:" + jwksPort + "/jwks");
        properties.getSecurity().getCiam().setClockSkewSeconds(0);
        JwksKeyStore keyStore = new JwksKeyStore(properties, null);
        return new CiamTokenVerifier(properties, keyStore);
    }

    private Map<String, Object> baseClaims(String clientType, String vehicleId) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", "user-1");
        claims.put("client_id", "client-1");
        claims.put("client_type", clientType);
        claims.put("device_id", "device-1");
        claims.put("session_id", "session-1");
        claims.put("scope", "vehicle.read perm:edd:vehicle:read");
        if (vehicleId != null) {
            claims.put("vehicle_id", vehicleId);
        }
        return claims;
    }

    private String token(Map<String, Object> claims, Date expiration) {
        return Jwts.builder()
                .header().keyId(KID).and()
                .claims(claims)
                .issuer(ISSUER)
                .issuedAt(new Date())
                .expiration(expiration)
                .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
                .compact();
    }

    private static String base64Url(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

}
