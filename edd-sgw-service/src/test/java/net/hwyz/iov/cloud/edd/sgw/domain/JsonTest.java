package net.hwyz.iov.cloud.edd.sgw.domain;

import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteTarget;
import net.hwyz.iov.cloud.edd.sgw.api.enums.RouteTargetType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * JSON 稳定序列化与校验和测试。
 *
 * @author hwyz_leo
 */
class JsonTest {

    @Test
    @DisplayName("同一配置的稳定序列化与摘要一致")
    void canonicalChecksumStable() {
        Map<String, Object> first = Map.of("b", 2, "a", Map.of("y", 1, "x", 0));
        Map<String, Object> second = Map.of("a", Map.of("x", 0, "y", 1), "b", 2);
        assertThat(Json.canonical(first)).isEqualTo(Json.canonical(second));
        assertThat(Json.sha256(Json.canonical(first))).isEqualTo(Json.sha256(Json.canonical(second)));
        assertThat(Json.sha256("x")).hasSize(64);
    }

    @Test
    @DisplayName("JSON 与领域对象可往返转换")
    void roundTrip() {
        RouteTarget target = RouteTarget.builder()
                .type(RouteTargetType.SERVICE)
                .serviceId("edd-vmd-service")
                .build();
        String json = Json.write(target);
        RouteTarget restored = Json.read(json, RouteTarget.class);
        assertThat(restored).isEqualTo(target);
    }

}
