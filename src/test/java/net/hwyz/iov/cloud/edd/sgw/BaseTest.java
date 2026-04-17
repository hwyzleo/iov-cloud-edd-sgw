package net.hwyz.iov.cloud.edd.sgw;

import cn.hutool.json.JSONUtil;
import net.hwyz.iov.cloud.framework.common.constant.CustomHeaders;
import org.junit.jupiter.api.BeforeAll;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ActiveProfiles;

import java.util.HashMap;
import java.util.Map;

@Rollback
@ActiveProfiles("dev")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class BaseTest {

    protected String vin = "HWYZTEST000000001";

    /**
     * 创建Header
     *
     * @return 测试Header
     */
    protected HttpHeaders newHttpHeader() {
        Map<String, Object> map = new HashMap<>(2);
        map.put(CustomHeaders.CLIENT_ID, "clientId");
        map.put("uid", "uid");
        HttpHeaders headers = new HttpHeaders();
        headers.add(CustomHeaders.CLIENT_ID, "clientId");
        return headers;
    }

    @BeforeAll
    protected static void beforeAll() {
        System.setProperty("nacos.logging.default.config.enabled", "false");
    }

    public static void main(String[] args) {

    }

}
