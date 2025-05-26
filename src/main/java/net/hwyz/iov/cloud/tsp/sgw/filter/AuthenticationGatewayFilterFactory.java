package net.hwyz.iov.cloud.tsp.sgw.filter;

import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.common.enums.ClientType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;

import static net.hwyz.iov.cloud.framework.common.enums.CustomHeaders.*;


/**
 * 身份认证网关过滤器
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class AuthenticationGatewayFilterFactory extends AbstractGatewayFilterFactory<AuthenticationGatewayFilterFactory.Config> {

    @Autowired
    @LoadBalanced
    private WebClient.Builder webClientBuilder;

    public AuthenticationGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String clientType = exchange.getRequest().getHeaders().getFirst(CLIENT_TYPE.value);
            String clientId = exchange.getRequest().getHeaders().getFirst(CLIENT_ID.value);
            if (StrUtil.isBlank(clientType) || StrUtil.isBlank(clientId)) {
                logger.warn("缺失客户端类型[{}]或客户端ID[{}]", clientType, clientId);
                exchange.getResponse().getHeaders().add("Content-Type", "application/json");
                return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                        .bufferFactory().wrap(new JSONObject()
                                .set("code", 100000)
                                .set("message", "缺失客户端类型或客户端ID")
                                .set("ts", System.currentTimeMillis())
                                .toString().getBytes())));
            }
            switch (ClientType.valueOf(clientType)) {
                case MP -> {
                    String token = exchange.getRequest().getHeaders().getFirst(TOKEN.value);
                    if (StrUtil.isBlank(token)) {
                        logger.warn("手机客户端[{}]缺失客户端令牌[{}]", clientId, token);
                        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
                        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                                .bufferFactory().wrap(new JSONObject()
                                        .set("code", 100000)
                                        .set("message", "缺失客户端令牌")
                                        .set("ts", System.currentTimeMillis())
                                        .toString().getBytes())));
                    }
                    Mono<JSONObject> responseMono = webClientBuilder.build()
                            .post().uri("lb://tsp-account/service/token/authenticateMp")
                            .bodyValue(new JSONObject().set(TOKEN.value, token).set(CLIENT_ID.value, clientId))
                            .retrieve()
                            .bodyToMono(JSONObject.class);
                    return responseMono.flatMap(response -> {
                        if (response.size() == 0) {
                            logger.warn("设备[{}]令牌[{}]无效", clientId, token);
                            exchange.getResponse().getHeaders().add("Content-Type", "application/json");
                            return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                                    .bufferFactory().wrap(new JSONObject()
                                            .set("code", 100000)
                                            .set("message", "设备令牌无效")
                                            .set("ts", System.currentTimeMillis())
                                            .toString().getBytes())));
                        }
                        ServerHttpRequest request = exchange.getRequest().mutate().header(CLIENT_ACCOUNT.value, response.toString()).build();
                        return chain.filter(exchange.mutate().request(request).build());
                    });
                }
                case TBOX -> {
                    String vin = exchange.getRequest().getHeaders().getFirst(VIN.value);
                    if (StrUtil.isBlank(vin)) {
                        logger.warn("车联终端[{}]缺失车架号[{}]", clientId, vin);
                        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
                        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                                .bufferFactory().wrap(new JSONObject()
                                        .set("code", 100000)
                                        .set("message", "缺失车架号")
                                        .set("ts", System.currentTimeMillis())
                                        .toString().getBytes())));
                    }
                    return chain.filter(exchange);
                }
            }
            logger.warn("未知客户端类型[{}]", clientType);
            exchange.getResponse().getHeaders().add("Content-Type", "application/json");
            return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                    .bufferFactory().wrap(new JSONObject()
                            .set("code", 100000)
                            .set("message", "未知客户端类型")
                            .set("ts", System.currentTimeMillis())
                            .toString().getBytes())));
        };
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return List.of();
    }

    @Data
    @NoArgsConstructor
    public static class Config {
    }

}
