package net.hwyz.iov.cloud.edd.sgw.application;

import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ServiceOptionVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.UpstreamOptionsResponse;
import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 上游可选项用例。
 *
 * @author hwyz_leo
 */
@Service
public class UpstreamAdminService {

    private final GatewayInstanceProvider gatewayInstanceProvider;

    private final SgwProperties properties;

    public UpstreamAdminService(GatewayInstanceProvider gatewayInstanceProvider, SgwProperties properties) {
        this.gatewayInstanceProvider = gatewayInstanceProvider;
        this.properties = properties;
    }

    /**
     * 注册中心服务与获批直连主机
     *
     * @return 上游可选项
     */
    public UpstreamOptionsResponse options() {
        List<ServiceOptionVo> services = gatewayInstanceProvider.services().stream()
                .sorted()
                .map(serviceId -> ServiceOptionVo.builder()
                        .serviceId(serviceId)
                        .instanceCount(gatewayInstanceProvider.instanceCount(serviceId))
                        .build())
                .toList();
        return UpstreamOptionsResponse.builder()
                .services(services)
                .directHosts(List.copyOf(properties.getRuntime().getDirectUpstreamHosts()))
                .build();
    }

}
