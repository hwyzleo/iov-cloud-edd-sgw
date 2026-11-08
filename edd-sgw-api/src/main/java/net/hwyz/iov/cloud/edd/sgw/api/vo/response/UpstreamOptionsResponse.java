package net.hwyz.iov.cloud.edd.sgw.api.vo.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * 上游可选项：注册中心服务与获批直连主机。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpstreamOptionsResponse {

    /** 注册中心服务 */
    private List<ServiceOptionVo> services;

    /** 获批的内部直连主机 */
    private List<String> directHosts;

}
