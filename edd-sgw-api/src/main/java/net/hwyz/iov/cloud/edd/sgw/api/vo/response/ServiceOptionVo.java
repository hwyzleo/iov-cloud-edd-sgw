package net.hwyz.iov.cloud.edd.sgw.api.vo.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 可选上游服务。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ServiceOptionVo {

    /** 服务ID */
    private String serviceId;

    /** 实例数 */
    private Integer instanceCount;

}
