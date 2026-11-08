package net.hwyz.iov.cloud.edd.sgw.api.vo.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 配置差异项。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ConfigDiffItemVo {

    /** 对象类型：ROUTE、AUTH_POLICY、TRAFFIC_POLICY、CANARY_POLICY */
    private String objectType;

    /** 对象编码 */
    private String code;

    /** 变化类型：ADDED、MODIFIED、REMOVED */
    private String changeType;

}
