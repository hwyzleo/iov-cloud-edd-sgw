package net.hwyz.iov.cloud.edd.sgw.api.vo.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * 配置版本差异。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ConfigDiffResponse {

    /** 起始版本 */
    private Long fromVersionNo;

    /** 目标版本 */
    private Long toVersionNo;

    /** 差异项 */
    private List<ConfigDiffItemVo> items;

}
