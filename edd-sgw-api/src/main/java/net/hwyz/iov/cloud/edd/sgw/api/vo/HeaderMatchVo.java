package net.hwyz.iov.cloud.edd.sgw.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.edd.sgw.api.enums.MatchType;

/**
 * 请求头匹配条件。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class HeaderMatchVo {

    /** 请求头名称 */
    private String name;

    /** 匹配方式 */
    private MatchType matchType;

    /** 匹配值 */
    private String value;

}
