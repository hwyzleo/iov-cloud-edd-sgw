package net.hwyz.iov.cloud.edd.sgw.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 路径重写规则。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RewritePathVo {

    /** 路径正则 */
    private String pattern;

    /** 替换表达式，支持命名分组 ${name} */
    private String replacement;

}
