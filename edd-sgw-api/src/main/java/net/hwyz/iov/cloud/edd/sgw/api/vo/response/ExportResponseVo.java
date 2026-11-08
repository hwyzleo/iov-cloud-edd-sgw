package net.hwyz.iov.cloud.edd.sgw.api.vo.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * 配置导出结果（结构化 JSON，不含密钥）。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ExportResponseVo {

    /** 导出类型 */
    private String type;

    /** 生成时间 */
    private Instant generatedAt;

    /** 结构化 JSON 内容 */
    private String content;

}
