package net.hwyz.iov.cloud.edd.sgw.api.vo.response;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 配置对象字段级差异。
 * <p>
 * 字段路径使用 JSON Pointer（RFC 6901），用于解释同一对象内部的具体变化。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ConfigFieldDiffVo {

    /** 字段路径，JSON Pointer，例如 /target/serviceId、/match/paths/0 */
    private String path;

    /** 变化类型：ADDED、MODIFIED、REMOVED */
    private String changeType;

    /** 变更前值（字段仅存在于草稿时为 null） */
    private JsonNode beforeValue;

    /** 变更后值（字段仅存在于基准版本时为 null） */
    private JsonNode afterValue;

}
