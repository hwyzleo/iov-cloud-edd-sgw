package net.hwyz.iov.cloud.edd.sgw.api.vo.response;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

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

    /** 变更前对象完整内容（仅存在于草稿时为 null） */
    private JsonNode before;

    /** 变更后对象完整内容（仅存在于基准版本时为 null） */
    private JsonNode after;

    /** 字段级差异（按 path 字典序，新增与删除对象为空数组） */
    private List<ConfigFieldDiffVo> fields;

}
