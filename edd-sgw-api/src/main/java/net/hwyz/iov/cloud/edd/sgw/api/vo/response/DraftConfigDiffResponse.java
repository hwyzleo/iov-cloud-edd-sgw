package net.hwyz.iov.cloud.edd.sgw.api.vo.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * 待发布配置变更预览。
 * <p>
 * 基准版本为工作区 {@code target_version_no} 指向的发布版本，草稿修订号与基准快照在同一只读一致视图内读取。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DraftConfigDiffResponse {

    /** 基准版本号，首次发布前为 null */
    private Long baseVersionNo;

    /** 参与比较的草稿修订号 */
    private Long draftRevision;

    /** 差异项 */
    private List<ConfigDiffItemVo> items;

}
