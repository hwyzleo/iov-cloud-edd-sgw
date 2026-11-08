package net.hwyz.iov.cloud.edd.sgw.api.vo.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 配置工作区状态。
 * <p>
 * MPT 在发布或回滚前需要携带当前草稿修订号，用于乐观并发控制。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WorkspaceResponse {

    /** 当前草稿修订号 */
    private Long draftRevision;

    /** 当前目标版本号 */
    private Long targetVersionNo;

    /** 工作区记录版本 */
    private Integer rowVersion;

}
