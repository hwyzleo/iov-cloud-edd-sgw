package net.hwyz.iov.cloud.edd.sgw.api.vo.request;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 回滚请求。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RollbackRequest {

    /** 草稿修订号（乐观并发控制） */
    @NotNull(message = "草稿修订号不能为空")
    private Long draftRevision;

    /** 回滚说明 */
    private String comment;

}
