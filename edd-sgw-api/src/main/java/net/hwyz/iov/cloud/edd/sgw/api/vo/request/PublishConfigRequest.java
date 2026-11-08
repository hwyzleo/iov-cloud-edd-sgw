package net.hwyz.iov.cloud.edd.sgw.api.vo.request;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 发布当前草稿修订的请求。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PublishConfigRequest {

    /** 草稿修订号（乐观并发控制） */
    @NotNull(message = "草稿修订号不能为空")
    private Long draftRevision;

    /** 发布说明 */
    private String comment;

}
