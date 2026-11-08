package net.hwyz.iov.cloud.edd.sgw.api.vo.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 重试发布请求。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RetryPublicationRequest {

    /** 需要重试的发布ID */
    @NotBlank(message = "发布ID不能为空")
    private String publicationId;

}
