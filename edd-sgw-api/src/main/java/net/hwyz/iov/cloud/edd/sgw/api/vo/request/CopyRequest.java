package net.hwyz.iov.cloud.edd.sgw.api.vo.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 复制路由或策略的请求。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CopyRequest {

    /** 新编码 */
    @NotBlank(message = "新编码不能为空")
    private String newCode;

    /** 新名称 */
    private String newName;

}
