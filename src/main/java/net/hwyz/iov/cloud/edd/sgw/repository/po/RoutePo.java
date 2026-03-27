package net.hwyz.iov.cloud.edd.sgw.repository.po;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import net.hwyz.iov.cloud.framework.mysql.po.BasePo;

/**
 * <p>
 * 路由表 数据对象
 * </p>
 *
 * @author hwyz_leo
 * @since 2024-10-08
 */
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@TableName("tb_route")
public class RoutePo extends BasePo {

    private static final long serialVersionUID = 1L;

    /**
     * 主键
     */
    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    /**
     * 断言集合
     */
    @TableField("predicates")
    private String predicates;

    /**
     * 过滤器集合
     */
    @TableField("filters")
    private String filters;

    /**
     * 目标类型
     */
    @TableField("target_type")
    private String targetType;

    /**
     * 目标URI
     */
    @TableField("target_uri")
    private String targetUri;

    /**
     * 排序
     */
    @TableField("sort")
    private Integer sort;
}
