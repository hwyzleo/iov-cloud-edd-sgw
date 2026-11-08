package net.hwyz.iov.cloud.edd.sgw.common;

import java.util.List;

/**
 * 数据库物理分页结果。
 *
 * @param items 当前页数据
 * @param total 总记录数
 * @param page  页码
 * @param size  每页条数
 * @param <T>   数据类型
 * @author hwyz_leo
 */
public record PageSlice<T>(List<T> items, long total, int page, int size) {
}
