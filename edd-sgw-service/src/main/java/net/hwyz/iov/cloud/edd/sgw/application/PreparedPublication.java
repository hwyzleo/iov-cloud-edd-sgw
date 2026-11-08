package net.hwyz.iov.cloud.edd.sgw.application;

/**
 * 事务内已创建的发布记录，事务提交后需要分发版本指针。
 *
 * @param publicationId 发布ID
 * @param versionNo     目标版本号
 * @param checksum      快照校验和
 * @param type          发布类型
 * @param sourceVersionNo 来源版本号
 * @author hwyz_leo
 */
public record PreparedPublication(String publicationId, Long versionNo, String checksum, String type,
                                  Long sourceVersionNo) {
}
