package net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway;

/**
 * Nacos 版本指针（仅包含版本元数据，不包含任何配置内容或密钥）。
 *
 * @param versionNo     目标版本号
 * @param publicationId 发布ID
 * @param checksum      快照校验和
 * @author hwyz_leo
 */
public record PublicationPointer(Long versionNo, String publicationId, String checksum) {
}
