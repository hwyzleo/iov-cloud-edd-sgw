package net.hwyz.iov.cloud.edd.sgw.gateway;

import net.hwyz.iov.cloud.edd.sgw.api.enums.PublicationStatus;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.gateway.PublicationAggregator;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.InstancePublicationPo;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.PublicationPo;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.InstancePublicationRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.PublicationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * 发布状态聚合测试。
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
class PublicationAggregatorTest {

    @Mock
    private PublicationRepository publicationRepository;

    @Mock
    private InstancePublicationRepository instancePublicationRepository;

    private PublicationAggregator aggregator;

    @BeforeEach
    void setUp() {
        aggregator = new PublicationAggregator(publicationRepository, instancePublicationRepository);
    }

    @Test
    @DisplayName("存在待确认实例时保持等待确认")
    void pending() {
        givenPublication("WAITING_ACK");
        when(instancePublicationRepository.findByPublicationId("p1"))
                .thenReturn(List.of(instance("a", "PENDING")));
        assertThat(aggregator.recompute("p1")).isEqualTo(PublicationStatus.WAITING_ACK);
        verify(publicationRepository, never()).updateStatus(eq("p1"), any(), any(), any());
    }

    @Test
    @DisplayName("全部实例成功则发布成功")
    void allSucceeded() {
        givenPublication("WAITING_ACK");
        when(instancePublicationRepository.findByPublicationId("p1"))
                .thenReturn(List.of(instance("a", "SUCCEEDED"), instance("b", "SUCCEEDED")));
        assertThat(aggregator.recompute("p1")).isEqualTo(PublicationStatus.SUCCEEDED);
        verify(publicationRepository).updateStatus(eq("p1"), eq(PublicationStatus.SUCCEEDED), eq(null), any());
    }

    @Test
    @DisplayName("部分失败与全部失败可区分")
    void partialAndFailed() {
        givenPublication("WAITING_ACK");
        when(instancePublicationRepository.findByPublicationId("p1"))
                .thenReturn(List.of(instance("a", "SUCCEEDED"), instance("b", "FAILED")));
        assertThat(aggregator.recompute("p1")).isEqualTo(PublicationStatus.PARTIAL_FAILED);

        when(instancePublicationRepository.findByPublicationId("p2"))
                .thenReturn(List.of(instance("a", "TIMEOUT")));
        when(publicationRepository.findByPublicationId("p2")).thenReturn(Optional.of(
                PublicationPo.builder().publicationId("p2").status("WAITING_ACK").build()));
        assertThat(aggregator.recompute("p2")).isEqualTo(PublicationStatus.FAILED);
    }

    @Test
    @DisplayName("终态发布不再重复聚合")
    void terminal() {
        givenPublication("SUCCEEDED");
        assertThat(aggregator.recompute("p1")).isEqualTo(PublicationStatus.SUCCEEDED);
        verify(instancePublicationRepository, never()).findByPublicationId("p1");
    }

    private void givenPublication(String status) {
        when(publicationRepository.findByPublicationId("p1")).thenReturn(Optional.of(
                PublicationPo.builder().publicationId("p1").status(status).build()));
    }

    private InstancePublicationPo instance(String instanceId, String status) {
        return InstancePublicationPo.builder().publicationId("p1").instanceId(instanceId).status(status).build();
    }

}
