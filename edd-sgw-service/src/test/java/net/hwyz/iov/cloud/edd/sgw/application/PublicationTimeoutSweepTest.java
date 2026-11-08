package net.hwyz.iov.cloud.edd.sgw.application;

import net.hwyz.iov.cloud.edd.sgw.api.enums.PublicationStatus;
import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
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

import java.util.Date;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * 发布超时扫描测试。
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
class PublicationTimeoutSweepTest {

    @Mock
    private PublishTransactionService publishTransactionService;

    @Mock
    private PublicationDispatcher publicationDispatcher;

    @Mock
    private PublicationRepository publicationRepository;

    @Mock
    private InstancePublicationRepository instancePublicationRepository;

    @Mock
    private PublicationAggregator publicationAggregator;

    private PublicationService publicationService;

    @BeforeEach
    void setUp() {
        publicationService = new PublicationService(publishTransactionService, publicationDispatcher,
                publicationRepository, instancePublicationRepository, publicationAggregator,
                new SgwProperties());
    }

    @Test
    @DisplayName("超时未确认的实例结果被标记并重新聚合")
    void marksPendingInstancesAndRecomputes() {
        InstancePublicationPo pending = InstancePublicationPo.builder()
                .id(1L).publicationId("pub-1").instanceId("a").status("PENDING").build();
        when(instancePublicationRepository.findPendingOlderThan(any(Date.class), anyInt()))
                .thenReturn(List.of(pending));
        when(publicationRepository.findActiveOlderThan(any(Date.class))).thenReturn(List.of());

        publicationService.sweepTimeouts();

        verify(instancePublicationRepository).markTimeout(1L);
        verify(publicationAggregator).recompute("pub-1");
    }

    @Test
    @DisplayName("无实例确认的发布在超时后标记失败")
    void failsPublicationWithoutInstances() {
        PublicationPo publication = PublicationPo.builder()
                .publicationId("pub-2").targetVersionNo(3L).status("WAITING_ACK").build();
        when(instancePublicationRepository.findPendingOlderThan(any(Date.class), anyInt()))
                .thenReturn(List.of());
        when(publicationRepository.findActiveOlderThan(any(Date.class))).thenReturn(List.of(publication));
        when(instancePublicationRepository.findByPublicationId("pub-2")).thenReturn(List.of());

        publicationService.sweepTimeouts();

        verify(publicationRepository).updateStatus(eq("pub-2"), eq(PublicationStatus.FAILED),
                eq("实例未在发布时限内确认"), any(Date.class));
    }

}
