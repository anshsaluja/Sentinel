package dev.sentinel.approval;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.dao.OptimisticLockingFailureException;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class ApprovalPersistenceServiceTest {
    private final ApprovalRepository repository = mock(ApprovalRepository.class);
    private final Instant now = Instant.parse("2026-11-08T08:00:00Z");
    private final ApprovalPersistenceService service = new ApprovalPersistenceService(
            repository, Clock.fixed(now, ZoneOffset.UTC));

    private ApprovalDocument pending() {
        return new ApprovalDocument(new ApprovalWorkflow.Request("req-1", "tenant-a",
                "requester", null, "finance", "Quarterly review",
                ApprovalWorkflow.Status.PENDING, 3,
                Instant.parse("2026-11-07T08:00:00Z")));
    }

    @Test void lookupIsScopedByTenant() {
        when(repository.findByIdAndTenantId("req-1", "tenant-a"))
                .thenReturn(Optional.of(pending()));
        assertEquals("req-1", service.find("tenant-a", "req-1").id());
        verify(repository).findByIdAndTenantId("req-1", "tenant-a");
    }

    @Test void missingTenantRecordCannotBeRead() {
        when(repository.findByIdAndTenantId("req-1", "tenant-b"))
                .thenReturn(Optional.empty());
        assertThrows(IllegalArgumentException.class, () -> service.find("tenant-b", "req-1"));
    }

    @Test void rejectsUnexpectedForeignTenantRecord() {
        when(repository.findByIdAndTenantId("req-1", "tenant-b"))
                .thenReturn(Optional.of(pending()));
        assertThrows(SecurityException.class, () -> service.find("tenant-b", "req-1"));
    }

    @Test void pendingListingRejectsForeignTenantRecord() {
        when(repository.findByTenantIdAndStatusOrderByUpdatedAtDesc(
                "tenant-b", ApprovalWorkflow.Status.PENDING))
                .thenReturn(List.of(pending()));
        assertThrows(SecurityException.class, () -> service.pending("tenant-b"));
    }

    @Test void transitionUsesDatabaseVersionForOptimisticLock() {
        when(repository.findByIdAndTenantId("req-1", "tenant-a"))
                .thenReturn(Optional.of(pending()));
        when(repository.save(any(ApprovalDocument.class))).thenAnswer(invocation -> {
            ApprovalDocument saved = invocation.getArgument(0);
            assertEquals(3L, saved.version);
            assertEquals(ApprovalWorkflow.Status.APPROVED, saved.status);
            assertEquals("reviewer", saved.approverId);
            saved.version = 4L;
            return saved;
        });
        var result = service.transition("req-1",
                new ApprovalWorkflow.Actor("tenant-a", "reviewer", true),
                ApprovalWorkflow.Action.APPROVE, 3);
        assertEquals(4, result.version());
        assertEquals(ApprovalWorkflow.Status.APPROVED, result.status());
    }

    @Test void staleVersionCannotWrite() {
        when(repository.findByIdAndTenantId("req-1", "tenant-a"))
                .thenReturn(Optional.of(pending()));
        assertThrows(IllegalStateException.class, () -> service.transition("req-1",
                new ApprovalWorkflow.Actor("tenant-a", "reviewer", true),
                ApprovalWorkflow.Action.APPROVE, 2));
        verify(repository, never()).save(any());
    }

    @Test void selfApprovalCannotWrite() {
        when(repository.findByIdAndTenantId("req-1", "tenant-a"))
                .thenReturn(Optional.of(pending()));
        assertThrows(SecurityException.class, () -> service.transition("req-1",
                new ApprovalWorkflow.Actor("tenant-a", "requester", true),
                ApprovalWorkflow.Action.APPROVE, 3));
        verify(repository, never()).save(any());
    }

    @Test void concurrentWriteConflictIsReported() {
        when(repository.findByIdAndTenantId("req-1", "tenant-a"))
                .thenReturn(Optional.of(pending()));
        when(repository.save(any(ApprovalDocument.class)))
                .thenThrow(new OptimisticLockingFailureException("conflict"));
        assertThrows(IllegalStateException.class, () -> service.transition("req-1",
                new ApprovalWorkflow.Actor("tenant-a", "reviewer", true),
                ApprovalWorkflow.Action.APPROVE, 3));
    }
}
