package dev.sentinel.audit;

import java.time.Instant;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import org.junit.jupiter.api.Test;

class AuditHistoryServiceTest {
    private final AuditRepository repository = mock(AuditRepository.class);
    private final AuditHistoryService service = new AuditHistoryService(repository);
    private final AuditChain chain = new AuditChain();
    private final Instant now = Instant.parse("2026-11-08T09:00:00Z");

    @Test void returnsVerifiedTenantHistory() {
        var first = chain.append("tenant-a", "alice", "REQUEST_CREATED", "req-1", now, List.of());
        var second = chain.append("tenant-a", "bob", "ACCESS_REQUEST_APPROVE",
                "req-1", now.plusSeconds(1), List.of(first));
        when(repository.findByTenantIdOrderBySequenceAsc("tenant-a"))
                .thenReturn(List.of(new AuditDocument(first), new AuditDocument(second)));
        assertEquals(List.of(first, second), service.verifiedHistory("tenant-a"));
    }

    @Test void rejectsForeignTenantRecord() {
        var foreign = chain.append("tenant-b", "alice", "REQUEST_CREATED", "req-1", now, List.of());
        when(repository.findByTenantIdOrderBySequenceAsc("tenant-a"))
                .thenReturn(List.of(new AuditDocument(foreign)));
        assertThrows(SecurityException.class, () -> service.verifiedHistory("tenant-a"));
    }

    @Test void rejectsTamperedEvent() {
        var first = chain.append("tenant-a", "alice", "REQUEST_CREATED", "req-1", now, List.of());
        var tampered = new AuditDocument(first);
        tampered.action = "ACCESS_REQUEST_APPROVE";
        when(repository.findByTenantIdOrderBySequenceAsc("tenant-a"))
                .thenReturn(List.of(tampered));
        assertThrows(IllegalStateException.class, () -> service.verifiedHistory("tenant-a"));
    }

    @Test void rejectsMissingSequence() {
        var first = chain.append("tenant-a", "alice", "REQUEST_CREATED", "req-1", now, List.of());
        var second = chain.append("tenant-a", "bob", "ACCESS_REQUEST_APPROVE",
                "req-1", now.plusSeconds(1), List.of(first));
        when(repository.findByTenantIdOrderBySequenceAsc("tenant-a"))
                .thenReturn(List.of(new AuditDocument(second)));
        assertThrows(IllegalStateException.class, () -> service.verifiedHistory("tenant-a"));
    }

    @Test void rejectsMissingTenant() {
        assertThrows(IllegalArgumentException.class, () -> service.verifiedHistory(" "));
        verifyNoInteractions(repository);
    }
}
