package dev.sentinel.approval;

import dev.sentinel.audit.AuditDocument;
import dev.sentinel.audit.AuditHistoryService;
import dev.sentinel.audit.AuditRepository;
import dev.sentinel.config.MongoTransactionConfig;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.mongo.DataMongoTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Runs against a real MongoDB replica set, not mocked repositories.
 * CI explicitly enables this suite after initiating rs0.
 */
@DataMongoTest
@Import({MongoTransactionConfig.class, AuditHistoryService.class, TransactionalApprovalService.class})
@EnabledIfEnvironmentVariable(named = "SENTINEL_MONGO_IT", matches = "true")
class MongoApprovalTransactionIT {
    @Autowired ApprovalRepository approvals;
    @Autowired AuditRepository audits;
    @Autowired MongoTemplate mongo;
    @Autowired PlatformTransactionManager transactionManager;
    @Autowired TransactionalApprovalService service;
    @Autowired AuditHistoryService history;

    @BeforeEach
    void reset() {
        mongo.dropCollection(ApprovalDocument.class);
        mongo.dropCollection(AuditDocument.class);
        mongo.indexOps(AuditDocument.class).ensureIndex(
                new org.springframework.data.mongodb.core.index.Index()
                        .on("tenantId", org.springframework.data.domain.Sort.Direction.ASC)
                        .on("sequence", org.springframework.data.domain.Sort.Direction.ASC)
                        .unique());
    }

    private ApprovalDocument pending(String id) {
        return approvals.save(new ApprovalDocument(new ApprovalWorkflow.Request(
                id, "tenant-integration", "alice", null, "ledger", "Quarterly review",
                ApprovalWorkflow.Status.PENDING, 0, Instant.parse("2026-11-08T10:00:00Z"))));
    }

    @Test
    void approvalAndAuditCommitTogether() {
        var request = pending("approval-success");
        var result = service.transition(request.id,
                new ApprovalWorkflow.Actor("tenant-integration", "bob", true),
                ApprovalWorkflow.Action.APPROVE, request.version);
        assertEquals(ApprovalWorkflow.Status.APPROVED, result.status());
        assertEquals(ApprovalWorkflow.Status.APPROVED,
                approvals.findById(request.id).orElseThrow().status);
        var events = history.verifiedHistory("tenant-integration");
        assertEquals(1, events.size());
        assertEquals("bob", events.getFirst().actorId());
    }

    @Test
    void failedAuditWriteRollsBackApprovalWrite() {
        var request = pending("approval-rollback");
        var transaction = new TransactionTemplate(transactionManager);
        assertThrows(IllegalStateException.class, () -> transaction.execute(status -> {
            var updated = approvals.findById(request.id).orElseThrow();
            updated.status = ApprovalWorkflow.Status.APPROVED;
            approvals.save(updated);
            throw new IllegalStateException("simulated audit storage failure");
        }));
        var reloaded = approvals.findById(request.id).orElseThrow();
        assertEquals(ApprovalWorkflow.Status.PENDING, reloaded.status);
        assertEquals(request.version, reloaded.version);
        assertEquals(0, audits.count());
    }
}
