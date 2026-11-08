package dev.sentinel.approval;

import java.util.List;
import java.util.Optional;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface ApprovalRepository extends MongoRepository<ApprovalDocument, String> {
    Optional<ApprovalDocument> findByIdAndTenantId(String id, String tenantId);
    List<ApprovalDocument> findByTenantIdAndStatusOrderByUpdatedAtDesc(
            String tenantId, ApprovalWorkflow.Status status);
}
