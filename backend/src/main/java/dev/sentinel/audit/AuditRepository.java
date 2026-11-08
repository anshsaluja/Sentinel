package dev.sentinel.audit;

import java.util.List;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * Always scope reads to tenant ID. Do not expose unscoped audit history
 * through API controllers or authorization decisions.
 */
public interface AuditRepository extends MongoRepository<AuditDocument, String> {
    List<AuditDocument> findByTenantIdOrderBySequenceAsc(String tenantId);
}
