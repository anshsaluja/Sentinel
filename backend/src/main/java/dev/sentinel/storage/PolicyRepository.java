package dev.sentinel.storage;

import org.springframework.data.mongodb.repository.MongoRepository;
import java.util.List;
import java.util.Optional;

/** All application queries must include the authenticated tenant ID. */
public interface PolicyRepository extends MongoRepository<StoredPolicy, String> {
    List<StoredPolicy> findByTenantIdAndEnabledTrue(String tenantId);
    List<StoredPolicy> findByTenantIdAndResourceIdAndActionAndEnabledTrue(
            String tenantId, String resourceId, String action);
    Optional<StoredPolicy> findByTenantIdAndPolicyId(String tenantId, String policyId);
    boolean existsByTenantIdAndPolicyId(String tenantId, String policyId);
}
