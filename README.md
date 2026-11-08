# Sentinel — Access Risk & Policy Simulation

Focused portfolio project for explaining and predicting access changes, not a full identity management product.

## Implemented (source committed; CI verification pending)

- Pure Java deny-by-default RBAC + attribute-equality ABAC evaluator with explicit-deny precedence.
- Read-only, deterministic before/after policy simulation.
- Risk finding engine and associated unit tests (see backend sources).
- Spring Boot REST preview endpoints protected by JWT resource-server authentication.
- API derives tenant context from the verified JWT `tenant_id` claim; mismatched tenant inputs are rejected.
- JUnit unit tests and MockMvc authentication/tenant-isolation test source.

**Security boundary:** Both preview endpoints currently accept policy rules supplied by the caller. They are **not authorization enforcement endpoints** and MUST NOT be used to authorize real access. The tenant claim must be issued by a trusted Keycloak realm, not an untrusted caller. Future production enforcement will load policies from tenant-scoped MongoDB persistence.

## Local backend setup

Requires Java 21, Maven, and a running OIDC issuer such as Keycloak.

1. Configure a Keycloak realm with issuer URI and a trusted client; include a verified `tenant_id` claim in access tokens.
2. Export `SENTINEL_OIDC_ISSUER_URI` to the issuer URL (default: `http://localhost:8081/realms/sentinel`).
3. In `backend/`, run `mvn verify` then `mvn spring-boot:run`.
4. POST `/api/v1/policies/evaluate` or `/api/v1/policies/simulate` with `Authorization: Bearer <access-token>`. There are no anonymous demo endpoints.

### Evaluation example

```json
{
  "request": {"tenantId":"alpha","resourceId":"ledger","action":"read","roles":["analyst"],"attributes":{"department":"finance"}},
  "rules": [{"tenantId":"alpha","resourceId":"ledger","action":"read","roles":["analyst"],"attributes":{"department":"finance"},"effect":"ALLOW"}]
}
```

For simulation, send `{"subjects":[{"userId":"alice","request":{...}}],"before":[...],"after":[...]}`, where all tenant IDs equal the authenticated token's `tenant_id`.

## Roadmap

- MongoDB-backed tenant-scoped identity/resource/policy repository and trusted rule loading.
- Keycloak local Docker Compose with realm bootstrap and verified token issuance.
- Access risk explanations, approvals and immutable audit trail.
- Polished Angular dashboard and guided policy simulator.
- Integration/security tests, CI green, documented local demo.

## Status and safeguards

Do not claim CI green until the GitHub Actions workflow has actually passed. No secrets committed; no public deployment or paid services. Elasticsearch and gRPC are deferred unless real requirements justify their complexity.
