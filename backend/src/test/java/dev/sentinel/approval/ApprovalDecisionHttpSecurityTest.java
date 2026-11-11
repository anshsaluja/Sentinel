package dev.sentinel.approval;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.sentinel.security.SecurityConfiguration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/** Exercise the real HTTP security filter chain, not only controller methods. */
@WebMvcTest(ApprovalApiController.class)
@Import(SecurityConfiguration.class)
class ApprovalDecisionHttpSecurityTest {
    @Autowired MockMvc mvc;
    @MockitoBean ApprovalPersistenceService approvals;
    @MockitoBean TransactionalApprovalService transitions;
    @MockitoBean JwtDecoder jwtDecoder;

    private static final String PATH = "/api/v1/approvals/req-1/decision";
    private static final String BODY = "{\"action\":\"APPROVE\",\"expectedVersion\":0}";

    @Test
    void anonymousDecisionIsRejectedBySecurityFilter() throws Exception {
        mvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isUnauthorized());
        verifyNoInteractions(transitions);
    }

    @Test
    void ordinaryUserCannotDecideEvenWithValidToken() throws Exception {
        mvc.perform(post(PATH).with(jwt().jwt(token -> token
                        .subject("ordinary").claim("tenant_id", "team-a")))
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isForbidden());
        verifyNoInteractions(transitions);
    }

    @Test
    void anonymousCannotReadApprovalQueue() throws Exception {
        mvc.perform(get("/api/v1/approvals/pending"))
                .andExpect(status().isUnauthorized());
        verifyNoInteractions(approvals);
    }

    @Test
    void ordinaryUserCannotReadApprovalQueue() throws Exception {
        mvc.perform(get("/api/v1/approvals/pending").with(jwt().jwt(token -> token
                        .subject("ordinary").claim("tenant_id", "team-a"))))
                .andExpect(status().isForbidden());
        verifyNoInteractions(approvals);
    }

    @Test
    void reviewerCanReadOwnTenantQueue() throws Exception {
        mvc.perform(get("/api/v1/approvals/pending").with(jwt().jwt(token -> token
                        .subject("reviewer").claim("tenant_id", "team-a")
                        .claim("realm_access", Map.of("roles", List.of("sentinel-reviewer"))))))
                .andExpect(status().isOk());
        verify(approvals).pending("team-a");
    }

    @Test
    void anonymousCannotReadApprovalDetails() throws Exception {
        mvc.perform(get("/api/v1/approvals/req-1"))
                .andExpect(status().isUnauthorized());
        verifyNoInteractions(approvals);
    }

    @Test
    void ordinaryUserCannotReadApprovalDetails() throws Exception {
        mvc.perform(get("/api/v1/approvals/req-1").with(jwt().jwt(token -> token
                        .subject("ordinary").claim("tenant_id", "team-a"))))
                .andExpect(status().isForbidden());
        verifyNoInteractions(approvals);
    }

    @Test
    void reviewerDetailLookupIsScopedToTokenTenant() throws Exception {
        mvc.perform(get("/api/v1/approvals/req-1").with(jwt().jwt(token -> token
                        .subject("reviewer").claim("tenant_id", "team-a")
                        .claim("realm_access", Map.of("roles", List.of("sentinel-reviewer"))))))
                .andExpect(status().isOk());
        verify(approvals).find("team-a", "req-1");
    }

    @Test
    void angularPreflightCanReadApprovalQueue() throws Exception {
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options(
                        "/api/v1/approvals/pending")
                        .header("Origin", "http://localhost:4200")
                        .header("Access-Control-Request-Method", "GET")
                        .header("Access-Control-Request-Headers", "authorization"))
                .andExpect(status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .header().string("Access-Control-Allow-Origin", "http://localhost:4200"));
        verifyNoInteractions(approvals);
    }

    @Test
    void reviewerDecisionReachesTransactionalServiceThroughFilterChain() throws Exception {
        mvc.perform(post(PATH).with(jwt().jwt(token -> token
                        .subject("reviewer").claim("tenant_id", "team-a")
                        .claim("realm_access", Map.of("roles", List.of("sentinel-reviewer")))))
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isOk());
        verify(transitions).transition(eq("req-1"),
                eq(new ApprovalWorkflow.Actor("team-a", "reviewer", true)),
                eq(ApprovalWorkflow.Action.APPROVE), eq(0L));
    }
}
