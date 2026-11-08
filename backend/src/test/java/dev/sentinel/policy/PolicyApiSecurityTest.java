package dev.sentinel.policy;

import dev.sentinel.SentinelApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(classes = SentinelApplication.class)
@AutoConfigureMockMvc
class PolicyApiSecurityTest {
    @Autowired MockMvc mvc;
    private static final String ALLOW = """
        {"request":{"tenantId":"alpha","resourceId":"ledger","action":"read",
        "roles":["analyst"],"attributes":{}},"rules":[{"tenantId":"alpha",
        "resourceId":"ledger","action":"read","roles":["analyst"],
        "attributes":{},"effect":"ALLOW"}]}
        """;

    @Test void anonymousRequestsAreRejected() throws Exception {
        mvc.perform(post("/api/v1/policies/evaluate")
                .contentType(MediaType.APPLICATION_JSON).content(ALLOW))
                .andExpect(status().isUnauthorized());
    }

    @Test void authenticatedTenantCanEvaluateMatchingRule() throws Exception {
        mvc.perform(post("/api/v1/policies/evaluate").with(jwt().jwt(j -> j.claim("tenant_id", "alpha")))
                .contentType(MediaType.APPLICATION_JSON).content(ALLOW))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(true));
    }

    @Test void callerCannotEvaluateAnotherTenantsRules() throws Exception {
        mvc.perform(post("/api/v1/policies/evaluate").with(jwt().jwt(j -> j.claim("tenant_id", "beta")))
                .contentType(MediaType.APPLICATION_JSON).content(ALLOW))
                .andExpect(status().isForbidden());
    }

    @Test void missingTenantClaimIsForbidden() throws Exception {
        mvc.perform(post("/api/v1/policies/evaluate").with(jwt())
                .contentType(MediaType.APPLICATION_JSON).content(ALLOW))
                .andExpect(status().isForbidden());
    }

    @Test void anonymousSimulationIsRejected() throws Exception {
        mvc.perform(post("/api/v1/policies/simulate").contentType(MediaType.APPLICATION_JSON)
                .content("{\"subjects\":[],\"before\":[],\"after\":[]}"))
                .andExpect(status().isUnauthorized());
    }

    @Test void crossTenantSimulationIsForbidden() throws Exception {
        mvc.perform(post("/api/v1/policies/simulate").with(jwt().jwt(j -> j.claim("tenant_id", "alpha")))
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"subjects\":[],\"before\":[{\"tenantId\":\"beta\",\"resourceId\":\"ledger\",\"action\":\"read\",\"roles\":[\"analyst\"],\"attributes\":{},\"effect\":\"ALLOW\"}],\"after\":[]}"))
                .andExpect(status().isForbidden());
    }
}
