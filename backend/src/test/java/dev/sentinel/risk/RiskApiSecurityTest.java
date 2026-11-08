package dev.sentinel.risk;

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
class RiskApiSecurityTest {
    @Autowired MockMvc mvc;

    private static final String WILDCARD = """
        {"grants":[{"tenantId":"alpha","userId":"alice","resourceId":"ledger",
        "permission":"*","activeUser":true}]}
        """;

    @Test void anonymousRiskAnalysisIsUnauthorized() throws Exception {
        mvc.perform(post("/api/v1/risks/analyze")
                .contentType(MediaType.APPLICATION_JSON).content(WILDCARD))
                .andExpect(status().isUnauthorized());
    }

    @Test void authenticatedRiskAnalysisReturnsFinding() throws Exception {
        mvc.perform(post("/api/v1/risks/analyze")
                .with(jwt().jwt(j -> j.claim("tenant_id", "alpha")))
                .contentType(MediaType.APPLICATION_JSON).content(WILDCARD))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].code").value("BROAD_PRIVILEGE"));
    }

    @Test void foreignTenantRiskAnalysisIsForbidden() throws Exception {
        mvc.perform(post("/api/v1/risks/analyze")
                .with(jwt().jwt(j -> j.claim("tenant_id", "beta")))
                .contentType(MediaType.APPLICATION_JSON).content(WILDCARD))
                .andExpect(status().isForbidden());
    }

    @Test void missingTenantClaimIsForbidden() throws Exception {
        mvc.perform(post("/api/v1/risks/analyze").with(jwt())
                .contentType(MediaType.APPLICATION_JSON).content(WILDCARD))
                .andExpect(status().isForbidden());
    }

    @Test void riskComparisonReturnsIntroducedFinding() throws Exception {
        String payload = """
            {"before":[],"after":[{"tenantId":"alpha","userId":"alice",
            "resourceId":"ledger","permission":"*","activeUser":true}]}
            """;
        mvc.perform(post("/api/v1/risks/compare")
                .with(jwt().jwt(j -> j.claim("tenant_id", "alpha")))
                .contentType(MediaType.APPLICATION_JSON).content(payload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.introduced").value(1))
                .andExpect(jsonPath("$.resolved").value(0));
    }

    @Test void crossTenantRiskComparisonIsForbidden() throws Exception {
        String payload = """
            {"before":[],"after":[{"tenantId":"other","userId":"alice",
            "resourceId":"ledger","permission":"*","activeUser":true}]}
            """;
        mvc.perform(post("/api/v1/risks/compare")
                .with(jwt().jwt(j -> j.claim("tenant_id", "alpha")))
                .contentType(MediaType.APPLICATION_JSON).content(payload))
                .andExpect(status().isForbidden());
    }

    @Test void malformedRiskInputIsBadRequest() throws Exception {
        mvc.perform(post("/api/v1/risks/analyze")
                .with(jwt().jwt(j -> j.claim("tenant_id", "alpha")))
                .contentType(MediaType.APPLICATION_JSON).content("{\"grants\":null}"))
                .andExpect(status().isBadRequest());
    }
}
