package io.github.rmkrdev.entra.security.test.authority;

import static io.github.rmkrdev.entra.security.test.EntraMockMvc.bearer;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import com.nimbusds.jwt.SignedJWT;

import io.github.rmkrdev.entra.security.autoconfigure.EntraEndpoints;
import io.github.rmkrdev.entra.security.autoconfigure.EntraOutboundClients;
import io.github.rmkrdev.entra.security.test.EntraMockAuthority;
import io.github.rmkrdev.entra.security.test.EntraTestTokens;
import io.github.rmkrdev.entra.security.test.it.TestApplication;

/**
 * The mock authority presenting itself on a custom host (a sovereign-cloud style login host), with every
 * endpoint taken from its OIDC discovery document.
 */
@SpringBootTest(classes = TestApplication.class, properties = {
        "entra.security.authority.allow-http=true",
        "entra.security.authority.discovery.enabled=true",
        "entra.security.graph.overage-enabled=false",
        "entra.security.outbound.clients.peer.scope=api://peer/.default" })
@AutoConfigureMockMvc
class CustomHostMockAuthorityIntegrationTest {

    static final EntraMockAuthority AUTHORITY = EntraMockAuthority.start("login.sovereign.test");
    static final String TENANT = "11111111-1111-1111-1111-111111111111";

    @DynamicPropertySource
    static void authority(DynamicPropertyRegistry registry) {
        registry.add("entra.security.authority.host", AUTHORITY::baseUrl);
    }

    @AfterAll
    static void stop() {
        AUTHORITY.close();
    }

    @Autowired
    MockMvc mvc;

    @Autowired
    EntraEndpoints endpoints;

    @Autowired
    EntraOutboundClients outbound;

    @Test
    void theMockAuthorityAdvertisesTheCustomHost() {
        assertThat(AUTHORITY.baseUrl()).startsWith("http://login.sovereign.test:");
        assertThat(endpoints.issuers()).containsExactly(AUTHORITY.issuer(TENANT));
        assertThat(endpoints.jwksUri()).hasToString(AUTHORITY.jwkSetUri(TENANT));
        assertThat(endpoints.authorizeEndpoint()).hasToString(AUTHORITY.baseUrl() + "/" + TENANT
                + "/oauth2/v2.0/authorize");
    }

    @Test
    void userTokensFromTheCustomHostAreAccepted() throws Exception {
        EntraTestTokens tokens = AUTHORITY.tokens(TENANT, "22222222-2222-2222-2222-222222222222");
        mvc.perform(get("/orders").with(bearer(tokens.user().groups("aaaaaaaa-0000-0000-0000-000000000001"))))
                .andExpect(status().isOk());
    }

    @Test
    void outboundTokensComeFromTheDiscoveredTokenEndpoint() throws Exception {
        int before = AUTHORITY.tokenRequests();
        String token = outbound.token("peer").value();
        assertThat(AUTHORITY.tokenRequests()).isEqualTo(before + 1);
        assertThat(SignedJWT.parse(token).getJWTClaimsSet().getIssuer()).isEqualTo(AUTHORITY.issuer(TENANT));
    }

    @Test
    void publicHostMustBeABareHostName() {
        assertThatIllegalArgumentException().isThrownBy(() -> EntraMockAuthority.start("http://x"));
        assertThatIllegalArgumentException().isThrownBy(() -> EntraMockAuthority.start("x:80"));
        assertThatIllegalArgumentException().isThrownBy(() -> EntraMockAuthority.start(" "));
        assertThatIllegalArgumentException().isThrownBy(() -> EntraMockAuthority.start(null));
    }
}
