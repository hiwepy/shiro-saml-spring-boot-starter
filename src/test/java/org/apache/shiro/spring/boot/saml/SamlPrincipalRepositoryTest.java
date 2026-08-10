package org.apache.shiro.spring.boot.saml;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.spring.boot.saml.token.SamlToken;
import org.apache.shiro.spring.boot.saml.token.Saml2Token;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for SAML principal repository classes.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SAML Principal Repository Tests")
class SamlPrincipalRepositoryTest {

    @Test
    @DisplayName("SamlPrincipalRepository can be instantiated")
    void testSamlPrincipalRepository() {
        SamlPrincipalRepository repo = new SamlPrincipalRepository();
        assertThat(repo).isNotNull();
    }

    @Test
    @DisplayName("Saml2PrincipalRepository can be instantiated")
    void testSaml2PrincipalRepository() {
        Saml2PrincipalRepository repo = new Saml2PrincipalRepository();
        assertThat(repo).isNotNull();
    }

    @Test
    @DisplayName("SamlPrincipalRepository getAuthenticationInfo returns info")
    void testSamlPrincipalRepoGetAuthInfo() {
        SamlPrincipalRepository repo = new SamlPrincipalRepository();
        SamlToken token = new SamlToken("host", "saml-request", false);
        AuthenticationInfo info = repo.getAuthenticationInfo(token);
        assertThat(info).isNotNull();
    }

    @Test
    @DisplayName("Saml2PrincipalRepository getAuthenticationInfo returns info")
    void testSaml2PrincipalRepoGetAuthInfo() {
        Saml2PrincipalRepository repo = new Saml2PrincipalRepository();
        Saml2Token token = new Saml2Token("host", "saml2-request", false);
        AuthenticationInfo info = repo.getAuthenticationInfo(token);
        assertThat(info).isNotNull();
    }
}
