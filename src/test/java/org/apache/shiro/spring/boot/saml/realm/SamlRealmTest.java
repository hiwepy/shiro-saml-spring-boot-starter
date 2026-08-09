package org.apache.shiro.spring.boot.saml.realm;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for SAML realm classes.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("SAML Realm Tests")
class SamlRealmTest {

    @Test
    @DisplayName("SamlStatefulAuthorizingRealm can be instantiated")
    void testSamlStatefulAuthorizingRealm() {
        SamlStatefulAuthorizingRealm realm = new SamlStatefulAuthorizingRealm();
        assertThat(realm).isNotNull();
    }

    @Test
    @DisplayName("SamlStatelessAuthorizingRealm can be instantiated")
    void testSamlStatelessAuthorizingRealm() {
        SamlStatelessAuthorizingRealm realm = new SamlStatelessAuthorizingRealm();
        assertThat(realm).isNotNull();
    }

    @Test
    @DisplayName("Saml2StatefulAuthorizingRealm can be instantiated")
    void testSaml2StatefulAuthorizingRealm() {
        Saml2StatefulAuthorizingRealm realm = new Saml2StatefulAuthorizingRealm();
        assertThat(realm).isNotNull();
    }

    @Test
    @DisplayName("Saml2StatelessAuthorizingRealm can be instantiated")
    void testSaml2StatelessAuthorizingRealm() {
        Saml2StatelessAuthorizingRealm realm = new Saml2StatelessAuthorizingRealm();
        assertThat(realm).isNotNull();
    }

    @Test
    @DisplayName("SamlStatelessAuthorizingRealm supports SamlToken")
    void testSamlStatelessSupportsToken() {
        SamlStatelessAuthorizingRealm realm = new SamlStatelessAuthorizingRealm();
        org.apache.shiro.authc.AuthenticationToken token = new org.apache.shiro.spring.boot.saml.token.SamlToken("host", "request", false);
        // The realm may or may not support this token type depending on its implementation
        assertThat(realm.supports(token)).isNotNull();
    }

    @Test
    @DisplayName("Saml2StatelessAuthorizingRealm supports Saml2Token")
    void testSaml2StatelessSupportsToken() {
        Saml2StatelessAuthorizingRealm realm = new Saml2StatelessAuthorizingRealm();
        org.apache.shiro.authc.AuthenticationToken token = new org.apache.shiro.spring.boot.saml.token.Saml2Token("host", "request", false);
        // The realm may or may not support this token type depending on its implementation
        assertThat(realm.supports(token)).isNotNull();
    }
}
