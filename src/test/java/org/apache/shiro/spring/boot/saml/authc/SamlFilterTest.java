package org.apache.shiro.spring.boot.saml.authc;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for SAML filter classes.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("SAML Filter Tests")
class SamlFilterTest {

    @Test
    @DisplayName("SamlLogoutFilter can be instantiated")
    void testSamlLogoutFilter() {
        SamlLogoutFilter filter = new SamlLogoutFilter();
        assertThat(filter).isNotNull();
    }

    @Test
    @DisplayName("Saml2LogoutFilter can be instantiated")
    void testSaml2LogoutFilter() {
        Saml2LogoutFilter filter = new Saml2LogoutFilter();
        assertThat(filter).isNotNull();
    }

    @Test
    @DisplayName("SamlAuthenticatingFilter can be instantiated")
    void testSamlAuthenticatingFilter() {
        SamlAuthenticatingFilter filter = new SamlAuthenticatingFilter();
        assertThat(filter).isNotNull();
    }

    @Test
    @DisplayName("Saml2AuthenticatingFilter can be instantiated")
    void testSaml2AuthenticatingFilter() {
        Saml2AuthenticatingFilter filter = new Saml2AuthenticatingFilter();
        assertThat(filter).isNotNull();
    }

    @Test
    @DisplayName("SamlAuthenticatingFilter default header name")
    void testSamlAuthcDefaultHeader() {
        SamlAuthenticatingFilter filter = new SamlAuthenticatingFilter();
        assertThat(filter.getAuthorizationHeaderName()).isEqualTo("Authorization");
    }

    @Test
    @DisplayName("SamlAuthenticatingFilter default param name")
    void testSamlAuthcDefaultParam() {
        SamlAuthenticatingFilter filter = new SamlAuthenticatingFilter();
        assertThat(filter.getAuthorizationParamName()).isEqualTo("SAMLRequest");
    }

    @Test
    @DisplayName("SamlAuthenticatingFilter header name getter/setter")
    void testSamlAuthcHeaderGetterSetter() {
        SamlAuthenticatingFilter filter = new SamlAuthenticatingFilter();
        filter.setAuthorizationHeaderName("X-SAML");
        assertThat(filter.getAuthorizationHeaderName()).isEqualTo("X-SAML");
    }

    @Test
    @DisplayName("SamlAuthenticatingFilter param name getter/setter")
    void testSamlAuthcParamGetterSetter() {
        SamlAuthenticatingFilter filter = new SamlAuthenticatingFilter();
        filter.setAuthorizationParamName("SAMLRequest2");
        assertThat(filter.getAuthorizationParamName()).isEqualTo("SAMLRequest2");
    }

    @Test
    @DisplayName("Saml2AuthenticatingFilter default header name")
    void testSaml2AuthcDefaultHeader() {
        Saml2AuthenticatingFilter filter = new Saml2AuthenticatingFilter();
        assertThat(filter.getAuthorizationHeaderName()).isEqualTo("Authorization");
    }

    @Test
    @DisplayName("Saml2AuthenticatingFilter default param name")
    void testSaml2AuthcDefaultParam() {
        Saml2AuthenticatingFilter filter = new Saml2AuthenticatingFilter();
        assertThat(filter.getAuthorizationParamName()).isEqualTo("SAMLRequest");
    }

    @Test
    @DisplayName("Saml2AuthenticatingFilter header name getter/setter")
    void testSaml2AuthcHeaderGetterSetter() {
        Saml2AuthenticatingFilter filter = new Saml2AuthenticatingFilter();
        filter.setAuthorizationHeaderName("X-SAML");
        assertThat(filter.getAuthorizationHeaderName()).isEqualTo("X-SAML");
    }

    @Test
    @DisplayName("Saml2AuthenticatingFilter param name getter/setter")
    void testSaml2AuthcParamGetterSetter() {
        Saml2AuthenticatingFilter filter = new Saml2AuthenticatingFilter();
        filter.setAuthorizationParamName("SAMLRequest2");
        assertThat(filter.getAuthorizationParamName()).isEqualTo("SAMLRequest2");
    }
}
