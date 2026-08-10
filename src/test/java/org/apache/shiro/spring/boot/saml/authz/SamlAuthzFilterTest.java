package org.apache.shiro.spring.boot.saml.authz;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for SAML authorization filter classes.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SAML Authorization Filter Tests")
class SamlAuthzFilterTest {

    @Test
    @DisplayName("SamlAuthorizationFilter can be instantiated")
    void testSamlAuthorizationFilter() {
        SamlAuthorizationFilter filter = new SamlAuthorizationFilter();
        assertThat(filter).isNotNull();
    }

    @Test
    @DisplayName("Saml2AuthorizationFilter can be instantiated")
    void testSaml2AuthorizationFilter() {
        Saml2AuthorizationFilter filter = new Saml2AuthorizationFilter();
        assertThat(filter).isNotNull();
    }

    @Test
    @DisplayName("SamlAuthorizationFilter default header name")
    void testSamlAuthzDefaultHeader() {
        SamlAuthorizationFilter filter = new SamlAuthorizationFilter();
        assertThat(filter.getAuthorizationHeaderName()).isEqualTo("Authorization");
    }

    @Test
    @DisplayName("SamlAuthorizationFilter default param name")
    void testSamlAuthzDefaultParam() {
        SamlAuthorizationFilter filter = new SamlAuthorizationFilter();
        assertThat(filter.getAuthorizationParamName()).isEqualTo("SAMLRequest");
    }

    @Test
    @DisplayName("SamlAuthorizationFilter header name getter/setter")
    void testSamlAuthzHeaderGetterSetter() {
        SamlAuthorizationFilter filter = new SamlAuthorizationFilter();
        filter.setAuthorizationHeaderName("X-SAML");
        assertThat(filter.getAuthorizationHeaderName()).isEqualTo("X-SAML");
    }

    @Test
    @DisplayName("SamlAuthorizationFilter param name getter/setter")
    void testSamlAuthzParamGetterSetter() {
        SamlAuthorizationFilter filter = new SamlAuthorizationFilter();
        filter.setAuthorizationParamName("SAMLRequest2");
        assertThat(filter.getAuthorizationParamName()).isEqualTo("SAMLRequest2");
    }

    @Test
    @DisplayName("Saml2AuthorizationFilter default header name")
    void testSaml2AuthzDefaultHeader() {
        Saml2AuthorizationFilter filter = new Saml2AuthorizationFilter();
        assertThat(filter.getAuthorizationHeaderName()).isEqualTo("Authorization");
    }

    @Test
    @DisplayName("Saml2AuthorizationFilter default param name")
    void testSaml2AuthzDefaultParam() {
        Saml2AuthorizationFilter filter = new Saml2AuthorizationFilter();
        assertThat(filter.getAuthorizationParamName()).isEqualTo("SAMLRequest");
    }

    @Test
    @DisplayName("Saml2AuthorizationFilter header name getter/setter")
    void testSaml2AuthzHeaderGetterSetter() {
        Saml2AuthorizationFilter filter = new Saml2AuthorizationFilter();
        filter.setAuthorizationHeaderName("X-SAML");
        assertThat(filter.getAuthorizationHeaderName()).isEqualTo("X-SAML");
    }

    @Test
    @DisplayName("Saml2AuthorizationFilter param name getter/setter")
    void testSaml2AuthzParamGetterSetter() {
        Saml2AuthorizationFilter filter = new Saml2AuthorizationFilter();
        filter.setAuthorizationParamName("SAMLRequest2");
        assertThat(filter.getAuthorizationParamName()).isEqualTo("SAMLRequest2");
    }
}
