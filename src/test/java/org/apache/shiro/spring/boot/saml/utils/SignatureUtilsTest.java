package org.apache.shiro.spring.boot.saml.utils;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.opensaml.xml.security.credential.Credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {{ @link SignatureUtils }}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SignatureUtils Tests")
class SignatureUtilsTest {

    @Test
    @DisplayName("Default constructor creates non-null instance")
    void testDefaultConstructor() {
        SignatureUtils utils = new SignatureUtils();
        assertThat(utils).isNotNull();
    }

    @Test
    @DisplayName("Constructor with parameters sets fields")
    void testConstructorWithParams() {
        Credential credential = mock(Credential.class);
        SignatureUtils utils = new SignatureUtils(credential, "c14n", "rsa-sha256");
        assertThat(utils.getSigningCredential()).isEqualTo(credential);
        assertThat(utils.getCanonicalizationAlgorithm()).isEqualTo("c14n");
        assertThat(utils.getSignatureAlgorithm()).isEqualTo("rsa-sha256");
    }

    @Test
    @DisplayName("Getter/setter for signingCredential")
    void testSigningCredentialGetterSetter() {
        SignatureUtils utils = new SignatureUtils();
        Credential credential = mock(Credential.class);
        utils.setSigningCredential(credential);
        assertThat(utils.getSigningCredential()).isEqualTo(credential);
    }

    @Test
    @DisplayName("Getter/setter for canonicalizationAlgorithm")
    void testCanonicalizationAlgorithmGetterSetter() {
        SignatureUtils utils = new SignatureUtils();
        utils.setCanonicalizationAlgorithm("c14n");
        assertThat(utils.getCanonicalizationAlgorithm()).isEqualTo("c14n");
    }

    @Test
    @DisplayName("Getter/setter for signatureAlgorithm")
    void testSignatureAlgorithmGetterSetter() {
        SignatureUtils utils = new SignatureUtils();
        utils.setSignatureAlgorithm("rsa-sha256");
        assertThat(utils.getSignatureAlgorithm()).isEqualTo("rsa-sha256");
    }

    @Test
    @DisplayName("signRequest with null credential does nothing")
    void testSignRequestWithNullCredential() {
        SignatureUtils utils = new SignatureUtils();
        org.opensaml.xml.signature.SignableXMLObject obj = mock(org.opensaml.xml.signature.SignableXMLObject.class);
        utils.signRequest(obj);
        verify(obj, never()).setSignature(any());
    }
}
