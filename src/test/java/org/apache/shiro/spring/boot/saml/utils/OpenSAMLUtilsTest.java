package org.apache.shiro.spring.boot.saml.utils;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationService;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {{ @link OpenSAMLUtils }}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("OpenSAMLUtils Tests")
class OpenSAMLUtilsTest {

    static {
        try {
            InitializationService.initialize();
        } catch (Exception e) {
            // initialization may fail in test environment
        }
    }

    @Test
    @DisplayName("generateSecureRandomId returns non-null string")
    void testGenerateSecureRandomId() {
        String id = OpenSAMLUtils.generateSecureRandomId();
        assertThat(id).isNotNull().isNotEmpty();
    }

    @Test
    @DisplayName("generateSecureRandomId returns unique values")
    void testGenerateSecureRandomIdUniqueness() {
        String id1 = OpenSAMLUtils.generateSecureRandomId();
        String id2 = OpenSAMLUtils.generateSecureRandomId();
        assertThat(id1).isNotEqualTo(id2);
    }
}
