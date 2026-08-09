package org.apache.shiro.spring.boot.saml;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {{ @link SamlSubjectFactory }}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("SamlSubjectFactory Tests")
class SamlSubjectFactoryTest {

    @Test
    @DisplayName("Constructor with sessionCreationEnabled")
    void testConstructor() {
        SamlSubjectFactory factory = new SamlSubjectFactory(true);
        assertThat(factory).isNotNull();
    }

    @Test
    @DisplayName("Constructor with false creates non-null instance")
    void testConstructorWithFalse() {
        SamlSubjectFactory factory = new SamlSubjectFactory(false);
        assertThat(factory).isNotNull();
    }
}
