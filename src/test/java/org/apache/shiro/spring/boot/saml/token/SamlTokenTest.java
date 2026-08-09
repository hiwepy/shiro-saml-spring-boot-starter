/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot.saml.token;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {{ @link SamlToken }}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("SamlToken Tests")
class SamlTokenTest {

    @Test
    @DisplayName("Constructor with host, SAMLRequest, and rememberMe")
    void testConstructor() {
        SamlToken token = new SamlToken("localhost", "saml-request", true);
        assertThat(token).isNotNull();
        assertThat(token.getHost()).isEqualTo("localhost");
        assertThat(token.getSAMLRequest()).isEqualTo("saml-request");
        assertThat(token.isRememberMe()).isTrue();
    }

    @Test
    @DisplayName("GetPrincipal returns SAMLRequest")
    void testGetPrincipal() {
        SamlToken token = new SamlToken("localhost", "saml-request", false);
        assertThat(token.getPrincipal()).isEqualTo("saml-request");
    }

    @Test
    @DisplayName("GetCredentials returns SAMLRequest")
    void testGetCredentials() {
        SamlToken token = new SamlToken("localhost", "saml-request", false);
        assertThat(token.getCredentials()).isEqualTo("saml-request");
    }
}
