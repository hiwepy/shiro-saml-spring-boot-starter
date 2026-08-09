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
package org.apache.shiro.spring.boot.saml.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for SAML exception classes.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("SAML Exception Tests")
class SamlExceptionTest {

    @Test
    @DisplayName("ExpiredSamlException can be created")
    void testExpiredSamlException() {
        ExpiredSamlException ex = new ExpiredSamlException("expired");
        assertThat(ex).isNotNull();
        assertThat(ex.getMessage()).isEqualTo("expired");
    }

    @Test
    @DisplayName("IncorrectSamlException can be created")
    void testIncorrectSamlException() {
        IncorrectSamlException ex = new IncorrectSamlException("incorrect");
        assertThat(ex).isNotNull();
        assertThat(ex.getMessage()).isEqualTo("incorrect");
    }

    @Test
    @DisplayName("InvalidSamlToken can be created")
    void testInvalidSamlToken() {
        InvalidSamlToken ex = new InvalidSamlToken("invalid");
        assertThat(ex).isNotNull();
        assertThat(ex.getMessage()).isEqualTo("invalid");
    }

    @Test
    @DisplayName("NotObtainedSamlException can be created")
    void testNotObtainedSamlException() {
        NotObtainedSamlException ex = new NotObtainedSamlException("not obtained");
        assertThat(ex).isNotNull();
        assertThat(ex.getMessage()).isEqualTo("not obtained");
    }
}
