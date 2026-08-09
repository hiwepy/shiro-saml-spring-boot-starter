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
package org.apache.shiro.spring.boot.saml;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {{ @link AuthnContextComparisonType }}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("AuthnContextComparisonType Tests")
class AuthnContextComparisonTypeTest {

    @Test
    @DisplayName("Enum has expected values")
    void testEnumValues() {
        assertThat(AuthnContextComparisonType.values()).hasSize(4);
        assertThat(AuthnContextComparisonType.exact).isNotNull();
        assertThat(AuthnContextComparisonType.minimum).isNotNull();
        assertThat(AuthnContextComparisonType.maximum).isNotNull();
        assertThat(AuthnContextComparisonType.better).isNotNull();
    }

    @Test
    @DisplayName("valueOf returns correct enum")
    void testValueOf() {
        assertThat(AuthnContextComparisonType.valueOf("exact")).isEqualTo(AuthnContextComparisonType.exact);
        assertThat(AuthnContextComparisonType.valueOf("minimum")).isEqualTo(AuthnContextComparisonType.minimum);
        assertThat(AuthnContextComparisonType.valueOf("maximum")).isEqualTo(AuthnContextComparisonType.maximum);
        assertThat(AuthnContextComparisonType.valueOf("better")).isEqualTo(AuthnContextComparisonType.better);
    }
}
