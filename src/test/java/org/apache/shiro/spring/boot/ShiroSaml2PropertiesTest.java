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
package org.apache.shiro.spring.boot;

import org.apache.shiro.spring.boot.saml.AuthnContextComparisonType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {{ @link ShiroSaml2Properties }}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("ShiroSaml2Properties Tests")
class ShiroSaml2PropertiesTest {

    @Test
    @DisplayName("Default constructor creates non-null instance")
    void testDefaultInstance() {
        ShiroSaml2Properties props = new ShiroSaml2Properties();
        assertThat(props).isNotNull();
    }

    @Test
    @DisplayName("PREFIX constant has expected value")
    void testPREFIXConstant() {
        assertThat(ShiroSaml2Properties.PREFIX).isEqualTo("shiro.saml2");
    }

    @Test
    @DisplayName("Default enabled is false")
    void testDefaultEnabled() {
        ShiroSaml2Properties props = new ShiroSaml2Properties();
        assertThat(props.isEnabled()).isFalse();
    }

    @Test
    @DisplayName("Enabled getter/setter works")
    void testEnabledGetterSetter() {
        ShiroSaml2Properties props = new ShiroSaml2Properties();
        props.setEnabled(true);
        assertThat(props.isEnabled()).isTrue();
    }

    @Test
    @DisplayName("Default comparisonType is minimum")
    void testDefaultComparisonType() {
        ShiroSaml2Properties props = new ShiroSaml2Properties();
        assertThat(props.getComparisonType()).isEqualTo(AuthnContextComparisonType.minimum);
    }

    @Test
    @DisplayName("ComparisonType getter/setter works")
    void testComparisonTypeGetterSetter() {
        ShiroSaml2Properties props = new ShiroSaml2Properties();
        props.setComparisonType(AuthnContextComparisonType.exact);
        assertThat(props.getComparisonType()).isEqualTo(AuthnContextComparisonType.exact);
    }
}
