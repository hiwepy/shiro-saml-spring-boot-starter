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
package org.apache.shiro.spring.boot.saml.utils;

import javax.xml.namespace.QName;

import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;

import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;

/**
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
@SuppressWarnings("unchecked")
public class OpenSAMLUtils {

	private static XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
	private static RandomIdentifierGenerationStrategy secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();

	public static String generateSecureRandomId() {
		return secureRandomIdGenerator.generateIdentifier();
	}

	public static <T> T buildSAMLObject(final Class<T> clazz) throws Exception {
		QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
		T object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
		return object;
	}

	public static <T> T create(final Class<T> clazz, final QName elementName) {
		// Assertion assertion = (Assertion)
		// builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME).buildObject(Assertion.DEFAULT_ELEMENT_NAME);
		return (T) builderFactory.getBuilder(elementName).buildObject(elementName);
	}
}
