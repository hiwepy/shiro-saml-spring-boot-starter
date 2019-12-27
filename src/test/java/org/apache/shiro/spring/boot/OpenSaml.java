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

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer;
import org.w3c.dom.Element;

public class OpenSaml {

	static {
		// Step 1: OpenSAML初始化过程

		JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();
		try {
			javaCryptoValidationInitializer.init();
		} catch (InitializationException e) {
			e.printStackTrace();
		}

		/*
		 * OpenSAML的初始化依赖于一些列配置文件。OpenSAML已经有一个默认的配置，其已经可以满足大多数的使用需求，如果有需要还可以对其修改。
		 * 配置文件必须在OpenSAML使用之前被加载，加载默认配置需的方法如下进行：
		 */
		try {
			InitializationService.initialize();
			// XMLObjectProviderRegistrySupport.
		} catch (InitializationException e1) {
			e1.printStackTrace();
		}
	}

	public void generateRequestURL() throws Exception {
		String consumerServiceUrl = "http://localhost:8080/consume.jsp"; // Set this for your app
		String website = "https://www.efesco.com"; // Set this for your app

		AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
		AuthnRequest authnRequest = authRequestBuilder.buildObject(SAMLConstants.SAML20P_NS, "AuthnRequest", "samlp");
		authnRequest.setIsPassive(false);
		authnRequest.setIssueInstant(new DateTime());
		authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
		authnRequest.setAssertionConsumerServiceURL(consumerServiceUrl);
		authnRequest.setID(new BigInteger(130, new SecureRandom()).toString(42));
		authnRequest.setVersion(SAMLVersion.VERSION_20);

		IssuerBuilder issuerBuilder = new IssuerBuilder();
		Issuer issuer = issuerBuilder.buildObject(SAMLConstants.SAML20_NS, "Issuer", "samlp");
		issuer.setValue(website);
		authnRequest.setIssuer(issuer);

		NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
		NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
		nameIdPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
		nameIdPolicy.setAllowCreate(true);
		authnRequest.setNameIDPolicy(nameIdPolicy);

		RequestedAuthnContextBuilder requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
		RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
		requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);

		AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
		AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject(SAMLConstants.SAML20_NS,
				"AuthnContextClassRef", "saml");
		authnContextClassRef
				.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

		requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
		authnRequest.setRequestedAuthnContext(requestedAuthnContext);

		org.opensaml.core.xml.io.Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory()
				.getMarshaller(authnRequest);
		Element authDOM = marshaller.marshall(authnRequest);
		StringWriter requestWriter = new StringWriter();
		XMLHelper.writeNode(authDOM, requestWriter);
		String messageXML = requestWriter.toString();
		System.out.println(messageXML);

	}

	public static void main(String[] args) throws Exception {
		OpenSaml openSaml = new OpenSaml();
		openSaml.generateRequestURL();
	}
	
}