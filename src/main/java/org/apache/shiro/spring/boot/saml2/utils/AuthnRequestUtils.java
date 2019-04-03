/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
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
package org.apache.shiro.spring.boot.saml2.utils;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.UUID;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.hibernate.internal.util.xml.XMLHelper;
import org.joda.time.DateTime;
import org.opensaml.core.config.Configuration;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * TODO
 * 
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */

public class AuthnRequestUtils {

	static String xmlString = "<?xml version=\"1.0\"?>" + "  <!DOCTYPE address" + "  ["
			+ "     <!ELEMENT address (buildingnumber, street, city, state, zip)>"
			+ "     <!ATTLIST address xmlns CDATA #IMPLIED>" + "     <!ELEMENT buildingnumber (#PCDATA)>"
			+ "     <!ELEMENT street (#PCDATA)>" + "     <!ELEMENT city (#PCDATA)>" + "     <!ELEMENT state (#PCDATA)>"
			+ "     <!ELEMENT zip (#PCDATA)>" + "  ]>" + "" + "  <address>"
			+ "    <buildingnumber> 29 </buildingnumber>" + "    <street> South Street</street>"
			+ "    <city>Vancouver</city>" + "" + "    <state>BC</state>" + "    <zip>V6V 4U7</zip>" + "  </address>";

	public static void main(String[] args) {

		try {

			InitializationService.initialize();
			DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
			Document document = docBuilder.parse(new ByteArrayInputStream(xmlString.trim().getBytes()));
			Element element = document.getDocumentElement();
			UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
			org.opensaml.core.xml.io.Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element); // This
																												// is
																												// coming
																												// out
																												// be
																												// null
			System.out.println(unmarshaller);
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * 创建AutheRequest对象
	 * 
	 * @author
	 * @param idpSsoUrl
	 * @param acsUrl
	 * @param spEntityId
	 * @return
	 */
	public static AuthnRequest createRequest(String idpSsoUrl, String acsUrl, String spEntityId) {
		AuthnRequest authnRequest = OpenSAMLUtils.create(AuthnRequest.class, AuthnRequest.DEFAULT_ELEMENT_NAME);
		authnRequest.setIssueInstant(new DateTime());
		authnRequest.setDestination(idpSsoUrl);
		authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
		authnRequest.setID(UUID.randomUUID().toString());
		authnRequest.setAssertionConsumerServiceURL(acsUrl);

		Issuer issuer = OpenSAMLUtils.create(Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue(spEntityId);
		authnRequest.setIssuer(issuer);

		NameIDPolicy nameIDPolicy = OpenSAMLUtils.create(NameIDPolicy.class, NameIDPolicy.DEFAULT_ELEMENT_NAME);
		nameIDPolicy.setAllowCreate(true);
		nameIDPolicy.setFormat(NameID.UNSPECIFIED);
		authnRequest.setNameIDPolicy(nameIDPolicy);
		return authnRequest;
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

		UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
		MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
		XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

		Marshaller marshaller = marshallerFactory.getMarshaller(authnRequest);
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller((QName) null); // This is coming out be null
		System.out.println(unmarshaller);

		Element authDOM = marshaller.marshall(authnRequest);
		StringWriter requestWriter = new StringWriter();
		XMLHelper.writeNode(authDOM, requestWriter);
		String messageXML = requestWriter.toString();
		System.out.println(messageXML);

	}

}
