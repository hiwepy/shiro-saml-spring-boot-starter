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
package org.apache.shiro.spring.boot.saml.utils;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.UUID;

import javax.xml.namespace.QName;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.shiro.spring.boot.saml.utils.OpenSAMLUtils;
import org.joda.time.DateTime;
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
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author ： <a href="https://github.com/vindell">vindell</a>
 * https://www.jianshu.com/p/d041935641b4
 * https://www.jianshu.com/p/6f61fa7be0b6
 * https://www.jianshu.com/p/6c72408fa480
 */
public class AuthnRequestUtils {

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
	
	/**
	 * 
	 * @author ： <a href="https://github.com/vindell">vindell</a>
	 * @param idpDestinationUrl
	 * @param acsUrl
	 * @param spEntityId
	 * @return
	 */
	public static AuthnRequest createRequest(String idpDestinationUrl, String acsUrl, String spEntityId, boolean forceAuthn) {
		return createRequest(idpDestinationUrl, acsUrl, spEntityId, null, null, forceAuthn);
	}

	/**
	 * @author ： <a href="https://github.com/vindell">vindell</a>
	 * @param idpDestinationUrl
	 * @param acsUrl
	 * @param spEntityId
	 * @param authnContextClassRef
	 * @param forceAuthn				: whether the IdP should force the user to reauthenticate
	 * @return
	 */
	public static AuthnRequest createRequest(String idpDestinationUrl, String acsUrl, String spEntityId,
			AuthnContextClassRef authnContextClassRef, RequestedAuthnContext requestedAuthnContext, boolean forceAuthn) {
		return createRequest(idpDestinationUrl, acsUrl, spEntityId, authnContextClassRef, null, forceAuthn);
	}

	/**
	 * 
	 * TODO
	 * @author 		： <a href="https://github.com/vindell">vindell</a>
	 * @param destinationURL
	 * @param assertionConsumerServiceURL
	 * @param forceAuthn				: whether the IdP should force the user to reauthenticate
	 * @param spEntityId
	 * @param authnContextClassRef
	 * @param requestedAuthnContext
	 * @return
	 */
	public static AuthnRequest createRequest(String destinationURL, String assertionConsumerServiceURL,
			boolean forceAuthn, String spEntityId, AuthnContextClassRef authnContextClassRef,
			RequestedAuthnContext requestedAuthnContext) {

		// Issuer： 发行人信息，也就是SP的ID，一般是SP的URL
		Issuer issuer = OpenSAMLUtils.create(Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue(spEntityId);

		/*
		 * NameID：IDP对于用户身份的标识； NameID policy是SP关于NameID是如何被创建的说明；
		 * Format指明SP需要返回什么类型的标识（SAML Artifact）； 属性AllowCreate指明IDP是否被允许当发现用户不存在时创建用户账号。
		 * 
		 * NameID Formats: 在SAML中有多种NameID的格式存在，比如Kerberos，邮箱以及Windows域限定名称（Windows
		 * Domain Qualified Name），这里要特别说明如下两种： 持久标识（Persistent
		 * Identifier）：一个随机的ID标识被分配给用户，以避免暴露用户的真实账户。无论用户何时登入，都会返回相同的标识。
		 * SP可以将这个标识和本地的用户账号绑定； 临时标识（Transient
		 * Identifier）：临时标识是一个和用户账户没有关系的随机标识，不会被重复使用，用户每次登陆所返回的标识都是不一样的。
		 */
		NameIDPolicy nameIDPolicy = OpenSAMLUtils.create(NameIDPolicy.class, NameIDPolicy.DEFAULT_ELEMENT_NAME);
		nameIDPolicy.setAllowCreate(true);
		nameIDPolicy.setFormat(NameID.UNSPECIFIED);

		return createRequest(destinationURL, assertionConsumerServiceURL, forceAuthn, authnContextClassRef,
				requestedAuthnContext, issuer, nameIDPolicy);
	}

	/**
	 * 
	 * 创建AutheRequest对象
	 * @author 		： <a href="https://github.com/vindell">vindell</a>
	 * @param destinationURL				：	
	 * @param assertionConsumerServiceURL	：
	 * @param forceAuthn 					：whether the IdP should force the user to reauthenticate
	 * @param authnContextClassRef			：
	 * @param requestedAuthnContext			：
	 * @param issuer						：
	 * @param nameIDPolicy					：
	 * @return
	 */
	public static AuthnRequest createRequest(String destinationURL, String assertionConsumerServiceURL,
			boolean forceAuthn, AuthnContextClassRef authnContextClassRef, RequestedAuthnContext requestedAuthnContext,
			Issuer issuer, NameIDPolicy nameIDPolicy) {

		AuthnRequest authnRequest = OpenSAMLUtils.create(AuthnRequest.class, AuthnRequest.DEFAULT_ELEMENT_NAME);
		// 请求的ID：为当前请求设置ID，一般为随机数，
		authnRequest.setID(OpenSAMLUtils.generateSecureRandomId());
		// 请求时间：该对象创建的时间，以判断其时效性
		authnRequest.setIssueInstant(new DateTime());
		// 目标URL：AuthnRequest的目标地址，IDP地址，
		authnRequest.setDestination(destinationURL);
		// 输SAML断言所使用的绑定：也就是用何种协议来使用Artifact取回真正的认证信息
		authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
		// SP地址： 也就是SAML断言返回的地址
		authnRequest.setAssertionConsumerServiceURL(assertionConsumerServiceURL);
		// Issuer： 发行人信息，也就是SP的ID，一般是SP的URL
		if (issuer != null) {
			authnRequest.setIssuer(issuer);
		}
		// NameID：IDP对于用户身份的标识； NameID policy是SP关于NameID是如何被创建的说明
		if (nameIDPolicy != null) {
			authnRequest.setNameIDPolicy(nameIDPolicy);
		}
		// ForceAuthn whether the IdP should force the user to reauthenticate
		authnRequest.setForceAuthn(forceAuthn);
		// 请求认证上下文（requested Authentication Context）: SP对于认证的要求，包含SP希望IDP如何验证用户，也就是IDP要依据什么来验证用户身份。
		if (requestedAuthnContext != null) {
			authnRequest.setRequestedAuthnContext(requestedAuthnContext);
		}

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
		
		Document document = asDOMDocument(authnRequest);
		DOMSource source=new DOMSource(document);
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer former=tf.newTransformer();
		former.setOutputProperty(OutputKeys.STANDALONE, "yes");
		StringWriter sw = new StringWriter();
		StreamResult sr = new StreamResult(sw);
		former.transform(source, sr);
		String result=sw.toString();
		
		

	}

}
