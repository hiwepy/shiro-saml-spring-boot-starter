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

import java.util.UUID;

import javax.xml.namespace.QName;

import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;

import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;

/**
 * TODO
 * @author ： <a href="https://github.com/vindell">vindell</a>
 * https://www.jianshu.com/p/d041935641b4
 * https://www.jianshu.com/p/6f61fa7be0b6
 * https://www.jianshu.com/p/6c72408fa480
 */
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
	
	/**
	 * 创建AutheRequest对象
	 * @param idpSsoUrl
	 * @param acsUrl
	 * @param spEntityId
	 * @return
	 */
	public static AuthnRequest createRequest(String idpDestinationUrl, String acsUrl, String spEntityId) {
		
		AuthnRequest authnRequest = create(AuthnRequest.class, AuthnRequest.DEFAULT_ELEMENT_NAME);
		// 请求的ID：为当前请求设置ID，一般为随机数，
		authnRequest.setID(generateSecureRandomId());
		// 请求时间：该对象创建的时间，以判断其时效性
		authnRequest.setIssueInstant(new DateTime());
		// 目标URL：AuthnRequest的目标地址，IDP地址，
		authnRequest.setDestination(idpDestinationUrl);
		// 输SAML断言所使用的绑定：也就是用何种协议来使用Artifact取回真正的认证信息
		authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
		// SP地址： 也就是SAML断言返回的地址
		authnRequest.setAssertionConsumerServiceURL(acsUrl);

		// Issuer： 发行人信息，也就是SP的ID，一般是SP的URL
		Issuer issuer = create(Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue(spEntityId);
		authnRequest.setIssuer(issuer);

		/*
		 * NameID：IDP对于用户身份的标识；
		 * NameID policy是SP关于NameID是如何被创建的说明；
		 * Format指明SP需要返回什么类型的标识（SAML Artifact）；
		 * 属性AllowCreate指明IDP是否被允许当发现用户不存在时创建用户账号。 
		 * 
		 * NameID Formats:
		 * 在SAML中有多种NameID的格式存在，比如Kerberos，邮箱以及Windows域限定名称（Windows Domain Qualified Name），这里要特别说明如下两种：
		 * 持久标识（Persistent Identifier）：一个随机的ID标识被分配给用户，以避免暴露用户的真实账户。无论用户何时登入，都会返回相同的标识。SP可以将这个标识和本地的用户账号绑定；
		 * 临时标识（Transient Identifier）：临时标识是一个和用户账户没有关系的随机标识，不会被重复使用，用户每次登陆所返回的标识都是不一样的。
		 */
		NameIDPolicy nameIDPolicy = create(NameIDPolicy.class, NameIDPolicy.DEFAULT_ELEMENT_NAME);
		nameIDPolicy.setAllowCreate(true);
		nameIDPolicy.setFormat(NameID.UNSPECIFIED);
		authnRequest.setNameIDPolicy(nameIDPolicy);
		
		/*
		 * 请求认证上下文（requested Authentication Context）: SP对于认证的要求，包含SP希望IDP如何验证用户，也就是IDP要依据什么来验证用户身份。
		 */
		//RequestedAuthnContext requestedAuthnContext = OpenSAMLUtils.create(RequestedAuthnContext.class);
		
		return authnRequest;
	}

	@SuppressWarnings("unchecked")
	public static <T> T create(final Class<T> clazz, final QName elementName) {
		// Assertion assertion = (Assertion)
		// builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME).buildObject(Assertion.DEFAULT_ELEMENT_NAME);
		return (T) builderFactory.getBuilder(elementName).buildObject(elementName);
	}
}
