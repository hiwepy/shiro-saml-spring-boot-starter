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

import java.util.Map;

import javax.annotation.PostConstruct;

import org.apache.commons.collections.MapUtils;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.spring.boot.cache.ShiroEhCache2CacheConfiguration;
import org.apache.shiro.spring.boot.saml.SamlSubjectFactory;
import org.apache.shiro.spring.boot.saml.utils.OpenSAMLUtils;
import org.apache.shiro.spring.web.config.AbstractShiroWebConfiguration;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

// http://www.cnblogs.com/suiyueqiannian/p/9359597.html
@Configuration
@AutoConfigureBefore( name = {
	"org.apache.shiro.spring.config.web.autoconfigure.ShiroWebAutoConfiguration",  // shiro-spring-boot-web-starter
	"org.apache.shiro.spring.boot.ShiroBizWebAutoConfiguration" // spring-boot-starter-shiro-biz
})
@AutoConfigureAfter(ShiroEhCache2CacheConfiguration.class)
@ConditionalOnWebApplication
@ConditionalOnClass({AuthnContextClassRef.class, RequestedAuthnContext.class })
@ConditionalOnProperty(prefix = ShiroSamlProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ ShiroBizProperties.class })
public class ShiroSaml2WebAutoConfiguration extends AbstractShiroWebConfiguration {
	
	@Autowired
	private ShiroBizProperties bizProperties;

	@PostConstruct
	public void init() {
		
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
			//XMLObjectProviderRegistrySupport.
		} catch (InitializationException e1) {
			e1.printStackTrace();
		}
		 
	}

	@Bean
	@ConditionalOnMissingBean
	protected AuthnContextClassRef authnContextClassRef(ShiroSamlProperties properties) {
		AuthnContextClassRef passwordAuthnContextClassRef = new AuthnContextClassRefBuilder().buildObject();
		passwordAuthnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
		return passwordAuthnContextClassRef;
	}
	
	/*
	 * NameID：IDP对于用户身份的标识； NameID policy是SP关于NameID是如何被创建的说明；
	 * Format指明SP需要返回什么类型的标识（SAML Artifact）； 属性AllowCreate指明IDP是否被允许当发现用户不存在时创建用户账号。
	 * 
	 * NameID Formats: 在SAML中有多种NameID的格式存在，比如Kerberos，邮箱以及Windows域限定名称（Windows Domain Qualified Name），
	 * 这里要特别说明如下两种：
	 *  持久标识（Persistent Identifier）：一个随机的ID标识被分配给用户，以避免暴露用户的真实账户。无论用户何时登入，都会返回相同的标识。 SP可以将这个标识和本地的用户账号绑定；
	 *  临时标识（Transient Identifier）：临时标识是一个和用户账户没有关系的随机标识，不会被重复使用，用户每次登陆所返回的标识都是不一样的。
	 */
	@Bean
	@ConditionalOnMissingBean
	protected NameIDPolicy nameIDPolicy() {
		
		NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
		NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
		nameIdPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
		nameIdPolicy.setAllowCreate(true);
		
		NameIDPolicy nameIDPolicy = OpenSAMLUtils.create(NameIDPolicy.class, NameIDPolicy.DEFAULT_ELEMENT_NAME);
		nameIDPolicy.setAllowCreate(true);
		nameIDPolicy.setFormat(NameID.UNSPECIFIED);
		return nameIDPolicy;
	}
	
	@Bean
	@ConditionalOnMissingBean
	protected RequestedAuthnContext requestedAuthnContext(AuthnContextClassRef authnContextClassRef, ShiroSamlProperties properties) {

		RequestedAuthnContext requestedAuthnContext = new RequestedAuthnContextBuilder().buildObject();
		
		requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
		
		/*
		 * 同时请求认证上下文也可能有多个，如果是这样的情况他们就要安装优先级排列。
		 * Comparison代表着如何IDP要如何依据所给出的鉴别方式选项处理鉴别结果，其取值包括：
		 * Minimum，最少策略，满足这个方式或者比它更安全方式就通过验证；
		 * Better，更优策略，需要满足比这个方式更为安全的方式才能通过验证；
		 * Exact，精准模式，必须满足当前方式才能通过验证；
		 * Maximum，最多策略，需要满足安全性最强的方式才能通过认证。
		 */
		switch (properties.getComparisonType()) {
			case exact: {
				requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
			};break;
			case minimum: {
				requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
			};break;
			case maximum: {
				requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MAXIMUM);
			};break;
			case better: {
				requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.BETTER);
			};break;
			default: {
				requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
			};break;
		}
		
		return requestedAuthnContext;
	}
	
	/**
	 * 责任链定义 ：定义Shiro的逻辑处理责任链
	 */
	@Bean
    @Override
	protected ShiroFilterChainDefinition shiroFilterChainDefinition() {
		DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
		Map<String /* pattert */, String /* Chain names */> pathDefinitions = bizProperties.getFilterChainDefinitionMap();
		if (MapUtils.isNotEmpty(pathDefinitions)) {
			chainDefinition.addPathDefinitions(pathDefinitions);
			return chainDefinition;
		}
		chainDefinition.addPathDefinition("/callback", "pac4j");
		chainDefinition.addPathDefinition("/logout", "logout");
		chainDefinition.addPathDefinition("/**", "authc");
		return chainDefinition;
	}
	
	@Bean
	@ConditionalOnMissingBean
	@Override
    protected SubjectFactory subjectFactory() {
        return new SamlSubjectFactory(bizProperties.isSessionCreationEnabled());
    }
	
}
