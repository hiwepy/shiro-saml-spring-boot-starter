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
import org.apache.shiro.spring.web.config.AbstractShiroWebConfiguration;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
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
//@ConditionalOnClass({AuthnContextClassRef.class, RequestedAuthnContext.class })
@ConditionalOnProperty(prefix = ShiroSamlProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ ShiroBizProperties.class })
public class ShiroSamlWebAutoConfiguration extends AbstractShiroWebConfiguration {
	
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
