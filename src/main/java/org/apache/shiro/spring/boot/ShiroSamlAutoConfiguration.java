package org.apache.shiro.spring.boot;

import java.util.Map;

import javax.annotation.PostConstruct;
import javax.servlet.Filter;

import org.apache.commons.collections.MapUtils;
import org.apache.shiro.biz.spring.ShiroFilterProxyFactoryBean;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.boot.cache.ShiroEhCache2CacheConfiguration;
import org.apache.shiro.spring.boot.saml2.utils.OpenSAMLUtils;
import org.apache.shiro.spring.config.web.autoconfigure.ShiroWebAutoConfiguration;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.DelegatingFilterProxyRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 默认拦截器
 * <p>Shiro内置了很多默认的拦截器，比如身份验证、授权等相关的。默认拦截器可以参考org.apache.shiro.web.filter.mgt.DefaultFilter中的枚举拦截器：&nbsp;&nbsp;</p>
 * 自定义Filter通过@Bean注解后，被Spring Boot自动注册到了容器的Filter
 * chain中，这样导致的结果是，所有URL都会被自定义Filter过滤，而不是Shiro中配置的一部分URL。
 * https://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#howto-disable-registration-of-a-servlet-or-filter
 * http://www.jianshu.com/p/bf79fdab9c19
 */
@Configuration
@AutoConfigureBefore(ShiroWebAutoConfiguration.class)
@AutoConfigureAfter(ShiroEhCache2CacheConfiguration.class)
@ConditionalOnProperty(prefix = ShiroSamlProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ ShiroSamlProperties.class })
public class ShiroSamlAutoConfiguration implements ApplicationContextAware {

	private static final Logger LOG = LoggerFactory.getLogger(ShiroSamlAutoConfiguration.class);
	private ApplicationContext applicationContext;

	@Autowired
	private ShiroBizProperties properties;

	@PostConstruct
	public void init() {
		/*JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();
		try {
			javaCryptoValidationInitializer.init();
		} catch (InitializationException e) {
			e.printStackTrace();
		}*/
		try {
			InitializationService.initialize();
		} catch (InitializationException e) {
			new RuntimeException("Initialization failed");
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
	 * NameID Formats: 在SAML中有多种NameID的格式存在，比如Kerberos，邮箱以及Windows域限定名称（Windows
	 * Domain Qualified Name），这里要特别说明如下两种： 持久标识（Persistent
	 * Identifier）：一个随机的ID标识被分配给用户，以避免暴露用户的真实账户。无论用户何时登入，都会返回相同的标识。
	 * SP可以将这个标识和本地的用户账号绑定； 临时标识（Transient
	 * Identifier）：临时标识是一个和用户账户没有关系的随机标识，不会被重复使用，用户每次登陆所返回的标识都是不一样的。
	 */
	@Bean
	@ConditionalOnMissingBean
	protected NameIDPolicy nameIDPolicy() {
		NameIDPolicy nameIDPolicy = OpenSAMLUtils.create(NameIDPolicy.class, NameIDPolicy.DEFAULT_ELEMENT_NAME);
		nameIDPolicy.setAllowCreate(true);
		nameIDPolicy.setFormat(NameID.UNSPECIFIED);
		return nameIDPolicy;
	}
	

	@Bean
	@ConditionalOnMissingBean
	protected RequestedAuthnContext requestedAuthnContext(AuthnContextClassRef authnContextClassRef,
			ShiroSamlProperties properties) {

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

	@Bean
	@ConditionalOnMissingBean
	protected ShiroFilterChainDefinition shiroFilterChainDefinition() {

		XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
		Assertion assertion = (Assertion) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME)
				.buildObject(Assertion.DEFAULT_ELEMENT_NAME);

		// Step 1: OpenSAML初始化过程

		/*
		 * OpenSAML的初始化依赖于一些列配置文件。OpenSAML已经有一个默认的配置，其已经可以满足大多数的使用需求，如果有需要还可以对其修改。
		 * 配置文件必须在OpenSAML使用之前被加载，加载默认配置需的方法如下进行：
		 */
		try {
			InitializationService.initialize();
		} catch (InitializationException e1) {
			e1.printStackTrace();
		}

		JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();
		try {
			javaCryptoValidationInitializer.init();
		} catch (InitializationException e) {
			e.printStackTrace();
		}

		DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
		Map<String /* pattert */, String /* Chain names */> pathDefinitions = properties.getFilterChainDefinitionMap();
		if (MapUtils.isNotEmpty(pathDefinitions)) {
			chainDefinition.addPathDefinitions(pathDefinitions);
			return chainDefinition;
		}
		chainDefinition.addPathDefinition("/**", "authc");
		return chainDefinition;
	}

	@Bean("shiroFilter")
	@ConditionalOnMissingBean(name = "shiroFilter")
	protected ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager,
			ShiroFilterChainDefinition shiroFilterChainDefinition, Map<String, Filter> authcFilters) {

		ShiroFilterFactoryBean filterFactoryBean = new ShiroFilterProxyFactoryBean();
		// ShiroFilterFactoryBean filterFactoryBean = new ShiroFilterFactoryBean();

		// 登录地址：会话不存在时访问的地址
		filterFactoryBean.setLoginUrl(properties.getLoginUrl());
		// 系统主页：登录成功后跳转路径
		filterFactoryBean.setSuccessUrl(properties.getSuccessUrl());
		// 异常页面：无权限时的跳转路径
		filterFactoryBean.setUnauthorizedUrl(properties.getUnauthorizedUrl());
		// 必须设置 SecurityManager
		filterFactoryBean.setSecurityManager(securityManager);
		// 过滤器链：实现对路径规则的拦截过滤
		filterFactoryBean.setFilters(authcFilters);
		// 拦截规则
		filterFactoryBean.setFilterChainDefinitionMap(shiroFilterChainDefinition.getFilterChainMap());

		return filterFactoryBean;
	}

	@Bean
	public DelegatingFilterProxyRegistrationBean delegatingFilterProxy(AbstractShiroFilter shiroFilter) {
		// FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
		DelegatingFilterProxyRegistrationBean filterRegistrationBean = new DelegatingFilterProxyRegistrationBean(
				"shiroFilter");

		filterRegistrationBean.setOrder(Integer.MAX_VALUE);
		filterRegistrationBean.addUrlPatterns("/*");
		return filterRegistrationBean;
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}

}
