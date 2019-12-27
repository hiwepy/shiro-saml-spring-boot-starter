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

import java.util.List;

import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.biz.realm.AuthorizingRealmListener;
import org.apache.shiro.biz.spring.ShiroFilterProxyFactoryBean;
import org.apache.shiro.biz.web.filter.authc.AuthenticatingFailureCounter;
import org.apache.shiro.biz.web.filter.authc.captcha.CaptchaResolver;
import org.apache.shiro.biz.web.filter.authc.listener.LoginListener;
import org.apache.shiro.biz.web.filter.authc.listener.LogoutListener;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.boot.captcha.ShiroKaptchaProperties;
import org.apache.shiro.spring.boot.saml.Saml2LogoutFilter;
import org.apache.shiro.spring.boot.saml.Saml2PrincipalRepository;
import org.apache.shiro.spring.boot.saml.authc.Saml2AuthenticatingFilter;
import org.apache.shiro.spring.boot.saml.realm.Saml2StatefulAuthorizingRealm;
import org.apache.shiro.spring.boot.saml.realm.Saml2StatelessAuthorizingRealm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.AbstractShiroWebFilterConfiguration;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
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
@AutoConfigureBefore( name = {
	"org.apache.shiro.spring.config.web.autoconfigure.ShiroWebFilterConfiguration",  // shiro-spring-boot-web-starter
	"org.apache.shiro.spring.boot.ShiroBizWebFilterConfiguration" // spring-boot-starter-shiro-biz
})
@ConditionalOnWebApplication
@ConditionalOnClass({AuthnContextClassRef.class, RequestedAuthnContext.class})
@ConditionalOnProperty(prefix = ShiroSaml2Properties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ ShiroSaml2Properties.class, ShiroBizProperties.class, ServerProperties.class })
public class ShiroSaml2WebFilterConfiguration extends AbstractShiroWebFilterConfiguration implements ApplicationContextAware {

	private ApplicationContext applicationContext;

	@Autowired
	private ShiroSaml2Properties pac4jProperties;
	@Autowired
	private ShiroBizProperties bizProperties;
	@Autowired
	private ServerProperties serverProperties;
	
	@Bean
	@ConditionalOnMissingBean
	public Saml2PrincipalRepository samlPrincipalRepository() {
		return new Saml2PrincipalRepository();
	}
	
	@Bean("samlRealm")
	@ConditionalOnMissingBean(name = "samlRealm")
	public Realm samlRealm(Saml2PrincipalRepository samlPrincipalRepository,
			@Autowired(required = false) List<AuthorizingRealmListener> realmsListeners) {
		AbstractAuthorizingRealm authzRealm = null;
		if (bizProperties.isSessionStateless()) {
			authzRealm = new Saml2StatelessAuthorizingRealm();
		} else {
			authzRealm = new Saml2StatefulAuthorizingRealm();
		}
		// 认证账号信息提供实现：认证信息、角色信息、权限信息；业务系统需要自己实现该接口
		authzRealm.setRepository(samlPrincipalRepository);
		// 凭证匹配器：该对象主要做密码校验
		authzRealm.setCredentialsMatcher(new AllowAllCredentialsMatcher());
		// Realm 执行监听：实现该接口可监听认证失败和成功的状态，从而做业务系统自己的事情，比如记录日志
		authzRealm.setRealmsListeners(realmsListeners);
		// 缓存相关的配置：采用提供的默认配置即可
		authzRealm.setCachingEnabled(bizProperties.isCachingEnabled());
		// 认证缓存配置:无状态情况不缓存认证信息
		authzRealm.setAuthenticationCachingEnabled(bizProperties.isAuthenticationCachingEnabled());
		authzRealm.setAuthenticationCacheName(bizProperties.getAuthenticationCacheName());
		// 授权缓存配置:无状态情况不缓存认证信息
		authzRealm.setAuthorizationCachingEnabled(bizProperties.isAuthorizationCachingEnabled());
		authzRealm.setAuthorizationCacheName(bizProperties.getAuthorizationCacheName());

		return authzRealm;
	}
	
	/*
	 * 账号注销过滤器 ：处理账号注销
	 */
	@Bean("logout")
	public FilterRegistrationBean<Saml2LogoutFilter> logoutFilter(@Autowired(required = false) List<LogoutListener> logoutListeners){
		
		FilterRegistrationBean<Saml2LogoutFilter> filterRegistration = new FilterRegistrationBean<Saml2LogoutFilter>();
		
		Saml2LogoutFilter logoutFilter = new Saml2LogoutFilter();
	    
		//注销监听：实现该接口可监听账号注销失败和成功的状态，从而做业务系统自己的事情，比如记录日志
		logoutFilter.setLogoutListeners(logoutListeners);
		logoutFilter.setPostOnlyLogout(bizProperties.isPostOnlyLogout());
		//登录注销后的重定向地址：直接进入登录页面
		logoutFilter.setRedirectUrl(bizProperties.getRedirectUrl());
		
		filterRegistration.setFilter(logoutFilter);
		filterRegistration.setEnabled(false); 
	    
	    return filterRegistration;
	}
	
	/*
	 * 权限控制过滤器 ：实现权限认证
	 */
	@Bean("authc")
	public FilterRegistrationBean<Saml2AuthenticatingFilter> authenticationFilter(
			@Autowired(required = false) List<LoginListener> loginListeners, 
			@Autowired(required = false) CaptchaResolver captchaResolver,
			@Autowired(required = false) AuthenticatingFailureCounter authcFailureCounter,
			ShiroBizProperties bizProperties, 
			ShiroKaptchaProperties kaptchaProperties,
			ShiroSaml2Properties samlProperties) {
		
		Saml2AuthenticatingFilter authcFilter = new Saml2AuthenticatingFilter();
		
		// 登录监听：实现该接口可监听账号登录失败和成功的状态，从而做业务系统自己的事情，比如记录日志
		authcFilter.setLoginListeners(loginListeners);
		// 认证失败次数计数器实现
		authcFilter.setFailureCounter(authcFailureCounter);
		// Session 状态设置：是否无状态Session
		authcFilter.setSessionStateless(bizProperties.isSessionStateless());
		// 是否启用验证码
		if(kaptchaProperties.isEnabled()) {
			// 登陆失败重试次数，超出限制需要输入验证码
			authcFilter.setRetryTimesWhenAccessDenied(kaptchaProperties.getRetryTimesWhenAccessDenied());
			// 是否验证验证码
			authcFilter.setCaptchaEnabled(kaptchaProperties.isEnabled());
			// 验证码解析器
			authcFilter.setCaptchaResolver(captchaResolver);
		}
		/*
		 * 自定义Filter通过@Bean注解后，被Spring Boot自动注册到了容器的Filter
		 * chain中，这样导致的结果是，所有URL都会被自定义Filter过滤， 而不是Shiro中配置的一部分URL。下面方式可以解决该问题
		 */
		FilterRegistrationBean<Saml2AuthenticatingFilter> registration = new FilterRegistrationBean<Saml2AuthenticatingFilter>(
				authcFilter);
		registration.setEnabled(false);
		return registration;
	}
	
	/**
	 * 权限控制过滤器 ：权限过滤链的入口（仅是FactoryBean需要引用）
	 */
	@Bean
    @Override
	protected ShiroFilterFactoryBean shiroFilterFactoryBean() {

		ShiroFilterFactoryBean filterFactoryBean = new ShiroFilterProxyFactoryBean();
		
		// 登录地址：会话不存在时访问的地址
		filterFactoryBean.setLoginUrl(bizProperties.getLoginUrl());
		// 系统主页：登录成功后跳转路径
		filterFactoryBean.setSuccessUrl(bizProperties.getSuccessUrl());
		// 异常页面：无权限时的跳转路径
		filterFactoryBean.setUnauthorizedUrl(bizProperties.getUnauthorizedUrl());
		// 必须设置 SecurityManager
		filterFactoryBean.setSecurityManager(securityManager);
		// 拦截规则
		filterFactoryBean.setFilterChainDefinitionMap(shiroFilterChainDefinition.getFilterChainMap());
		
		return filterFactoryBean;
	}
	
	/**
	 * 权限控制过滤器 ：权限过滤链的入口
	 */
	@Bean(name = "filterShiroFilterRegistrationBean")
    protected FilterRegistrationBean<AbstractShiroFilter> filterShiroFilterRegistrationBean() throws Exception {

        FilterRegistrationBean<AbstractShiroFilter> filterRegistrationBean = new FilterRegistrationBean<AbstractShiroFilter>();
        filterRegistrationBean.setFilter((AbstractShiroFilter) shiroFilterFactoryBean().getObject());
        filterRegistrationBean.setOrder(1);

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
