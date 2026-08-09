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
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.boot.captcha.ShiroKaptchaProperties;
import org.apache.shiro.spring.boot.saml.SamlPrincipalRepository;
import org.apache.shiro.spring.boot.saml.authc.SamlAuthenticatingFilter;
import org.apache.shiro.spring.boot.saml.authc.SamlLogoutFilter;
import org.apache.shiro.spring.boot.saml.realm.SamlStatefulAuthorizingRealm;
import org.apache.shiro.spring.boot.saml.realm.SamlStatelessAuthorizingRealm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.AbstractShiroWebFilterConfiguration;
import org.apache.shiro.web.filter.authc.LogoutFilter;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.bouncycastle.math.ec.ECCurve.Config;
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
import org.springframework.cglib.proxy.CallbackFilter;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * default拦截器
 * <p>Shiro内置了很多default的拦截器，比如身份validate、authorization等相关的。default拦截器可以参考org.apache.shiro.web.filter.mgt.DefaultFilter中的枚举拦截器：&nbsp;&nbsp;</p>
 * 自定义Filter通过@Bean注解后，被Spring Boot自动registers到了容器的Filter
 * chain中，这样导致的结果是，所有URL都会被自定义Filter过滤，而不是Shiro中configuration的一部分URL。
 * https://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#howto-disable-registration-of-a-servlet-or-filter
 * http://www.jianshu.com/p/bf79fdab9c19
 */
@Configuration
@AutoConfigureBefore( name = {
	"org.apache.shiro.spring.config.web.autoconfigure.ShiroWebFilterConfiguration",  // shiro-spring-boot-web-starter
	"org.apache.shiro.spring.boot.ShiroBizWebFilterConfiguration" // spring-boot-starter-shiro-biz
})
@ConditionalOnWebApplication
//@ConditionalOnClass({CallbackFilter.class, SecurityFilter.class, LogoutFilter.class})
/**
 * ShiroSamlWebFilterConfiguration.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@ConditionalOnProperty(prefix = ShiroSamlProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ ShiroSamlProperties.class, ShiroBizProperties.class, ServerProperties.class })
public class ShiroSamlWebFilterConfiguration extends AbstractShiroWebFilterConfiguration implements ApplicationContextAware {

	private ApplicationContext applicationContext;

	@Autowired
	private ShiroSamlProperties samlProperties;
	@Autowired
	private ShiroBizProperties bizProperties;
	@Autowired
	private ServerProperties serverProperties;
	@Autowired
	private CacheManager shiroCacheManager;
	
	@Bean
	@ConditionalOnMissingBean
	public SamlPrincipalRepository samlPrincipalRepository() {
		return new SamlPrincipalRepository();
	}
	
	@Bean("samlRealm")
	@ConditionalOnMissingBean(name = "samlRealm")
	public Realm samlRealm(SamlPrincipalRepository samlPrincipalRepository,
			@Autowired(required = false) List<AuthorizingRealmListener> realmsListeners) {
		AbstractAuthorizingRealm authzRealm = null;
		if (bizProperties.isSessionStateless()) {
			authzRealm = new SamlStatelessAuthorizingRealm();
		} else {
			authzRealm = new SamlStatefulAuthorizingRealm();
		}
		// authentication账号info提供实现：authenticationinfo、roleinfo、permissioninfo；业务系统需要自己实现该接口
		authzRealm.setRepository(samlPrincipalRepository);
		// 凭证匹配器：该对象主要做password校验
		authzRealm.setCredentialsMatcher(new AllowAllCredentialsMatcher());
		// Realm 执行listener：实现该接口可listenerauthenticationfailure和success的状态，从而做业务系统自己的事情，比如record日志
		authzRealm.setRealmsListeners(realmsListeners);
		// cache相关的configuration：采用提供的defaultconfiguration即可
		authzRealm.setCachingEnabled(bizProperties.isCachingEnabled());
		// authenticationcacheconfiguration:无状态情况不cacheauthenticationinfo
		authzRealm.setAuthenticationCachingEnabled(bizProperties.isAuthenticationCachingEnabled());
		authzRealm.setAuthenticationCacheName(bizProperties.getAuthenticationCacheName());
		// authorizationcacheconfiguration:无状态情况不cacheauthenticationinfo
		authzRealm.setAuthorizationCachingEnabled(bizProperties.isAuthorizationCachingEnabled());
		authzRealm.setAuthorizationCacheName(bizProperties.getAuthorizationCacheName());

		return authzRealm;
	}
	
	/*
	 * 账号注销filter ：处理账号注销
	 */
	@Bean("logout")
	public FilterRegistrationBean<SamlLogoutFilter> logoutFilter(@Autowired(required = false) List<LogoutListener> logoutListeners){
		
		FilterRegistrationBean<SamlLogoutFilter> filterRegistration = new FilterRegistrationBean<SamlLogoutFilter>();
		
		SamlLogoutFilter logoutFilter = new SamlLogoutFilter();
	    
		//注销listener：实现该接口可listener账号注销failure和success的状态，从而做业务系统自己的事情，比如record日志
		logoutFilter.setLogoutListeners(logoutListeners);
		logoutFilter.setPostOnlyLogout(bizProperties.isPostOnlyLogout());
		//login注销后的重定向address：直接进入login页面
		logoutFilter.setRedirectUrl(bizProperties.getRedirectUrl());
		
		filterRegistration.setFilter(logoutFilter);
		filterRegistration.setEnabled(false); 
	    
	    return filterRegistration;
	}
	
	/*
	 * permission控制filter ：实现permissionauthentication
	 */
	@Bean("authc")
	public FilterRegistrationBean<SamlAuthenticatingFilter> authenticationFilter(
			@Autowired(required = false) List<LoginListener> loginListeners, 
			@Autowired(required = false) CaptchaResolver captchaResolver,
			@Autowired(required = false) AuthenticatingFailureCounter authcFailureCounter,
			ShiroBizProperties bizProperties, 
			ShiroKaptchaProperties kaptchaProperties,
			ShiroSamlProperties samlProperties) {
		
		SamlAuthenticatingFilter authcFilter = new SamlAuthenticatingFilter();
		
		// loginlistener：实现该接口可listener账号loginfailure和success的状态，从而做业务系统自己的事情，比如record日志
		authcFilter.setLoginListeners(loginListeners);
		// authenticationfailure次数计数器实现
		authcFilter.setFailureCounter(authcFailureCounter);
		// Session 状态sets：whether无状态Session
		authcFilter.setSessionStateless(bizProperties.isSessionStateless());
		// whetherenablecaptcha
		if(kaptchaProperties.isEnabled()) {
			// 登陆failureretry次数，超出限制需要输入captcha
			authcFilter.setRetryTimesWhenAccessDenied(kaptchaProperties.getRetryTimesWhenAccessDenied());
			// whethervalidatecaptcha
			authcFilter.setCaptchaEnabled(kaptchaProperties.isEnabled());
			// captcha解析器
			authcFilter.setCaptchaResolver(captchaResolver);
		}
		/*
		 * 自定义Filter通过@Bean注解后，被Spring Boot自动registers到了容器的Filter
		 * chain中，这样导致的结果是，所有URL都会被自定义Filter过滤， 而不是Shiro中configuration的一部分URL。下面方式可以解决该问题
		 */
		FilterRegistrationBean<SamlAuthenticatingFilter> registration = new FilterRegistrationBean<SamlAuthenticatingFilter>(
				authcFilter);
		registration.setEnabled(false);
		return registration;
	}
	 
	/**
	 * permission控制filter ：permission过滤链的入口（仅是FactoryBean需要引用）
	 */
	@Bean
    @Override
	protected ShiroFilterFactoryBean shiroFilterFactoryBean() {

		ShiroFilterFactoryBean filterFactoryBean = new ShiroFilterProxyFactoryBean();
		
		// loginaddress：session不存在时访问的address
		filterFactoryBean.setLoginUrl(bizProperties.getLoginUrl());
		// 系统主页：loginsuccess后跳转path
		filterFactoryBean.setSuccessUrl(bizProperties.getSuccessUrl());
		// exception页面：无permission时的跳转path
		filterFactoryBean.setUnauthorizedUrl(bizProperties.getUnauthorizedUrl());
		// 必须sets SecurityManager
		filterFactoryBean.setSecurityManager(securityManager);
		// 拦截规则
		filterFactoryBean.setFilterChainDefinitionMap(shiroFilterChainDefinition.getFilterChainMap());
		
		return filterFactoryBean;
	}
	
	/**
	 * permission控制filter ：permission过滤链的入口
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
