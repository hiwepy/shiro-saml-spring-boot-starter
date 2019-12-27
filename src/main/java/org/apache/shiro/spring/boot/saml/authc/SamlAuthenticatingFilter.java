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
package org.apache.shiro.spring.boot.saml.authc;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authz.principal.ShiroPrincipal;
import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authc.TrustableRestAuthenticatingFilter;
import org.apache.shiro.biz.web.filter.authc.listener.LoginListener;
import org.apache.shiro.spring.boot.saml.exception.ExpiredSamlException;
import org.apache.shiro.spring.boot.saml.exception.IncorrectSamlException;
import org.apache.shiro.spring.boot.saml.exception.InvalidSamlToken;
import org.apache.shiro.spring.boot.saml.token.SamlToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.alibaba.fastjson.JSONObject;


/**
 * SAML 1.x 认证 (authentication)过滤器
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class SamlAuthenticatingFilter extends TrustableRestAuthenticatingFilter {

	private static final Logger LOG = LoggerFactory.getLogger(SamlAuthenticatingFilter.class);
	
	/**
     * HTTP Authorization header, equal to <code>Authorization</code>
     */
    protected static final String AUTHORIZATION_HEADER = "Authorization";
    private String authorizationHeaderName = AUTHORIZATION_HEADER;
    
	protected static final String AUTHORIZATION_PARAM =  "SAMLRequest";
	private String authorizationParamName = AUTHORIZATION_PARAM;
    
	public SamlAuthenticatingFilter() {
		super();
	}
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
		// 判断是否无状态
		if (isSessionStateless()) {
			// 判断是否认证请求  
			if (!isLoginRequest(request, response) && isSamlSubmission(request, response)) {
				// Step 1、生成无状态Token 
				AuthenticationToken token = createSamlToken(request, response);
				try {
					//Step 2、委托给Realm进行登录  
					Subject subject = getSubject(request, response);
					subject.login(token);
					//Step 3、执行授权成功后的函数
					return onAccessSuccess(token, subject, request, response);
				} catch (AuthenticationException e) {
					//Step 4、执行授权失败后的函数
					return onAccessFailure(token, e, request, response);
				}
			}
			// 要求认证
			return false;
		}
		return super.isAccessAllowed(request, response, mappedValue);
	}
	
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		
		// 1、判断是否登录请求 
		if (isLoginRequest(request, response)) {
			if (isLoginSubmission(request, response)) {
				if (LOG.isTraceEnabled()) {
					LOG.trace("Login submission detected.  Attempting to execute login.");
				}
				return executeLogin(request, response);
			} else {
				String mString = "Authentication url [" + getLoginUrl() + "] Not Http Post request.";
				if (LOG.isTraceEnabled()) {
					LOG.trace(mString);
				}
				WebUtils.getHttpResponse(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
				JSONObject.writeJSONString(response.getWriter(), mString);
				return false;
			}
		}
		// 2、未授权情况
		else if (!isSamlSubmission(request, response)) {
			
			String mString = String.format("Attempting to access a path which requires authentication.  %s = Authorization Header or %s = Authorization Param is not present in the request", 
					getAuthorizationHeaderName(), getAuthorizationParamName());
			if (LOG.isTraceEnabled()) { 
				LOG.trace(mString);
			}
			
			// 响应成功状态信息
			Map<String, Object> data = new HashMap<String, Object>();
			data.put("status", "fail");
			data.put("message", mString);
			// 响应
			JSONObject.writeJSONString(response.getWriter(), data);
			
			return false;
		}
		
		return false;
	}

	@Override
	protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request,
			ServletResponse response) throws Exception {

		// 调用事件监听器
		if (getLoginListeners() != null && getLoginListeners().size() > 0) {
			for (LoginListener loginListener : getLoginListeners()) {
				loginListener.onSuccess(token, subject, request, response);
			}
		}

		// 响应成功状态信息
		Map<String, Object> data = new HashMap<String, Object>();
		data.put("status", "success");
		data.put("message", "Authentication Success.");
		
		ShiroPrincipal principal = (ShiroPrincipal) subject.getPrincipal();
		Map<String, Object> mapPrincipal =  new HashMap<>();
		mapPrincipal.put("userid", principal.getUserid());
		mapPrincipal.put("userkey", principal.getUserkey());
		mapPrincipal.put("username", principal.getUsername());
		mapPrincipal.put("perms", principal.getPerms());
		mapPrincipal.put("roles", principal.getRoles());
		data.put("principal", mapPrincipal);
		
		// 响应
		JSONObject.writeJSONString(response.getWriter(), data);
		
		// we handled the success , prevent the chain from continuing:
		return false;

	}
	
	@Override
	protected boolean onAccessFailure(AuthenticationToken token, Exception e, ServletRequest request,
			ServletResponse response) {
		
		LOG.error("Host {} JWT Authentication Failure : {}", getHost(request), e.getMessage());
		
		//WebUtils.getHttpResponse(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		// 响应异常状态信息
		Map<String, Object> data = new HashMap<String, Object>();
		data.put("status", "fail");
		
		// Saml错误
		if (e instanceof IncorrectSamlException) {
			data.put("message", "JWT is incorrect.");
			data.put("token", "incorrect");
		}
		// Saml无效
		else if (e instanceof InvalidSamlToken) {
			data.put("message", "Invalid JWT value.");
			data.put("token", "invalid");
		}
		// Saml过期
		else if (e instanceof ExpiredSamlException) {
			data.put("message", "Expired JWT value. " );
			data.put("token", "expiry");
		} else {
			String rootCause = ExceptionUtils.getRootCauseMessage(e);
			data.put("message", StringUtils.hasText(rootCause) ? rootCause : ExceptionUtils.getMessage(e));
		}
		
		try {
			JSONObject.writeJSONString(response.getWriter(), data);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return false;
	}
	
	protected AuthenticationToken createSamlToken(ServletRequest request, ServletResponse response) {
		String host = WebUtils.getRemoteAddr(request);
		String SAMLRequest = getSAMLRequest(request);
		return new SamlToken(host, SAMLRequest, isRememberMe(request));
	}

    protected boolean isSamlSubmission(ServletRequest request, ServletResponse response) {
    	 String SAMLRequest = getSAMLRequest(request);
		return (request instanceof HttpServletRequest) && SAMLRequest != null;
	}
    
    protected String getSAMLRequest(ServletRequest request) {
    	HttpServletRequest httpRequest = WebUtils.toHttp(request);
        //从header中获取SAMLRequest
        String token = httpRequest.getHeader(getAuthorizationHeaderName());
        //如果header中不存在SAMLRequest，则从参数中获取SAMLRequest
        if (StringUtils.isEmpty(token)) {
            return httpRequest.getParameter(getAuthorizationParamName());
        }
        return token;
    }

	public String getAuthorizationHeaderName() {
		return authorizationHeaderName;
	}

	public void setAuthorizationHeaderName(String authorizationHeaderName) {
		this.authorizationHeaderName = authorizationHeaderName;
	}

	public String getAuthorizationParamName() {
		return authorizationParamName;
	}

	public void setAuthorizationParamName(String authorizationParamName) {
		this.authorizationParamName = authorizationParamName;
	}

}
