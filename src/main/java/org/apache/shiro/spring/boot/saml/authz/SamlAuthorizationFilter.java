package org.apache.shiro.spring.boot.saml.authz;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.springframework.util.StringUtils;
import org.apache.shiro.biz.utils.WebUtils2;
import org.apache.shiro.biz.web.filter.authz.AbstracAuthorizationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.apache.shiro.spring.boot.saml.exception.ExpiredSamlException;
import org.apache.shiro.spring.boot.saml.exception.IncorrectSamlException;
import org.apache.shiro.spring.boot.saml.exception.InvalidSamlToken;
import org.apache.shiro.spring.boot.saml.token.SamlToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.alibaba.fastjson.JSONObject;

/**
 * SAML 1.x authorization (authorization)filter
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class SamlAuthorizationFilter extends AbstracAuthorizationFilter {

	private static final Logger LOG = LoggerFactory.getLogger(SamlAuthorizationFilter.class);
	/**
     * HTTP Authorization header, equal to <code>Authorization</code>
     */
    protected static final String AUTHORIZATION_HEADER = "Authorization";
    private String authorizationHeaderName = AUTHORIZATION_HEADER;
    
	protected static final String AUTHORIZATION_PARAM =  "SAMLRequest";
	private String authorizationParamName = AUTHORIZATION_PARAM;
	
	@Override
	/**
	 * on Pre Handle.
	 *
	 * @param request the request
	 * @param response the response
	 * @param mappedValue the mapped value
	 * @return the result
	 * @throws Exception if an error occurs
	 */
	public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
		return super.onPreHandle(request, response, mappedValue);
	}
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		// 判断whetherauthenticationrequest  
		if (isSamlSubmission(request, response)) {
			// Step 1、生成无状态Token 
			AuthenticationToken token = createSamlToken(request, response);
			try {
				//Step 2、委托给Realm进行login  
				Subject subject = getSubject(request, response);
				subject.login(token);
				//Step 3、执行authorizationsuccess后的函数
				return onAccessSuccess(mappedValue, subject, request, response);
			} catch (AuthenticationException e) {
				//Step 4、执行authorizationfailure后的函数
				return onAccessFailure(mappedValue, e, request, response);
			} 
		}
		
		String mString = String.format("Attempting to access a path which requires authentication.  %s = Authorization Header or %s = Authorization Param  is not present in the request", 
				getAuthorizationHeaderName(), getAuthorizationParamName());
		if (LOG.isTraceEnabled()) { 
			LOG.trace(mString);
		}
		
		// responsesuccess状态info
		Map<String, Object> data = new HashMap<String, Object>();
		data.put("status", "fail");
		data.put("message", mString);
		// response
		JSONObject.writeJSONString(response.getWriter(), data);
		
		return false;
	}
	
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws IOException {
		return false;
	}

	protected boolean onAccessFailure(Object mappedValue, Exception e, ServletRequest request,
			ServletResponse response) throws IOException {

		LOG.error("Host {} JWT Authentication Failure : {}", getHost(request), e.getMessage());

		//WebUtils.getHttpResponse(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		// responseexception状态info
		Map<String, Object> data = new HashMap<String, Object>();
		data.put("status", "fail");
		// Samlerror
		if (e instanceof IncorrectSamlException) {
			data.put("message", "JWT is incorrect.");
			data.put("token", "incorrect");
		}
		// Saml无效
		else if (e instanceof InvalidSamlToken) {
			data.put("message", "Invalid JWT value.");
			data.put("token", "invalid");
		}
		// Samlexpire
		else if (e instanceof ExpiredSamlException) {
			data.put("message", "Expired JWT value. " );
			data.put("token", "expiry");
		} else {
			String rootCause = ExceptionUtils.getRootCauseMessage(e);
			data.put("message", StringUtils.hasText(rootCause) ? rootCause : ExceptionUtils.getMessage(e));
		}
		JSONObject.writeJSONString(response.getWriter(), data);
		return false;
	}

	protected AuthenticationToken createSamlToken(ServletRequest request, ServletResponse response) {
		String host = WebUtils2.getRemoteAddr(request);
		String jwtToken = getSAMLRequest(request);
		return new SamlToken(host, jwtToken, true);
	}
	
    protected boolean isSamlSubmission(ServletRequest request, ServletResponse response) {
    	 String authzHeader = getSAMLRequest(request);
		return (request instanceof HttpServletRequest) && authzHeader != null;
	}
    
    protected String getSAMLRequest(ServletRequest request) {
    	HttpServletRequest httpRequest = WebUtils.toHttp(request);
        //从header中getsSAMLRequest
        String token = httpRequest.getHeader(getAuthorizationHeaderName());
        //如果header中不存在SAMLRequest，则从参数中getsSAMLRequest
        if (StringUtils.isEmpty(token)) {
            return httpRequest.getParameter(getAuthorizationParamName());
        }
        return token;
    }

    /**
     * Returns the authorization header name.
     *
     * @return the authorization header name
     */
    public String getAuthorizationHeaderName() {
		return authorizationHeaderName;
	}

	/**
	 * Sets the authorization header name.
	 *
	 * @param authorizationHeaderName the authorization header name
	 */
	public void setAuthorizationHeaderName(String authorizationHeaderName) {
		this.authorizationHeaderName = authorizationHeaderName;
	}
	
	/**
	 * Returns the authorization param name.
	 *
	 * @return the authorization param name
	 */
	public String getAuthorizationParamName() {
		return authorizationParamName;
	}

	/**
	 * Sets the authorization param name.
	 *
	 * @param authorizationParamName the authorization param name
	 */
	public void setAuthorizationParamName(String authorizationParamName) {
		this.authorizationParamName = authorizationParamName;
	}
	
}
