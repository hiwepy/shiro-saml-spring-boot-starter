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
package org.apache.shiro.spring.boot.saml.token;

import org.apache.shiro.authc.HostAuthenticationToken;

/**
 * Saml 2.0 Token
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@SuppressWarnings("serial")
public final class Saml2Token implements HostAuthenticationToken {
    
	// 客户端IP
 	private String host;
 	// SAMLRequest 字符串
 	private String SAMLRequest;
 	// whether记住客户端authentication状态
     private final boolean isRememberMe;
     
     public Saml2Token(String host, String SAMLRequest, boolean isRememberMe) {
     	this.host = host;
         this.SAMLRequest = SAMLRequest;
         this.isRememberMe = isRememberMe;
     }
     
     @Override
 	/**
 	 * Returns the principal.
 	 *
 	 * @return the principal
 	 */
 	public Object getPrincipal() {
 		return this.SAMLRequest;
 	}

 	@Override
 	/**
 	 * Returns the credentials.
 	 *
 	 * @return the credentials
 	 */
 	public Object getCredentials() {
 		return this.SAMLRequest;
 	}
 	
 	@Override
 	/**
 	 * Returns the host.
 	 *
 	 * @return the host
 	 */
 	public String getHost() {
 		return host;
 	}

 	/**
 	 * Returns the s a m l request.
 	 *
 	 * @return the s a m l request
 	 */
 	public String getSAMLRequest() {
 		return SAMLRequest;
 	}
 	
 	/**
 	 * Returns the remember me.
 	 *
 	 * @return the remember me
 	 */
 	public boolean isRememberMe() {
 		return isRememberMe;
 	}
 	
}

