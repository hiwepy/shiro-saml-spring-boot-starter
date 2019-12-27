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
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
@SuppressWarnings("serial")
public final class Saml2Token implements HostAuthenticationToken {
    
	// 客户端IP
 	private String host;
 	// SAMLRequest 字符串
 	private String SAMLRequest;
 	// 是否记住客户端认证状态
     private final boolean isRememberMe;
     
     public Saml2Token(String host, String SAMLRequest, boolean isRememberMe) {
     	this.host = host;
         this.SAMLRequest = SAMLRequest;
         this.isRememberMe = isRememberMe;
     }
     
     @Override
 	public Object getPrincipal() {
 		return this.SAMLRequest;
 	}

 	@Override
 	public Object getCredentials() {
 		return this.SAMLRequest;
 	}
 	
 	@Override
 	public String getHost() {
 		return host;
 	}

 	public String getSAMLRequest() {
 		return SAMLRequest;
 	}
 	
 	public boolean isRememberMe() {
 		return isRememberMe;
 	}
 	
}

