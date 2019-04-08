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
package org.apache.shiro.spring.boot.saml;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.biz.authz.principal.ShiroPrincipalRepositoryImpl;
import org.apache.shiro.spring.boot.saml.token.SamlToken;

/**
 * SAML 1.0 Principal Repository
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class SamlPrincipalRepository extends ShiroPrincipalRepositoryImpl {

	@Override
	public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		
		SamlToken samlToken = (SamlToken) token;
		
		SamlPayloadPrincipal principal = new SamlPayloadPrincipal(samlToken.getSAMLRequest());
		/*
		principal.setUserid(payload.getClientId());
		principal.setUserkey(payload.getClientId());
		principal.setRoles(Sets.newHashSet(StringUtils.tokenizeToStringArray(payload.getRoles())));
		principal.setPerms(Sets.newHashSet(StringUtils.tokenizeToStringArray(payload.getPerms())));
		*/
		return new SimpleAuthenticationInfo(principal, samlToken.getCredentials(), "SAML");
		
	}
	
}
