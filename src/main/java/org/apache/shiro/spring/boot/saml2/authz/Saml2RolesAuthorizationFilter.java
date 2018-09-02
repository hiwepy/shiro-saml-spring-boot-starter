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
package org.apache.shiro.spring.boot.saml2.authz;


import org.apache.shiro.biz.web.filter.authz.RolesAuthorizationFilter;

import com.github.scribejava.core.oauth.OAuth20Service;

/**
 * This class specializes the RolesAuthorizationFilter to have a login url which is the authorization url of the OAuth provider.
 */
public final class Saml2RolesAuthorizationFilter extends RolesAuthorizationFilter {
    
	private OAuth20Service oauth20Service;
	
	@Override
    public String getLoginUrl() {
        return getOauth20Service().getAuthorizationUrl();
    }

	public OAuth20Service getOauth20Service() {
		return oauth20Service;
	}

	public void setOauth20Service(OAuth20Service oauth20Service) {
		this.oauth20Service = oauth20Service;
	}
    
}

