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

import org.apache.shiro.biz.authz.principal.ShiroPrincipal;

/**
 * TODO
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
@SuppressWarnings("serial")
public class SamlPayloadPrincipal extends ShiroPrincipal {

	// SAMLRequest 字符串
	private final String payload;
	
	public SamlPayloadPrincipal(String payload) {
		this.payload = payload;
	}
	
	public String getPayload() {
		return payload;
	}
	
}
