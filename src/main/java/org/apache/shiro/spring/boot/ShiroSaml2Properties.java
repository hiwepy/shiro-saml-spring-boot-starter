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
package org.apache.shiro.spring.boot;

import org.apache.shiro.spring.boot.saml.AuthnContextComparisonType;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(ShiroSaml2Properties.PREFIX)
public class ShiroSaml2Properties {

	public static final String PREFIX = "shiro.saml2";
	
	/**
	 * Enable Shiro Saml2.
	 */
	private boolean enabled = false;

	/** 目标URL：AuthnRequest的目标地址，IDP地址 */
	private String destinationURL;
	/** SP地址： SAML断言返回的地址 */
    private String assertionConsumerServiceURL;
	/** SPID：一般是SP的URL */
    private String spEntityId;
    /** 异常页面：无权限时的跳转路径 */
    private String unauthorizedUrl;
    private boolean forceAuthn;
    
    /** Specifies the name of the request parameter on where to find the SAMLRequest (i.e. SAMLRequest). */
	private String samlRequestParameterName = "SAMLRequest";
    /** Name of parameter containing the state of the RelayState. */
	private String relayStateParameterName = "RelayState";
    
    
    /** */
    private AuthnContextComparisonType comparisonType = AuthnContextComparisonType.minimum;
	
	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getDestinationURL() {
		return destinationURL;
	}

	public void setDestinationURL(String destinationURL) {
		this.destinationURL = destinationURL;
	}

	public String getAssertionConsumerServiceURL() {
		return assertionConsumerServiceURL;
	}

	public void setAssertionConsumerServiceURL(String assertionConsumerServiceURL) {
		this.assertionConsumerServiceURL = assertionConsumerServiceURL;
	}

	public String getSpEntityId() {
		return spEntityId;
	}

	public void setSpEntityId(String spEntityId) {
		this.spEntityId = spEntityId;
	}

	public String getUnauthorizedUrl() {
		return unauthorizedUrl;
	}

	public void setUnauthorizedUrl(String unauthorizedUrl) {
		this.unauthorizedUrl = unauthorizedUrl;
	}
	
	public boolean isForceAuthn() {
		return forceAuthn;
	}

	public void setForceAuthn(boolean forceAuthn) {
		this.forceAuthn = forceAuthn;
	}

	public AuthnContextComparisonType getComparisonType() {
		return comparisonType;
	}

	public void setComparisonType(AuthnContextComparisonType comparisonType) {
		this.comparisonType = comparisonType;
	}

	public String getSamlRequestParameterName() {
		return samlRequestParameterName;
	}

	public void setSamlRequestParameterName(String samlRequestParameterName) {
		this.samlRequestParameterName = samlRequestParameterName;
	}

	public String getRelayStateParameterName() {
		return relayStateParameterName;
	}

	public void setRelayStateParameterName(String relayStateParameterName) {
		this.relayStateParameterName = relayStateParameterName;
	}

}

