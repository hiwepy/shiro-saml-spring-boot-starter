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

import org.apache.shiro.spring.boot.saml.AuthnContextComparisonType;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * ShiroSaml2Properties.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@ConfigurationProperties(ShiroSaml2Properties.PREFIX)
public class ShiroSaml2Properties {

	public static final String PREFIX = "shiro.saml2";
	
	/**
	 * Enable Shiro Saml2.
	 */
	private boolean enabled = false;

	/** 目标URL：AuthnRequest的目标address，IDPaddress */
	private String destinationURL;
	/** SPaddress： SAML断言returns的address */
    private String assertionConsumerServiceURL;
	/** SPID：一般是SP的URL */
    private String spEntityId;
    /** exception页面：无permission时的跳转path */
    private String unauthorizedUrl;
    private boolean forceAuthn;
    
    /** Specifies the name of the request parameter on where to find the SAMLRequest (i.e. SAMLRequest). */
	private String samlRequestParameterName = "SAMLRequest";
    /** Name of parameter containing the state of the RelayState. */
	private String relayStateParameterName = "RelayState";
    
    
    /** */
    private AuthnContextComparisonType comparisonType = AuthnContextComparisonType.minimum;
	
	/**
	 * Returns the enabled.
	 *
	 * @return the enabled
	 */
	public boolean isEnabled() {
		return enabled;
	}

	/**
	 * Sets the enabled.
	 *
	 * @param enabled the enabled
	 */
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	/**
	 * Returns the destination u r l.
	 *
	 * @return the destination u r l
	 */
	public String getDestinationURL() {
		return destinationURL;
	}

	/**
	 * Sets the destination u r l.
	 *
	 * @param destinationURL the destination u r l
	 */
	public void setDestinationURL(String destinationURL) {
		this.destinationURL = destinationURL;
	}

	/**
	 * Returns the assertion consumer service u r l.
	 *
	 * @return the assertion consumer service u r l
	 */
	public String getAssertionConsumerServiceURL() {
		return assertionConsumerServiceURL;
	}

	/**
	 * Sets the assertion consumer service u r l.
	 *
	 * @param assertionConsumerServiceURL the assertion consumer service u r l
	 */
	public void setAssertionConsumerServiceURL(String assertionConsumerServiceURL) {
		this.assertionConsumerServiceURL = assertionConsumerServiceURL;
	}

	/**
	 * Returns the sp entity id.
	 *
	 * @return the sp entity id
	 */
	public String getSpEntityId() {
		return spEntityId;
	}

	/**
	 * Sets the sp entity id.
	 *
	 * @param spEntityId the sp entity id
	 */
	public void setSpEntityId(String spEntityId) {
		this.spEntityId = spEntityId;
	}

	/**
	 * Returns the unauthorized url.
	 *
	 * @return the unauthorized url
	 */
	public String getUnauthorizedUrl() {
		return unauthorizedUrl;
	}

	/**
	 * Sets the unauthorized url.
	 *
	 * @param unauthorizedUrl the unauthorized url
	 */
	public void setUnauthorizedUrl(String unauthorizedUrl) {
		this.unauthorizedUrl = unauthorizedUrl;
	}
	
	/**
	 * Returns the force authn.
	 *
	 * @return the force authn
	 */
	public boolean isForceAuthn() {
		return forceAuthn;
	}

	/**
	 * Sets the force authn.
	 *
	 * @param forceAuthn the force authn
	 */
	public void setForceAuthn(boolean forceAuthn) {
		this.forceAuthn = forceAuthn;
	}

	/**
	 * Returns the comparison type.
	 *
	 * @return the comparison type
	 */
	public AuthnContextComparisonType getComparisonType() {
		return comparisonType;
	}

	/**
	 * Sets the comparison type.
	 *
	 * @param comparisonType the comparison type
	 */
	public void setComparisonType(AuthnContextComparisonType comparisonType) {
		this.comparisonType = comparisonType;
	}

	/**
	 * Returns the saml request parameter name.
	 *
	 * @return the saml request parameter name
	 */
	public String getSamlRequestParameterName() {
		return samlRequestParameterName;
	}

	/**
	 * Sets the saml request parameter name.
	 *
	 * @param samlRequestParameterName the saml request parameter name
	 */
	public void setSamlRequestParameterName(String samlRequestParameterName) {
		this.samlRequestParameterName = samlRequestParameterName;
	}

	/**
	 * Returns the relay state parameter name.
	 *
	 * @return the relay state parameter name
	 */
	public String getRelayStateParameterName() {
		return relayStateParameterName;
	}

	/**
	 * Sets the relay state parameter name.
	 *
	 * @param relayStateParameterName the relay state parameter name
	 */
	public void setRelayStateParameterName(String relayStateParameterName) {
		this.relayStateParameterName = relayStateParameterName;
	}

}

