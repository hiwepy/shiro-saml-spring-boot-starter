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
package org.apache.shiro.spring.boot.saml2.utils;

import java.util.UUID;

import org.joda.time.DateTime;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;

/**
 * TODO
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */

public class AuthnRequestUtils {

	/**
     * 创建AutheRequest对象 * @param idpSsoUrl
      * @param acsUrl
      * @param spEntityId
      * @return
      */
    public static AuthnRequest createRequest(String idpSsoUrl,String acsUrl,String spEntityId){
        AuthnRequest authnRequest = create(AuthnRequest.class,AuthnRequest.DEFAULT_ELEMENT_NAME);
      authnRequest.setIssueInstant(new DateTime());
      authnRequest.setDestination(idpSsoUrl);
      authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
      authnRequest.setID(UUID.randomUUID().toString());
      authnRequest.setAssertionConsumerServiceURL(acsUrl);

      Issuer issuer = create(Issuer.class,Issuer.DEFAULT_ELEMENT_NAME);
      issuer.setValue(spEntityId);
      authnRequest.setIssuer(issuer);

      NameIDPolicy nameIDPolicy = create(NameIDPolicy.class,NameIDPolicy.DEFAULT_ELEMENT_NAME);
      nameIDPolicy.setAllowCreate(true);
      nameIDPolicy.setFormat(NameID.UNSPECIFIED);
      authnRequest.setNameIDPolicy(nameIDPolicy);
     return authnRequest;
    }
	
}
