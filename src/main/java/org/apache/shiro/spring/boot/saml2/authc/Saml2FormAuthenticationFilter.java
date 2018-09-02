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
package org.apache.shiro.spring.boot.saml2.authc;

import java.io.StringWriter;
import java.util.UUID;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.shiro.spring.boot.saml2.utils.AuthnRequestUtils;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.joda.time.DateTime;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.w3c.dom.Document;

/**
 * This class specializes the FormAuthenticationFilter to have a login url which is the authorization url of the OAuth provider.
 */
public final class Saml2FormAuthenticationFilter extends FormAuthenticationFilter {
    
    
    @Override
    public String getLoginUrl() {
    	
    	AuthnRequest authnRequest = AuthnRequestUtils.createRequest(idpSsoUrl, acsUrl, spEntityId);
    	
    	Document document = asDOMDocument(authnRequest);
    	DOMSource source=new DOMSource(document);
    	TransformerFactory tf = TransformerFactory.newInstance();
    	Transformer former=tf.newTransformer();
    	former.setOutputProperty(OutputKeys.STANDALONE, "yes");
    	StringWriter sw = new StringWriter();
    	StreamResult sr = new StreamResult(sw);
    	former.transform(source, sr);
    	String result=sw.toString();
    	
    	
        return result;
    }

    
    
}
