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
package org.apache.shiro.spring.boot.saml.utils;

import org.opensaml.core.config.Configuration;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;

public class SignatureUtils {

	 private void signRequest(SignableXMLObject obj) {
	        Credential credential = this.getCredential(SP_PRIVATEKEY, SP_CERTIFICATE);
	        Signature signature = (Signature) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME)
	                .buildObject(Signature.DEFAULT_ELEMENT_NAME);
	        signature.setSigningCredential(credential);
	        signature.setCanonicalizationAlgorithm(getIdpSignature().getCanonicalizationAlgorithm());
	        signature.setSignatureAlgorithm(getIdpSignature().getSignatureAlgorithm());
	        SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();
	        try {
	            SecurityHelper.prepareSignatureParams(signature, credential, secConfig, null);
	            obj.setSignature(signature);
	            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(obj).marshall(obj);
	            Signer.signObject(signature);
	        } catch (Exception e) {

	        }
	    }
	    
}
