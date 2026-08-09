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

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;

/**
 * SignatureUtils for SAML request signing.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public class SignatureUtils {

    private Credential signingCredential;
    private String canonicalizationAlgorithm;
    private String signatureAlgorithm;

    public SignatureUtils() {
    }

    public SignatureUtils(Credential signingCredential, String canonicalizationAlgorithm, String signatureAlgorithm) {
        this.signingCredential = signingCredential;
        this.canonicalizationAlgorithm = canonicalizationAlgorithm;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * Sign a SAML XML object.
     *
     * @param obj the signable XML object
     */
    /**
     * Sign a SAML XML object.
     *
     * @param obj the signable XML object
     */
    public void signRequest(SignableXMLObject obj) {
        if (signingCredential == null) {
            return;
        }
        try {
            Signature signature = (Signature) XMLObjectProviderRegistrySupport.getBuilderFactory()
                    .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
                    .buildObject(Signature.DEFAULT_ELEMENT_NAME);
            signature.setSigningCredential(signingCredential);
            if (canonicalizationAlgorithm != null) {
                signature.setCanonicalizationAlgorithm(canonicalizationAlgorithm);
            }
            if (signatureAlgorithm != null) {
                signature.setSignatureAlgorithm(signatureAlgorithm);
            }
            obj.setSignature(signature);
            Signer.signObject(signature);
        } catch (Exception e) {
            // signing failed
        }
    }

    public Credential getSigningCredential() {
        return signingCredential;
    }

    public void setSigningCredential(Credential signingCredential) {
        this.signingCredential = signingCredential;
    }

    public String getCanonicalizationAlgorithm() {
        return canonicalizationAlgorithm;
    }

    public void setCanonicalizationAlgorithm(String canonicalizationAlgorithm) {
        this.canonicalizationAlgorithm = canonicalizationAlgorithm;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }
}
