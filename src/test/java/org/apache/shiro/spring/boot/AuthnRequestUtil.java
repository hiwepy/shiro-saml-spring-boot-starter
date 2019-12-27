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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Base64;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.naming.ConfigurationException;
import javax.xml.namespace.QName;

import org.joda.time.DateTime;
import org.opensaml.core.config.Configuration;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.impl.KeyInfoBuilder;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.xmlsec.signature.support.Signer;
import org.slf4j.Logger;
import org.w3c.dom.Element;
 
public class AuthnRequestUtil {
 
    /**
     * @param args
     */
    public static void main(String[] args) {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            e.printStackTrace();
        }
        String actionUrl = "http://127.0.0.1:8080/idp";
        String redirectionUrl = "http://127.0.0.1:8080/sp";
        System.out.println(buildAuthnRequest(actionUrl,redirectionUrl, "1"));
 
    }
    

	
   
    public String buildAuthnRequest()  {
        QName qname = new javax.xml.namespace.QName(SSO_METDATA_QNAME);
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer", "samlp");
        issuer.setValue(issuer.getValue());
        DateTime issueInstant = new DateTime();
        AuthnRequestBuilder authnRequestBuilder = new AuthnRequestBuilder();
        AuthnRequest authnRequest = authnRequestBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:protocol","AuthnRequest", "samlp");
        authnRequest.setAssertionConsumerServiceURL("http://test.com");
//      Signature sign = null;
//      sign.setSignatureAlgorithm("SHA256");
//      Credential credential = null;
//      sign.setSigningCredential(credential);
//      authnRequest.setSignature(sign);
        NameIDPolicyBuilder policy = new NameIDPolicyBuilder();
        NameIDPolicy pol = policy.buildObject();
        RequestedAuthnContextBuilder contextBuild = new RequestedAuthnContextBuilder();
        RequestedAuthnContext context = contextBuild.buildObject();
        authnRequest.setRequestedAuthnContext(context);
        authnRequest.setNameIDPolicy(pol);
        authnRequest.setForceAuthn(new Boolean(false));
        authnRequest.setIsPassive(new Boolean(false));
        authnRequest.setIssueInstant(issueInstant);
        authnRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        authnRequest.setAssertionConsumerServiceURL(issuer.getElementQName().getNamespaceURI());
        authnRequest.setProviderName("RGI");
        authnRequest.setIssuer(issuer);
        authnRequest.setID(UUID.randomUUID().toString());
        authnRequest.setVersion(SAMLVersion.VERSION_20);
       
        // Add signature to request
        SignatureBuilder signBuilder = new SignatureBuilder();
        Signature signature = signBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSchemaLocation("http://www.w3.org/2000/09/xmldsig#");
        signature.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        signature.setCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");
        KeyInfoBuilder keyBuilder = new KeyInfoBuilder();
        KeyInfo key = keyBuilder.buildObject();
        key.setID(UUID.randomUUID().toString());
        signature.setKeyInfo(key);
        
        signature.setCanonicalizationAlgorithm(getIdpSignature().getCanonicalizationAlgorithm());
        signature.setSignatureAlgorithm(getIdpSignature().getSignatureAlgorithm());
        signature.setSigningCredential(this.getCredentialFromFiles(SP_PRIVATEKEY,SP_CERTIFICATE));
        // set signature
        authnRequest.setSignature(signature);

//      RequestedAuthnContextBuilder requestContext = new RequestedAuthnContextBuilder();
//      RequestedAuthnContext rx = requestContext.buildObject(qname);
//      authne
//      rx.setComparison(arg0);
//      authnRequest.setRequestedAuthnContext(arg0);

        Logger.info("AUTHNREQUEST: "+authnRequest.toString());

        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(authnRequest);
        /* Encoding the compressed message */
        String encodedRequestMessage = null;
        String redirectionUrl = null;
        try {
            Element authDOM = marshaller.marshall(authnRequest);
            StringWriter rspWrt = new StringWriter();
            XMLHelper.writeNode(authDOM, rspWrt);
            String requestMessage = rspWrt.toString();
            utils.saveToFile("authmnRequest.xml", requestMessage);
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
            deflaterOutputStream.write(requestMessage.getBytes());
            deflaterOutputStream.close();
            encodedRequestMessage = Base64.encodeBytes(byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);
            String encodedAuthnRequest = URLEncoder.encode(encodedRequestMessage,"UTF-8").trim();
            String identitypProviderUrl = SignInUrl;
            redirectionUrl = identitypProviderUrl + "?SAMLRequest="+ encodedRequestMessage;
            Logger.info("RedirectionUrl: "+redirectionUrl);
            return redirectionUrl;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (MarshallingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return redirectionUrl;
    }
 
    /**
     * @param actionUrl
     * @param redirectionUrl
     * @param relayState
     * @return
     */
    public static String buildAuthnRequest(String actionURL,String redirectionUrl,
            String relayState) {
        try {
            // 生成ID
            String randId = Math.abs(UUID.randomUUID().getMostSignificantBits())+ "";
            System.out.println("Random ID: " + randId);
 
            // 创建 issuer Object
            IssuerBuilder issuerBuilder = new IssuerBuilder();
            Issuer issuer = issuerBuilder.buildObject(
                    "urn:oasis:names:tc:SAML:2.0:assertion", "Issuer", "samlp");
            issuer.setValue(actionURL);
 
            // 创建 NameIDPolicy
            NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
            NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
            nameIdPolicy.setSchemaLocation("urn:oasis:names:tc:SAML:2.0:protocol");
            nameIdPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
            nameIdPolicy.setSPNameQualifier(redirectionUrl);
            nameIdPolicy.setAllowCreate(true);
 
            // Create AuthnContextClassRef
            AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
            AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder
                    .buildObject("urn:oasis:names:tc:SAML:2.0:assertion",
                            "AuthnContextClassRef", "saml");
            authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
             
            // Create RequestedAuthnContext
            RequestedAuthnContextBuilder requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
            RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder
                    .buildObject();
            requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
            requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
 
            DateTime issueInstant = new DateTime();
            AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
            AuthnRequest authRequest = authRequestBuilder.buildObject(
                    "urn:oasis:names:tc:SAML:2.0:protocol", "AuthnRequest",
                    "samlp");
            authRequest.setForceAuthn(false);
            authRequest.setIsPassive(false);
            authRequest.setIssueInstant(issueInstant);
            authRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
            authRequest.setAssertionConsumerServiceURL(redirectionUrl);
            authRequest.setIssuer(issuer);
            authRequest.setNameIDPolicy(nameIdPolicy);
            authRequest.setRequestedAuthnContext(requestedAuthnContext);
            authRequest.setID(randId);
            authRequest.setVersion(SAMLVersion.VERSION_20);
             
            String stringRep = authRequest.toString();
             
            System.out.println("New AuthnRequestImpl: " + stringRep);
            System.out.println("Assertion Consumer Service URL: " + authRequest.getAssertionConsumerServiceURL());
 
            Marshaller marshaller = org.opensaml.saml.Configuration.getMarshallerFactory().getMarshaller(authRequest);
            org.w3c.dom.Element authDOM = marshaller.marshall(authRequest);
            StringWriter rspWrt = new StringWriter();
            XMLHelper.writeNode(authDOM, rspWrt);
            String messageXML = rspWrt.toString();
 
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(
                    byteArrayOutputStream, deflater);
            deflaterOutputStream.write(messageXML.getBytes());
            deflaterOutputStream.close();
            String samlResponse = Base64.encodeBytes(byteArrayOutputStream
                    .toByteArray(), Base64.DONT_BREAK_LINES);
            String outputString = new String(byteArrayOutputStream.toByteArray());
            System.out.println("Compressed String: " + outputString);
            samlResponse = URLEncoder.encode(samlResponse, "UTF-8");
 
            System.out.println("Converted AuthRequest: " + messageXML);
            System.out.println("samlResponse: " + samlResponse);
            // messageXML = messageXML.replace("<", "&lt;");
            // messageXML = messageXML.replace(">", "&gt;");
 
            String url = actionURL + "?SAMLRequest=" + samlResponse + "&RelayState=" + relayState;
            System.out.println(url);
            return url;
        } catch (MarshallingException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            // Nothing yet
        }
        return "";
    }
}