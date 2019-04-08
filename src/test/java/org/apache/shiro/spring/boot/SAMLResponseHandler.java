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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.codec.binary.Base64;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class SAMLResponseHandler {

	private static final String certificateS = "MIIENTCCAx2gAwIBAgIUDFWeXo2US+Je8Erqdc2IvREy8IswDQYJKoZIhvcNAQEF"
			+ "BQAwYjELMAkGA1UEBhMCVVMxGzAZBgNVBAoMEkNvbm5lY3RpZmllciwgSW5jLjEV"
			+ "MBMGA1UECwwMT25lTG9naW4gSWRQMR8wHQYDVQQDDBZPbmVMb2dpbiBBY2NvdW50"
			+ "BhMCVVMxGzAZBgNVBAoMEkNvbm5lY3RpZmllciwgSW5jLjEVMBMGA1UECwwMT25l"
			+ "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3ymFFiFfvDY/YsHFNg7sLON3luGo"
			+ "TG9naW4gSWRQMR8wHQYDVQQDDBZPbmVMb2dpbiBBY2NvdW50IDQ1NTAxMIIBIjAN"
			+ "I84UQx3N8nwl5ayfOJM3KC4AvExeWQQxfc2nO01SPrgJEy/DLr8OeFIXEVVBPVFe"
			+ "MKa2TnOARRImshLFzehOu0S+3AcrTWUnQccjpdpC/VUY8z65ntfm0W0XHtJ3HkVW"
			+ "uUMPl63X/OU7RLm0ALKahMs9+WV7LcwP/CkDGYUr2UcXz1Ehrcqh6x8FGx90OJCl"
			+ "Ws06mWpZYMSlMhNnT2cjN2+50HpU+51mearoZ6uKhD9SwpU4WkIFvfG1GGqj3ZS2"
			+ "mTvw1V7RZ28XV7ou5TUEf5YfpsWZ8FMAisiPZpO/mJCBqTSi2KjWN6P/rwIDAQAB"
			+ "IDQ1NTAxMB4XDTE0MDgwMzIxNDcyMloXDTE5MDgwNDIxNDcyMlowYjELMAkGA1UE"
			+ "o4HiMIHfMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFFwXtgC2NizDcjsi2SM+Jzt5"
			+ "cMt/MIGfBgNVHSMEgZcwgZSAFFwXtgC2NizDcjsi2SM+Jzt5cMt/oWakZDBiMQsw"
			+ "FAxVnl6NlEviXvBK6nXNiL0RMvCLMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0B"
			+ "CQYDVQQGEwJVUzEbMBkGA1UECgwSQ29ubmVjdGlmaWVyLCBJbmMuMRUwEwYDVQQL"
			+ "d0Ld0d2Dt6Gvsczba6fsbdmka9sdjLAfkA9dasdA3sFkasyqoiMN09123jJAooAI"
			+ "AQUFAAOCAQEA0FiaxTnK6D9HwirzOcQ0a7/lqqXHnm9nOw6bUS9TKlMNkoV0CqIq"
			+ "I6r8zWcB1CqsvrPsB4c3jB0Uc3u8hl+mOkvPUsMOsfM1fV+iGMFl4bYpd/HxQOpv"
			+ "tWMpi0TPat/WrbNOEPikahZwMK/XycoZ09VaXFoooSpYoOAaS4pAEwfabneAt1Pu"
			+ "O0IS6PrERgRFOe0ww2K9SNImvDLpH1rd239PUXKFFAtasuZhw6ol+kJwgylcyEHU"
			+ "SHHfYGDkRCVStrFN5uzPOurZKEfa9NETAKN5p2VetJ6+G9xPV05ONjDNZQLpo+VY"
			+ "eewqdHDL2SDOiEAblF1hYy5dDb/Fjc3W0Q==";

	public void handle(String responseMessage) {
		// Read certificate
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		InputStream inputStream = new ByteArrayInputStream(Base64.decodeBase64(certificateS.getBytes("UTF-8")));
		X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
		inputStream.close();

		BasicX509Credential credential = new BasicX509Credential();
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(certificate.getPublicKey().getEncoded());
		PublicKey key = keyFactory.generatePublic(publicKeySpec);
		credential.setPublicKey(key);

		// Parse response
		byte[] base64DecodedResponse = Base64.decodeBase64(responseMessage);

		ByteArrayInputStream is = new ByteArrayInputStream(base64DecodedResponse);
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
		Document document = docBuilder.parse(is);
		Element element = document.getDocumentElement();

		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
		XMLObject responseXmlObj = unmarshaller.unmarshall(element);
		Response responseObj = (Response) responseXmlObj;
		Assertion assertion = responseObj.getAssertions().get(0);
		String subject = assertion.getSubject().getNameID().getValue();
		String issuer = assertion.getIssuer().getValue();
		String audience = assertion.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0)
				.getAudienceURI();
		String statusCode = responseObj.getStatus().getStatusCode().getValue();

		org.opensaml.xml.signature.Signature sig = assertion.getSignature();
		org.opensaml.xml.signature.SignatureValidator validator = new org.opensaml.xml.signature.SignatureValidator(
				credential);
		validator.validate(sig);
	}
}