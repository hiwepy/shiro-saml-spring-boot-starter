package org.apache.shiro.spring.boot.saml.realm;

import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.saml.token.Saml2Token;

/**
 * SAML 2.0 Stateful AuthorizingRealm
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class Saml2StatefulAuthorizingRealm extends AbstractAuthorizingRealm {

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return Saml2Token.class;// 此Realm只支持Saml2Token
	}

}
