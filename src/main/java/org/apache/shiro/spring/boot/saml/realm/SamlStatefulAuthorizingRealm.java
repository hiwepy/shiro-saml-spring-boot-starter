package org.apache.shiro.spring.boot.saml.realm;

import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.saml.token.SamlToken;

/**
 * SAML 1.0 Stateful AuthorizingRealm
 * @author [@Loong Wan](https://github.com/loong10k)
 */
public class SamlStatefulAuthorizingRealm extends AbstractAuthorizingRealm {

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return SamlToken.class;// 此Realm只支持SamlToken
	}

}
