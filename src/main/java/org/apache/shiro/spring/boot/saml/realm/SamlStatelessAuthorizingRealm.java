package org.apache.shiro.spring.boot.saml.realm;

import java.util.stream.Collectors;

import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.saml.token.SamlToken;
import org.apache.shiro.spring.boot.saml.Saml2PayloadPrincipal;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * SAML 1.0 Stateless AuthorizingRealm
 * @author [@Loong Wan](https://github.com/loong10k)
 */
public class SamlStatelessAuthorizingRealm extends AbstractAuthorizingRealm {

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return SamlToken.class;// 此Realm只支持SamlToken
	}
	
	/*
	 * authorization,JWT已包含访问主张只需要解析其中的主张定义就行了
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		
		Saml2PayloadPrincipal principal = (Saml2PayloadPrincipal) principals.getPrimaryPrincipal();
		
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		// 解析role并sets
		info.setRoles(principal.getRoles().stream().map(pair -> pair.getKey()).collect(Collectors.toSet()));
		// 解析permission并sets
		info.setStringPermissions(principal.getPerms());
		return info;
	}
	
}
