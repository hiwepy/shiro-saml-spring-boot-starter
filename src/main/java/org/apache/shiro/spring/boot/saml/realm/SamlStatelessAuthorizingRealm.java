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
 * @author <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class SamlStatelessAuthorizingRealm extends AbstractAuthorizingRealm {

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return SamlToken.class;// 此Realm只支持SamlToken
	}
	
	/*
	 * 授权,JWT已包含访问主张只需要解析其中的主张定义就行了
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		
		Saml2PayloadPrincipal principal = (Saml2PayloadPrincipal) principals.getPrimaryPrincipal();
		
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		// 解析角色并设置
		info.setRoles(principal.getRoles().stream().map(pair -> pair.getKey()).collect(Collectors.toSet()));
		// 解析权限并设置
		info.setStringPermissions(principal.getPerms());
		return info;
	}
	
}
