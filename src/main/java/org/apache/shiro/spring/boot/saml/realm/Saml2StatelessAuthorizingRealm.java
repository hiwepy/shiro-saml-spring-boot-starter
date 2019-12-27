package org.apache.shiro.spring.boot.saml.realm;

import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.saml.Saml2PayloadPrincipal;
import org.apache.shiro.spring.boot.saml.token.Saml2Token;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * SAML 2.0 Stateless AuthorizingRealm
 * @author <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class Saml2StatelessAuthorizingRealm extends AbstractAuthorizingRealm {

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return Saml2Token.class;// 此Realm只支持Saml2Token
	}
	
	/*
	 * 授权,Saml已包含访问主张只需要解析其中的主张定义就行了
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		
		Saml2PayloadPrincipal principal = (Saml2PayloadPrincipal) principals.getPrimaryPrincipal();
		
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		// 解析角色并设置
		info.setRoles(principal.getRoles());
		// 解析权限并设置
		info.setStringPermissions(principal.getPerms());
		return info;
	}
	
}
