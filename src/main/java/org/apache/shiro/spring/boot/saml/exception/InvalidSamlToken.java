package org.apache.shiro.spring.boot.saml.exception;

import org.apache.shiro.authc.AuthenticationException;

@SuppressWarnings("serial")
public class InvalidSamlToken extends AuthenticationException {
	
	public InvalidSamlToken() {
		super();
	}

	public InvalidSamlToken(String message, Throwable cause) {
		super(message, cause);
	}

	public InvalidSamlToken(String message) {
		super(message);
	}

	public InvalidSamlToken(Throwable cause) {
		super(cause);
	}
	
}
