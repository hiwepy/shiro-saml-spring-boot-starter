package org.apache.shiro.spring.boot.saml.exception;

import org.apache.shiro.authc.AuthenticationException;

@SuppressWarnings("serial")
public class IncorrectSamlException extends AuthenticationException {
	
	public IncorrectSamlException() {
		super();
	}

	public IncorrectSamlException(String message, Throwable cause) {
		super(message, cause);
	}

	public IncorrectSamlException(String message) {
		super(message);
	}

	public IncorrectSamlException(Throwable cause) {
		super(cause);
	}
	
}
