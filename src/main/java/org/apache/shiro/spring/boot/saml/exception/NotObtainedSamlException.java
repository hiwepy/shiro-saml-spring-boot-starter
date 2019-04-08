package org.apache.shiro.spring.boot.saml.exception;

import org.apache.shiro.authc.AuthenticationException;

@SuppressWarnings("serial")
public class NotObtainedSamlException extends AuthenticationException {
	
	public NotObtainedSamlException() {
		super();
	}

	public NotObtainedSamlException(String message, Throwable cause) {
		super(message, cause);
	}

	public NotObtainedSamlException(String message) {
		super(message);
	}

	public NotObtainedSamlException(Throwable cause) {
		super(cause);
	}
	
}
