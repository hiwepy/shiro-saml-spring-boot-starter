package org.apache.shiro.spring.boot.saml.exception;

import org.apache.shiro.authc.AuthenticationException;

/**
 * InvalidSamlToken.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
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
