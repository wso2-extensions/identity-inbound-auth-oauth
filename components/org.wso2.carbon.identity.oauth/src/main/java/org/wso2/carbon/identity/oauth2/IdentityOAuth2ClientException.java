package org.wso2.carbon.identity.oauth2;

/**
 * Identity OAuth 2 Client exception.
 */
public class IdentityOAuth2ClientException extends IdentityOAuth2Exception {

    public IdentityOAuth2ClientException(String message) {

        super(message);
    }

    public IdentityOAuth2ClientException(String message, Throwable e) {

        super(message, e);
    }

    public IdentityOAuth2ClientException(String code, String message) {

        super(code, message);
    }

    public IdentityOAuth2ClientException(String code, String message, Throwable e) {

        super(code, message, e);
    }
}
