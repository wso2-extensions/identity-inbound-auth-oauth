package org.wso2.carbon.identity.oauth2;

/**
 * Identity OAuth 2 server exception.
 */
public class IdentityOAuth2ServerException extends IdentityOAuth2Exception {

    public IdentityOAuth2ServerException(String message) {

        super(message);
    }

    public IdentityOAuth2ServerException(String message, Throwable e) {

        super(message, e);
    }

    public IdentityOAuth2ServerException(String code, String message) {

        super(code, message);
    }

    public IdentityOAuth2ServerException(String code, String message, Throwable e) {

        super(code, message, e);
    }
}
