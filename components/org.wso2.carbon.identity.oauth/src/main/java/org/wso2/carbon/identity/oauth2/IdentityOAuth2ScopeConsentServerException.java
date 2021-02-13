package org.wso2.carbon.identity.oauth2;

/**
 * OAuth scope consent server exception.
 */
public class IdentityOAuth2ScopeConsentServerException extends IdentityOAuth2ScopeConsentException {

    public IdentityOAuth2ScopeConsentServerException(String message) {
        super(message);
    }

    public IdentityOAuth2ScopeConsentServerException(String errorCode, String message) {
        super(errorCode, message);
    }

    public IdentityOAuth2ScopeConsentServerException(String message, Throwable cause) {
        super(message, cause);
    }

    public IdentityOAuth2ScopeConsentServerException(String errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }
}
