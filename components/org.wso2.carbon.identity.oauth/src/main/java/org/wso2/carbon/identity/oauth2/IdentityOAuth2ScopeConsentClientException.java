package org.wso2.carbon.identity.oauth2;

/**
 * Identity OAuth scope consent client exception.
 */
public class IdentityOAuth2ScopeConsentClientException extends IdentityOAuth2ScopeConsentException {

    public IdentityOAuth2ScopeConsentClientException(String message) {
        super(message);
    }

    public IdentityOAuth2ScopeConsentClientException(String errorCode, String message) {
        super(errorCode, message);
    }

    public IdentityOAuth2ScopeConsentClientException(String message, Throwable cause) {
        super(message, cause);
    }

    public IdentityOAuth2ScopeConsentClientException(String errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }
}
