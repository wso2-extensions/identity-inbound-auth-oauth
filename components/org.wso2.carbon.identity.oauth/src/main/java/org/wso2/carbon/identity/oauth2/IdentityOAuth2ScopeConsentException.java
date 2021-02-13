package org.wso2.carbon.identity.oauth2;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.base.IdentityException;

/**
 * OAuth scope consent exception.
 */
public class IdentityOAuth2ScopeConsentException extends IdentityException {

    public IdentityOAuth2ScopeConsentException(String message) {
        super(message);
        this.setErrorCode(getDefaultErrorCode());
    }

    public IdentityOAuth2ScopeConsentException(String errorCode, String message) {
        super(errorCode, message);
    }

    public IdentityOAuth2ScopeConsentException(String message, Throwable cause) {
        super(message, cause);
        this.setErrorCode(getDefaultErrorCode());
    }

    public IdentityOAuth2ScopeConsentException(String errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }

    private String getDefaultErrorCode() {

        String errorCode = super.getErrorCode();
        if (StringUtils.isEmpty(errorCode)) {
            errorCode = Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_UNEXPECTED.getCode();
        }
        return errorCode;
    }
}
