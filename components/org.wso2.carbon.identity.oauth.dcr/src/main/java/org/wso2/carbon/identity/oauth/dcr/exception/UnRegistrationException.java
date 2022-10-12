package org.wso2.carbon.identity.oauth.dcr.exception;

import org.wso2.carbon.identity.oauth.dcr.DCRException;

/**
 * Exception class used to handle exceptions occur during un registering an OAuth application.
 * This was deprecated as part of deprecating the legacy identity/register DCR endpoint.
 * The recommendation is to use /identity/oauth2/dcr/v1.1 instead.
 */
@Deprecated
public class UnRegistrationException extends DCRException {

    public UnRegistrationException(String message) {

        super(message);
    }

    public UnRegistrationException(String errorCode, String message) {

        super(errorCode, message);
    }

    public UnRegistrationException(String message, Throwable cause) {

        super(message, cause);
    }

    public UnRegistrationException(String errorCode, String message, Throwable cause) {

        super(errorCode, message, cause);
    }
}
