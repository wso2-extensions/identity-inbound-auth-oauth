package org.wso2.carbon.identity.oauth.dcr.exception;

import org.wso2.carbon.identity.oauth.dcr.DCRException;

/**
 * Exception class used to handle exceptions occur during registering an OAuth application.
 * This was deprecated as part of deprecating the legacy identity/register DCR endpoint.
 * The recommendation is to use /identity/oauth2/dcr/v1.1 instead.
 */
@Deprecated
public class RegistrationException extends DCRException {

    public RegistrationException(String message) {

        super(message);
    }

    public RegistrationException(String errorCode, String message) {

        super(errorCode, message);
    }

    public RegistrationException(String message, Throwable cause) {

        super(message, cause);
    }

    public RegistrationException(String errorCode, String message, Throwable cause) {

        super(errorCode, message, cause);
    }
}
