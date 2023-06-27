package org.wso2.carbon.identity.oauth.par.exceptions;

import org.wso2.carbon.identity.base.IdentityException;

public class ParException extends IdentityException {

    public ParException(String message) {
        super(message);
    }

    public ParException(String errorCode, String message) {
        super(errorCode, message);
    }

    public ParException(String message, Throwable cause) {
        super(message, cause);
    }

    public ParException(String errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }
}
