package org.wso2.carbon.identity.oauth.endpoint.exception;

public class AccessDeniedException extends InvalidRequestException {

    public AccessDeniedException(String message) {
        super(message);
    }

    public AccessDeniedException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public AccessDeniedException(String message, String errorCode, Throwable cause) {
        super(message, errorCode, cause);
        this.errorCode = errorCode;
    }
}
