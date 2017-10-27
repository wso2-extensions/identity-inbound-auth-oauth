package org.wso2.carbon.identity.oauth.endpoint.exception;

public class InvalidApplicationServerException extends InvalidRequestException {

    public InvalidApplicationServerException(String message) {
        super(message);
    }

    public InvalidApplicationServerException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public InvalidApplicationServerException(String message, String errorCode, Throwable cause) {
        super(message, errorCode, cause);
        this.errorCode = errorCode;
    }
}
