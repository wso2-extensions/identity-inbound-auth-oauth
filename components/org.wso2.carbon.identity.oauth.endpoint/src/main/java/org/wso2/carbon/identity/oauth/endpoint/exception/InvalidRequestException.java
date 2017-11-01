package org.wso2.carbon.identity.oauth.endpoint.exception;

public class InvalidRequestException extends InvalidRequestParentException {

    public InvalidRequestException(String message) {
        super(message);
    }

    public InvalidRequestException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public InvalidRequestException(String message, String errorCode, Throwable cause) {
        super(message, errorCode, cause);
        this.errorCode = errorCode;
    }
}
