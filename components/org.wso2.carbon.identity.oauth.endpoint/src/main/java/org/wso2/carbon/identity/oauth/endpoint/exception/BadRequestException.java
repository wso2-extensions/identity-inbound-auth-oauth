package org.wso2.carbon.identity.oauth.endpoint.exception;

public class BadRequestException extends InvalidRequestParentException {

    public BadRequestException(String message) {
        super(message);
    }

    public BadRequestException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public BadRequestException(String message, String errorCode, Throwable cause) {
        super(message, errorCode, cause);
        this.errorCode = errorCode;
    }
}
