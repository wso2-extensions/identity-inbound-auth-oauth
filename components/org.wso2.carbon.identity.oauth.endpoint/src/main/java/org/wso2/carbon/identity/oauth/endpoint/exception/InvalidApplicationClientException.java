package org.wso2.carbon.identity.oauth.endpoint.exception;

public class InvalidApplicationClientException extends InvalidRequestException {

    public InvalidApplicationClientException(String message) {
        super(message);
    }

    public InvalidApplicationClientException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public InvalidApplicationClientException(String message, String errorCode, Throwable cause) {
        super(message, errorCode, cause);
        this.errorCode = errorCode;
    }
}
