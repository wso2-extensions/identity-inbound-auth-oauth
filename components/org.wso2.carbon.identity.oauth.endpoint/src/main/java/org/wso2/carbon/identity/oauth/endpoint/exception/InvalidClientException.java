package org.wso2.carbon.identity.oauth.endpoint.exception;

public class InvalidClientException extends InvalidRequestException {

    public InvalidClientException(String message) {
        super(message);
    }

    public InvalidClientException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public InvalidClientException(String message, String errorCode, Throwable cause) {
        super(message, errorCode, cause);
        this.errorCode = errorCode;
    }
}
