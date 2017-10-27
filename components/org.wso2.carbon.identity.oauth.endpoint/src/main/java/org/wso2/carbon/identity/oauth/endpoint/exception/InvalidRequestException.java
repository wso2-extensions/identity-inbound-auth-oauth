package org.wso2.carbon.identity.oauth.endpoint.exception;

public class InvalidRequestException extends Exception {

    protected String errorCode = null;
    protected String errorMessage = null;


    public InvalidRequestException(String message) {
        super(message);
    }

    public InvalidRequestException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public InvalidRequestException(String message, String errorCode, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public String getErrorMessage() {
        return errorMessage;
    }
}
