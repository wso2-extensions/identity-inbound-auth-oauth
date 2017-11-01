package org.wso2.carbon.identity.oauth.endpoint.exception;

public class InvalidRequestParentException extends Exception {

    protected String errorCode = null;
    protected String errorMessage = null;


    public InvalidRequestParentException(String message) {
        super(message);
    }

    public InvalidRequestParentException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public InvalidRequestParentException(String message, String errorCode, Throwable cause) {
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
