package org.wso2.carbon.identity.oauth.endpoint.exception;

public class ParErrorDTO extends Throwable {
    private boolean isValidClient;

    private int errorCode;
    private String errorMsg;

    public ParErrorDTO() {
    }

    public ParErrorDTO(int errorCode, String errorMsg) {
        this.isValidClient = false;
        this.setErrorCode(errorCode);
        this.setErrorMsg(errorMsg);
    }

    public boolean isValidClient() {
        return isValidClient;
    }

    public int getErrorCode() {
        return errorCode;
    }

    public String getErrorMsg() {
        return errorMsg;
    }

    public void setValidClient(boolean validClient) {
        isValidClient = validClient;
    }

    public void setErrorCode(int errorCode) {
        this.errorCode = errorCode;
    }

    public void setErrorMsg(String errorMsg) {
        this.errorMsg = errorMsg;
    }
}
