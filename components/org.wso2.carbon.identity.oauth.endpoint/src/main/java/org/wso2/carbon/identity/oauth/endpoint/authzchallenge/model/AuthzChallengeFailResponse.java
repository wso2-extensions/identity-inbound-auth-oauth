package org.wso2.carbon.identity.oauth.endpoint.authzchallenge.model;

public class AuthzChallengeFailResponse extends  AuthzChallengeGenericResponse {
    private String errorUri;
    private String requestUri;
    private String expiresIn;

    public AuthzChallengeFailResponse() {

    }

    public AuthzChallengeFailResponse(String authSession, String error, String errorDescription, String errorUri,
                                      String requestUri, String expiresIn) {
        super(authSession, error, errorDescription);
        this.errorUri = errorUri;
        this.requestUri = requestUri;
        this.expiresIn = expiresIn;
    }

    public String getErrorUri() {
        return errorUri;
    }

    public void setErrorUri(String errorUri) {
        this.errorUri = errorUri;
    }

    public String getRequestUri() {
        return requestUri;
    }

    public void setRequestUri(String requestUri) {
        this.requestUri = requestUri;
    }

    public String getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(String expiresIn) {
        this.expiresIn = expiresIn;
    }
}
