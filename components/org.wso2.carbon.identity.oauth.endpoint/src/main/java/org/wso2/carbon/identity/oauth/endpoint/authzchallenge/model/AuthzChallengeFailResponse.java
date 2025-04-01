package org.wso2.carbon.identity.oauth.endpoint.authzchallenge.model;

public class AuthzChallengeFailResponse extends  AuthzChallengeGenericResponse {
    private String error_uri;
    private String request_uri;
    private String expires_in;

    public AuthzChallengeFailResponse() {

    }

    public AuthzChallengeFailResponse(String authSession, String error, String errorDescription, String errorUri,
                                      String requestUri, String expiresIn) {
        super(authSession, error, errorDescription);
        this.error_uri = errorUri;
        this.request_uri = requestUri;
        this.expires_in = expiresIn;
    }

    public String getErrorUri() {
        return error_uri;
    }

    public void setErrorUri(String errorUri) {
        this.error_uri = errorUri;
    }

    public String getRequestUri() {
        return request_uri;
    }

    public void setRequestUri(String request_uri) {
        this.request_uri = request_uri;
    }

    public String getExpiresIn() {
        return expires_in;
    }

    public void setExpiresIn(String expiresIn) {
        this.expires_in = expiresIn;
    }
}
