package org.wso2.carbon.identity.oauth.endpoint.authzchallenge.model;

public class AuthzChallengeFailResponse {
    private String auth_session;
    private String error;
    private String error_description;
    private String error_uri;
    private String request_uri;
    private String expires_in;

    public AuthzChallengeFailResponse() {

    }

    public AuthzChallengeFailResponse(String auth_session, String error, String error_description,
                                      String error_uri, String request_uri, String expires_in) {
        this.auth_session = auth_session;
        this.error = error;
        this.error_description = error_description;
        this.error_uri = error_uri;
        this.request_uri = request_uri;
        this.expires_in = expires_in;
    }

    public String getAuth_session() {
        return auth_session;
    }

    public void setAuth_session(String auth_session) {
        this.auth_session = auth_session;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getError_description() {
        return error_description;
    }

    public void setError_description(String error_description) {
        this.error_description = error_description;
    }

    public String getError_uri() {
        return error_uri;
    }

    public void setError_uri(String error_uri) {
        this.error_uri = error_uri;
    }

    public String getRequest_uri() {
        return request_uri;
    }

    public void setRequest_uri(String request_uri) {
        this.request_uri = request_uri;
    }

    public String getExpires_in() {
        return expires_in;
    }

    public void setExpires_in(String expires_in) {
        this.expires_in = expires_in;
    }
}
