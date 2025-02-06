package org.wso2.carbon.identity.oauth.endpoint.authzchallenge.model;

public class AuthzChallengeFailResponse {
    private String auth_session;
    private String error;
    private String error_description;

    public AuthzChallengeFailResponse() {

    }

    public AuthzChallengeFailResponse(String auth_session, String error, String error_description) {
        this.auth_session = auth_session;
        this.error = error;
        this.error_description = error_description;
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
}
