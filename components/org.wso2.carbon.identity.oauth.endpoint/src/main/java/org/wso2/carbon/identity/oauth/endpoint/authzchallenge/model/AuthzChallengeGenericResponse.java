package org.wso2.carbon.identity.oauth.endpoint.authzchallenge.model;

public class AuthzChallengeGenericResponse {
    private String auth_session;
    private String error;
    private String error_description;

    public AuthzChallengeGenericResponse() {

    }

    public AuthzChallengeGenericResponse(String authSession, String error, String errorDescription) {
        this.auth_session = authSession;
        this.error = error;
        this.error_description = errorDescription;

    }

    public String getAuthSession() {
        return auth_session;
    }

    public void setAuthSession(String authSession) {
        this.auth_session = authSession;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getErrorDescription() {
        return error_description;
    }

    public void setErrorDescription(String errorDescription) {
        this.error_description = errorDescription;
    }
}
