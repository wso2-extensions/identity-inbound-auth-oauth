package org.wso2.carbon.identity.oauth.endpoint.authzchallenge.model;

public class AuthzChallengeGenericResponse {
    private String authSession;
    private String error;
    private String errorDescription;

    public AuthzChallengeGenericResponse() {

    }

    public AuthzChallengeGenericResponse(String authSession, String error, String errorDescription) {
        this.authSession = authSession;
        this.error = error;
        this.errorDescription = errorDescription;

    }

    public String getAuthSession() {
        return authSession;
    }

    public void setAuthSession(String authSession) {
        this.authSession = authSession;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public void setErrorDescription(String errorDescription) {
        this.errorDescription = errorDescription;
    }
}
