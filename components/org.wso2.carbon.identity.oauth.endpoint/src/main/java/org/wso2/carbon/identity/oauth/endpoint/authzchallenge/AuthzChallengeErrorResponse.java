package org.wso2.carbon.identity.oauth.endpoint.authzchallenge;

import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.NextStep;

public class AuthzChallengeErrorResponse {

    private String auth_session;
    private AuthzChallengeErrorEnum error;
    private String error_description;
    private String error_uri;
    private String request_uri;
    private String expires_in;
    private NextStep nextStep;

    public AuthzChallengeErrorResponse() {

    }

    public AuthzChallengeErrorResponse(String auth_session, AuthzChallengeErrorEnum error) {
        this.auth_session = auth_session;
        this.error = error;
    }

    public String getAuthSession() {
        return auth_session;
    }

    public void setAuthSession(String auth_session) {
        this.auth_session = auth_session;
    }

    public AuthzChallengeErrorEnum getError() {
        return error;
    }

    public void setError(AuthzChallengeErrorEnum error) {
        this.error = error;
    }
}
