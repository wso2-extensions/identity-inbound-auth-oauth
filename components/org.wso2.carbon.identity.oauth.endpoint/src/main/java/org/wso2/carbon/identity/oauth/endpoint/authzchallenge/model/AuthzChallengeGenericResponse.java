package org.wso2.carbon.identity.oauth.endpoint.authzchallenge.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthzChallengeGenericResponse {

    @JsonProperty("auth_session")
    private String authSession;

    @JsonProperty("error")
    private String error;

    @JsonProperty("error_description")
    private String errorDescription;

    public AuthzChallengeGenericResponse() {

    }

    public AuthzChallengeGenericResponse(String authSession, String error, String errorDescription) {

        this.authSession = authSession;
        this.error = error;
        this.errorDescription = errorDescription;
    }

    @JsonIgnore
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

    @JsonIgnore
    public String getErrorDescription() {

        return errorDescription;
    }

    public void setErrorDescription(String errorDescription) {

        this.errorDescription = errorDescription;
    }
}
