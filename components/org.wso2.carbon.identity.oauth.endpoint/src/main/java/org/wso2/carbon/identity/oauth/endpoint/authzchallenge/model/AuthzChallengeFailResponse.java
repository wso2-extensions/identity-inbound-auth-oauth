package org.wso2.carbon.identity.oauth.endpoint.authzchallenge.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthzChallengeFailResponse extends  AuthzChallengeGenericResponse {

    @JsonProperty("error_uri")
    private String errorUri;

    @JsonProperty("request_uri")
    private String requestUri;

    @JsonProperty("expires_in")
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

    @JsonIgnore
    public String getErrorUri() {

        return errorUri;
    }

    public void setErrorUri(String errorUri) {

        this.errorUri = errorUri;
    }

    @JsonIgnore
    public String getRequestUri() {

        return requestUri;
    }

    public void setRequestUri(String request_uri) {

        this.requestUri = request_uri;
    }

    @JsonIgnore
    public String getExpiresIn() {

        return expiresIn;
    }

    public void setExpiresIn(String expiresIn) {

        this.expiresIn = expiresIn;
    }
}
