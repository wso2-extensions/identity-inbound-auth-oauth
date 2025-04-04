package org.wso2.carbon.identity.oauth.endpoint.authzchallenge.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.HashMap;
import java.util.Map;

public class AuthzChallengeCompletedResponse {

    @JsonProperty("authData")
    private Map<String, String> authData = new HashMap<>();

    public AuthzChallengeCompletedResponse() {

    }

    public AuthzChallengeCompletedResponse(Map<String, String> authData) {

        this.authData = authData;
    }

    public Map<String, String> getAuthData() {

        return authData;
    }

    public void setAuthData(Map<String, String> authData) {

        this.authData = authData;
    }
}
