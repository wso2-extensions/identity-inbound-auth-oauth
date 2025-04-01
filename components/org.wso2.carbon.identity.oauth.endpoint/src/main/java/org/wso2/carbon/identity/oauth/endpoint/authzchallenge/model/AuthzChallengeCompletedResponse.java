package org.wso2.carbon.identity.oauth.endpoint.authzchallenge.model;

import java.util.HashMap;
import java.util.Map;

public class AuthzChallengeCompletedResponse {
    private Map<String, String> auth_data = new HashMap<>();

    public AuthzChallengeCompletedResponse() {

    }

    public AuthzChallengeCompletedResponse(Map<String, String> authData) {

        this.auth_data = authData;
    }

    public Map<String, String> getAuthData() {

        return auth_data;
    }

    public void setAuthData(Map<String, String> authData) {

        this.auth_data = authData;
    }
}
