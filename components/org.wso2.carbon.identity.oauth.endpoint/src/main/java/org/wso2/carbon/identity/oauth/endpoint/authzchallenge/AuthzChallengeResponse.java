package org.wso2.carbon.identity.oauth.endpoint.authzchallenge;

public class AuthzChallengeResponse {
    private String authorization_code;

    public AuthzChallengeResponse() {

    }

    public AuthzChallengeResponse(String authorization_code) {
        this.authorization_code = authorization_code;
    }

    public String getAuthorizationCode() {
        return authorization_code;
    }

    public void setAuthorizationCode(String auth_code) {
        this.authorization_code = auth_code;
    }

}



