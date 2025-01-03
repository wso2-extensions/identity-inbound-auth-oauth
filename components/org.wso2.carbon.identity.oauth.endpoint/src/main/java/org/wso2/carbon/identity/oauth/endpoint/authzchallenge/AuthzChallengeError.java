package org.wso2.carbon.identity.oauth.endpoint.authzchallenge;

public enum AuthzChallengeError {

    INVALID_REQUEST("invalid_request"),
    INVALID_CLIENT("invalid_client"),
    UNAUTHORIZED_CLIENT("unauthorized_client"),
    INVALID_SESSION("invalid_session"),
    INVALID_SCOPE("invalid_scope"),
    INSUFFICIENT_AUTHORIZATION("insufficient_authorization"),
    REDIRECT_TO_WEB("redirect_to_web");


    private final String code;

    AuthzChallengeError(String code) {
        this.code = code;
    }

    public String getCode() {
        return code;
    }

    @Override
    public String toString() {
        return code;
    }
}
