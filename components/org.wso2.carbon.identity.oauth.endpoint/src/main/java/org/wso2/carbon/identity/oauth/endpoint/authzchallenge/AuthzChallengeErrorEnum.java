package org.wso2.carbon.identity.oauth.endpoint.authzchallenge;

import com.fasterxml.jackson.annotation.JsonValue;

public enum AuthzChallengeErrorEnum {

    INVALID_REQUEST("invalid_request"),
    INVALID_CLIENT("invalid_client"),
    UNAUTHORIZED_CLIENT("unauthorized_client"),
    INVALID_SESSION("invalid_session"),
    INVALID_SCOPE("invalid_scope"),
    INSUFFICIENT_AUTHORIZATION("insufficient_authorization"),
    REDIRECT_TO_WEB("redirect_to_web");


    private final String value;

    AuthzChallengeErrorEnum(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return value;
    }
}
