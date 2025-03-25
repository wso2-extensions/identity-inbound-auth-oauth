package org.wso2.carbon.identity.oauth.endpoint.authzchallenge;

public class AuthzChallengeConstants {


    public enum Error {

        INVALID_REQUEST("invalid_request"),
        INVALID_CLIENT("invalid_client"),
        UNAUTHORIZED_CLIENT("unauthorized_client"),
        INVALID_SESSION("invalid_session"),
        INVALID_SCOPE("invalid_scope"),
        INSUFFICIENT_AUTHORIZATION("insufficient_authorization"),
        REDIRECT_TO_WEB("redirect_to_web");

        private final String value;

        Error(String value) {

            this.value = value;
        }

        public String value() {

            return value;
        }

        @Override
        public String toString() {

            return value;
        }
    }
}
