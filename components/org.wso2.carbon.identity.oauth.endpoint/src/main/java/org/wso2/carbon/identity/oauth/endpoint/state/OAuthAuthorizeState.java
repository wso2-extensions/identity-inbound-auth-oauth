package org.wso2.carbon.identity.oauth.endpoint.state;


public enum OAuthAuthorizeState {

    INITIAL_REQUEST, AUTHENTICATION_RESPONSE, USER_CONSENT_RESPONSE, AUTH_INVALID, PASSTHROUGH_TO_COMMONAUTH
}