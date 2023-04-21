package org.wso2.carbon.identity.oauth;

import org.wso2.carbon.identity.xds.common.constant.XDSOperationType;

/**
 * Enum for OAuth XDS operation types.
 */
public enum OAuthXDSOperationType implements XDSOperationType {

    UPDATE_AND_RETRIEVE_OAUTH_SECRET_KEY,
    REGISTER_AND_RETRIEVE_OAUTH_APPLICATION_DATA,
    REGISTER_OAUTH_CONSUMER,
    UPDATE_CONSUMER_APPLICATION,
    ADD_SCOPE,
    ADD_SCOPE_DTO,
    DELETE_SCOPE,
    UPDATE_SCOPE,
    UPDATE_SCOPE_DTO,
    UPDATE_CONSUMER_APP_STATE,
    REMOVE_OAUTH_APPLICATION_DATA,
    REMOVE_ALL_OAUTH_APPLICATION_DATA,
    REVOKE_AUTHZ_FOR_APPS_BY_RESOURCE_OWNER,
    REVOKE_ISSUED_TOKENS_BY_APPLICATION,
    UPDATE_APPROVE_ALWAYS_FOR_APP_CONSENT_BY_RESOURCE_OWNER
}
