/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.listener;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants
        .CURRENT_SESSION_IDENTIFIER;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.Config
        .PRESERVE_LOGGED_IN_SESSION_AT_PASSWORD_UPDATE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenBindings.NONE;

/**
 * This is an event handler listening to for some of the core user management operations.
 */
public class IdentityOauthEventHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(IdentityOauthEventHandler.class);

    public String getName() {

        return "identityOauthEventHandler";
    }

    public String getFriendlyName() {

        return "Identity Oauth Event Handler";
    }

    @Override
    public void init(InitConfig configuration) throws IdentityRuntimeException {

        super.init(configuration);
    }

    @Override
    public int getPriority(MessageContext messageContext) {

        return 50;
    }


    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        if (IdentityEventConstants.Event.POST_SET_USER_CLAIMS.equals(event.getEventName())) {
            String username = (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.USER_NAME);
            UserStoreManager userStoreManager =
                    (UserStoreManager) event.getEventProperties()
                            .get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);
            try {
                revokeTokensOfLockedUser(username, userStoreManager);
                revokeTokensOfDisabledUser(username, userStoreManager);
            } catch (UserStoreException e) {
                String errorMsg = "Error occurred while revoking  access token for User : " + username;
                log.error(errorMsg, e);
                throw new IdentityEventException(errorMsg);
            }
        }
    }

    private void revokeTokensOfLockedUser(String userName, UserStoreManager userStoreManager)
            throws UserStoreException {

        String errorCode =
                (String) IdentityUtil.threadLocalProperties.get().get(IdentityCoreConstants.USER_ACCOUNT_STATE);

        if (UserCoreConstants.ErrorCode.USER_IS_LOCKED.equalsIgnoreCase(errorCode)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("User %s is locked. Hence revoking user's access tokens.", userName));
            }
            revokeTokens(userName, userStoreManager);
        }
    }

    private void revokeTokensOfDisabledUser(String userName, UserStoreManager userStoreManager)
            throws UserStoreException {

        String errorCode =
                (String) IdentityUtil.threadLocalProperties.get().get(IdentityCoreConstants.USER_ACCOUNT_STATE);
        if (IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE.equalsIgnoreCase(errorCode)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("User %s is disabled. Hence revoking user's access tokens.", userName));
            }
            revokeTokens(userName, userStoreManager);
        }
    }

    private void revokeTokens(String username, UserStoreManager userStoreManager) throws UserStoreException {

        String userStoreDomain = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
        String tenantDomain = IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId());
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserStoreDomain(userStoreDomain);
        authenticatedUser.setTenantDomain(tenantDomain);
        authenticatedUser.setUserName(username);

        /* This userStoreDomain variable is used for access token table partitioning. So it is set to null when access
        token table partitioning is not enabled.*/
        userStoreDomain = null;
        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            try {
                userStoreDomain = OAuth2Util.getUserStoreForFederatedUser(authenticatedUser);
            } catch (IdentityOAuth2Exception e) {
                log.error("Error occurred while getting user store domain for User ID: " +
                        authenticatedUser, e);
                throw new UserStoreException(e);
            }
        }

        Set<String> clientIds;
        try {
            // get all the distinct client Ids authorized by this user
            clientIds =
                    OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO()
                            .getAllTimeAuthorizedClientIds(authenticatedUser);
        } catch (IdentityOAuth2Exception e) {
            log.error("Error occurred while retrieving apps authorized by User ID : " + authenticatedUser, e);
            throw new UserStoreException(e);
        }
        for (String clientId : clientIds) {
            Set<AccessTokenDO> accessTokenDOs;
            try {
                // retrieve all ACTIVE or EXPIRED access tokens for particular client authorized by this user
                accessTokenDOs =
                        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO().getAccessTokens(clientId,
                                authenticatedUser, userStoreDomain, true);
            } catch (IdentityOAuth2Exception e) {
                String errorMsg =
                        "Error occurred while retrieving access tokens issued for " + "Client ID : " + clientId + ", "
                                + "User ID : " + authenticatedUser;
                log.error(errorMsg, e);
                throw new UserStoreException(e);
            }

            boolean isTokenPreservingAtPasswordUpdateEnabled =
                    Boolean.parseBoolean(IdentityUtil.getProperty(PRESERVE_LOGGED_IN_SESSION_AT_PASSWORD_UPDATE));
            String currentTokenBindingReference = "";
            if (isTokenPreservingAtPasswordUpdateEnabled) {
                if (IdentityUtil.threadLocalProperties.get().get(CURRENT_SESSION_IDENTIFIER) != null) {
                    currentTokenBindingReference =
                            (String) IdentityUtil.threadLocalProperties.get().get(CURRENT_SESSION_IDENTIFIER);
                }
            }

            Set<String> scopes = new HashSet<>();
            List<AccessTokenDO> accessTokens = new ArrayList<>();
            boolean tokenBindingEnabled = false;
            for (AccessTokenDO accessTokenDO : accessTokenDOs) {
                // Clear cache
                String tokenBindingReference = NONE;
                if (accessTokenDO.getTokenBinding() != null && StringUtils.isNotBlank(accessTokenDO.
                        getTokenBinding().getBindingReference())) {
                    tokenBindingReference = accessTokenDO.getTokenBinding().getBindingReference();
                    tokenBindingEnabled = true;
                    // Skip current token from being revoked.
                    if (StringUtils.equals(accessTokenDO.getTokenBinding().getBindingValue(),
                            currentTokenBindingReference)) {
                        continue;
                    }
                }
                OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser(),
                        OAuth2Util.buildScopeString(accessTokenDO.getScope()), tokenBindingReference);
                OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser(),
                        OAuth2Util.buildScopeString(accessTokenDO.getScope()));
                OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser());
                OAuthUtil.clearOAuthCache(accessTokenDO.getAccessToken());
                // Get unique scopes list
                scopes.add(OAuth2Util.buildScopeString(accessTokenDO.getScope()));
                accessTokens.add(accessTokenDO);
            }

            if (!tokenBindingEnabled && OAuth2Util.isHashDisabled()) {
                revokeLatestTokensWithScopes(scopes, clientId, authenticatedUser);
            } else {
                // If the hashed token is enabled, there can be multiple active tokens with a user with same scope.
                // Also, if token binding is enabled, there can be multiple active tokens for the same user, scope
                // and client combination.
                // So need to revoke all the tokens.
                try {
                    revokeTokens(accessTokens);
                } catch (IdentityOAuth2Exception e) {
                    String errorMsg = "Error occurred while revoking Access Token";
                    log.error(errorMsg, e);
                    throw new UserStoreException(e);
                }
            }
        }
    }

    private void revokeTokens(List<AccessTokenDO> accessTokens) throws IdentityOAuth2Exception {

        if (!accessTokens.isEmpty()) {
            // Revoking token from database.
            for (AccessTokenDO accessToken : accessTokens) {
                OAuthUtil.invokePreRevocationBySystemListeners(accessToken, Collections.emptyMap());
                OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO().revokeAccessTokens(new String[]
                        {accessToken.getAccessToken()}, OAuth2Util.isHashEnabled());
                OAuthUtil.invokePostRevocationBySystemListeners(accessToken, Collections.emptyMap());
            }
        }
    }

    private void revokeLatestTokensWithScopes(Set<String> scopes, String clientId,
                                              AuthenticatedUser authenticatedUser) throws UserStoreException {

        for (String scope : scopes) {
            AccessTokenDO scopedToken = null;
            try {
                // Retrieve latest access token for particular client, user and scope combination
                // if its ACTIVE or EXPIRED.
                scopedToken =
                        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO().getLatestAccessToken(clientId,
                                authenticatedUser, authenticatedUser.getUserStoreDomain(), scope, true);
            } catch (IdentityOAuth2Exception e) {
                String errorMsg =
                        "Error occurred while retrieving latest access token issued for Client ID : " + clientId + ","
                                + " User ID : " + authenticatedUser + " and Scope : " + scope;
                log.error(errorMsg, e);
                throw new UserStoreException(e);
            }
            if (scopedToken != null) {
                try {
                    // Revoking token from database
                    revokeTokens(Collections.singletonList(scopedToken));
                } catch (IdentityOAuth2Exception e) {
                    String errorMsg =
                            "Error occurred while revoking " + "Access Token : " + scopedToken.getAccessToken() +
                                    " " + "for user " + authenticatedUser;
                    log.error(errorMsg, e);
                    throw new UserStoreException(e);
                }
            }
        }
    }
}
