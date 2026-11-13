/*
 *
 *   Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 * /
 */

package org.wso2.carbon.identity.oauth2.dao;

import org.apache.commons.lang3.tuple.Pair;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.OAuthAppInfo;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Set;

/**
 * Token management data access interface.
 */
public interface TokenManagementDAO {

    RefreshTokenValidationDataDO validateRefreshToken(String consumerKey, String refreshToken)
            throws IdentityOAuth2Exception;

    default AccessTokenDO getRefreshToken(String refreshToken) throws IdentityOAuth2Exception {
        return null;
    }

    Pair<String, Integer> findTenantAndScopeOfResource(String resourceUri) throws IdentityOAuth2Exception;

    void revokeOAuthConsentByApplicationAndUser(String username, String tenantDomain, String applicationName)
            throws IdentityOAuth2Exception;

    /**
     * Revoke the OAuth consents by the application name and tenant domain.
     *
     * @param applicationName Name of the OAuth application
     * @param tenantDomain    Tenant domain of the application
     * @throws IdentityOAuth2Exception If an unexpected error occurs
     */
    default void revokeOAuthConsentsByApplication(String applicationName, String tenantDomain)
            throws IdentityOAuth2Exception {

    }

    void updateApproveAlwaysForAppConsentByResourceOwner(String tenantAwareUserName,
                                                         String tenantDomain, String applicationName,
                                                         String state) throws IdentityOAuth2Exception;

    void updateAppAndRevokeTokensAndAuthzCodes(String consumerKey, Properties properties,
                                               String[] authorizationCodes, String[] accessTokens)
            throws IdentityOAuth2Exception, IdentityApplicationManagementException;

    /**
     * Revoke active access tokens issued against application.
     *
     * @param consumerKey    OAuth application consumer key.
     * @param accessTokens   Active access tokens.
     * @throws IdentityOAuth2Exception
     * @throws IdentityApplicationManagementException
     */
    default void revokeTokens(String consumerKey, String[] accessTokens)
            throws IdentityOAuth2Exception, IdentityApplicationManagementException {

    }

    /**
     * Revoke authorize codes issued against application.
     *
     * @param consumerKey          OAuth application consumer key.
     * @param authorizationCodes   Active authorization codes.
     * @throws IdentityApplicationManagementException
     */
    default void revokeAuthzCodes(String consumerKey, String[] authorizationCodes)
            throws IdentityApplicationManagementException {

    }

    void revokeSaaSTokensOfOtherTenants(String consumerKey, int tenantId) throws IdentityOAuth2Exception;

    void revokeSaaSTokensOfOtherTenants(String consumerKey, String userStoreDomain, int tenantId) throws
            IdentityOAuth2Exception;

    Set<String> getAllTimeAuthorizedClientIds(AuthenticatedUser authzUser) throws IdentityOAuth2Exception;

    /**
     * Get all client IDs ever authorized by the user, each paired with the tenant domain of the owning app.
     * The JOIN with IDN_OAUTH_CONSUMER_APPS provides the correct app tenant ID from the DB, avoiding
     * thread-local resolution which is unavailable in system-triggered flows.
     *
     * @param authzUser authorized user.
     * @return list of {@link OAuthAppInfo} entries, one per (clientId, appTenantDomain) combination.
     * @throws IdentityOAuth2Exception if failed to retrieve the client IDs.
     */
    default List<OAuthAppInfo> getAllTimeAuthorizedClientIdsWithAppTenantDomain(AuthenticatedUser authzUser)
            throws IdentityOAuth2Exception {

        List<OAuthAppInfo> result = new ArrayList<>();
        for (String clientId : getAllTimeAuthorizedClientIds(authzUser)) {
            result.add(new OAuthAppInfo(clientId, authzUser.getTenantDomain()));
        }
        return result;
    }
}
