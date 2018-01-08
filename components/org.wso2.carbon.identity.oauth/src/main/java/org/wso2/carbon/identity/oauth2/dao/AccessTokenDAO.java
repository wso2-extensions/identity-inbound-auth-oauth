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

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

import java.util.List;
import java.util.Set;
/*
NOTE
This is the very first step of moving to simplified architecture for token persistence. New set of DAO classes  for
each purpose  and factory class to get instance of each DAO classes were introduced  during  this step. Further methods
 on org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO were distributed among new set of classes, each of these method
 need to be reviewed  and refactored  during next step.
 */
public interface AccessTokenDAO {

    void insertAccessToken(String accessToken, String consumerKey, AccessTokenDO accessTokenDO,
                           String userStoreDomain) throws IdentityOAuth2Exception;

    boolean insertAccessToken(String accessToken, String consumerKey,
                              AccessTokenDO newAccessTokenDO, AccessTokenDO existingAccessTokenDO,
                              String rawUserStoreDomain) throws IdentityOAuth2Exception;

    AccessTokenDO getLatestAccessToken(String consumerKey, AuthenticatedUser authzUser, String userStoreDomain,
                                       String scope, boolean includeExpiredTokens) throws IdentityOAuth2Exception;

    Set<AccessTokenDO> getAccessTokens(String consumerKey, AuthenticatedUser userName,
                                       String userStoreDomain, boolean includeExpired) throws IdentityOAuth2Exception;

    AccessTokenDO getAccessToken(String accessTokenIdentifier, boolean includeExpired) throws IdentityOAuth2Exception;

    Set<String> getAccessTokensByUser(AuthenticatedUser authenticatedUser) throws IdentityOAuth2Exception;

    Set<String> getActiveTokensByConsumerKey(String consumerKey) throws IdentityOAuth2Exception;

    Set<AccessTokenDO> getActiveAcessTokenDataByConsumerKey(String consumerKey) throws IdentityOAuth2Exception;

    Set<AccessTokenDO> getAccessTokensByTenant(int tenantId) throws IdentityOAuth2Exception;

    Set<AccessTokenDO> getAccessTokensOfUserStore(int tenantId, String userStoreDomain) throws
            IdentityOAuth2Exception;

    void revokeAccessTokens(String[] tokens) throws IdentityOAuth2Exception;

    void revokeAccessTokensInBatch(String[] tokens) throws IdentityOAuth2Exception;

    void revokeAccessTokensIndividually(String[] tokens) throws IdentityOAuth2Exception;

    void revokeAccessToken(String tokenId, String userId) throws IdentityOAuth2Exception;

    void invalidateAndCreateNewAccessToken(String oldAccessTokenId, String tokenState, String consumerKey,
                                           String tokenStateId, AccessTokenDO accessTokenDO,
                                           String userStoreDomain) throws IdentityOAuth2Exception;

    void updateUserStoreDomain(int tenantId, String currentUserStoreDomain,
                               String newUserStoreDomain) throws IdentityOAuth2Exception;

    String getTokenIdByAccessToken(String token) throws IdentityOAuth2Exception;

    List<AccessTokenDO> getLatestAccessTokens(String consumerKey, AuthenticatedUser authzUser,
                                              String userStoreDomain, String scope,
                                              boolean includeExpiredTokens, int limit) throws IdentityOAuth2Exception;
}
