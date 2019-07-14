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
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;

import java.util.List;
import java.util.Set;
/*
NOTE
This is the very first step of moving to simplified architecture for token persistence. New set of DAO classes  for
each purpose  and factory class to get instance of each DAO classes were introduced  during  this step. Further methods
 on org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO were distributed among new set of classes, each of these method
 need to be reviewed  and refactored  during next step.
 */
public interface AuthorizationCodeDAO {

    void insertAuthorizationCode(String authzCode, String consumerKey, String callbackUrl,
                                 AuthzCodeDO authzCodeDO) throws IdentityOAuth2Exception;

    void deactivateAuthorizationCodes(List<AuthzCodeDO> authzCodeDOs) throws IdentityOAuth2Exception;

    AuthorizationCodeValidationResult validateAuthorizationCode(String consumerKey, String authorizationKey)
            throws IdentityOAuth2Exception;

    void updateAuthorizationCodeState(String authzCode, String newState) throws IdentityOAuth2Exception;

    void deactivateAuthorizationCode(AuthzCodeDO authzCodeDO) throws
            IdentityOAuth2Exception;

    Set<String> getAuthorizationCodesByUser(AuthenticatedUser authenticatedUser) throws
            IdentityOAuth2Exception;

    default List<AuthzCodeDO> getAuthorizationCodesByUserForOpenidScope(AuthenticatedUser authenticatedUser) throws
            IdentityOAuth2Exception{

        return null;
    }

    Set<String> getAuthorizationCodesByConsumerKey(String consumerKey) throws IdentityOAuth2Exception;

    Set<String> getActiveAuthorizationCodesByConsumerKey(String consumerKey) throws IdentityOAuth2Exception;

    List<AuthzCodeDO> getLatestAuthorizationCodesByTenant(int tenantId) throws IdentityOAuth2Exception;

    List<AuthzCodeDO> getLatestAuthorizationCodesByUserStore(int tenantId, String userStorDomain) throws
            IdentityOAuth2Exception;

    void updateUserStoreDomain(int tenantId, String currentUserStoreDomain, String
            newUserStoreDomain) throws IdentityOAuth2Exception;

    String getCodeIdByAuthorizationCode(String authzCode) throws IdentityOAuth2Exception;
}
