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

import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.AuthorizationCodeState.ACTIVE;
/*
NOTE
This is the very first step of moving to simplified architecture for token persistence. New set of DAO classes  for
each purpose  and factory class to get instance of each DAO classes were introduced  during  this step. Further methods
 on org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO were distributed among new set of classes, each of these method
 need to be reviewed  and refactored  during next step.
 */
public class AuthorizationCodeValidationResult {

    private AuthzCodeDO authzCodeDO;
    private String tokenId;

    public AuthorizationCodeValidationResult(AuthzCodeDO codeDO, String tokenId) {

        this.authzCodeDO = codeDO;
        this.tokenId = tokenId;
    }

    public boolean isActiveCode() {

        return ACTIVE.equals(authzCodeDO.getState());
    }

    public AuthzCodeDO getAuthzCodeDO() {

        return authzCodeDO;
    }

    public String getTokenId() {

        return tokenId;
    }
}
