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

/**
 * Authorization code validation result data object.
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
