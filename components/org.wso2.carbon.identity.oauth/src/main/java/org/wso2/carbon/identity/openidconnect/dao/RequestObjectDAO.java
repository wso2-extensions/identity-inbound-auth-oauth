/*
 *
 *   Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.openidconnect.dao;

import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;

import java.util.List;

/**
 * This interface handles all the DAO layer activities which are related to OIDC request object.
 */
public interface RequestObjectDAO {

    void insertRequestObjectData(String consumerKeyId, String codeId,
                                 String accessTokenId, String sessionDataKey, List<List<RequestedClaim>> claims)
            throws IdentityOAuth2Exception;

    void updateRequestObjectReference(String sessionDataKey, String codeId, String accessTokenId)
            throws IdentityOAuth2Exception;

    void deleteRequestObjectReference(String tokenId, String codeId) throws IdentityOAuth2Exception,
            IdentityOAuthAdminException;

    List<String> getEssentialClaims(String tokenId, String codeId, boolean isUserInfo) throws IdentityOAuth2Exception;
}
