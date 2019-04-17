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

import java.util.ArrayList;
import java.util.List;

/**
 * This interface handles all the DAO layer activities which are related to OIDC request object.
 */
public interface RequestObjectDAO {

    /**
     * Store request object related data into related db tables.
     *
     * @param consumerKeyId  consumer key
     * @param sessionDataKey session data key
     * @param claims         request object claims
     * @throws IdentityOAuth2Exception
     */
    void insertRequestObjectData(String consumerKeyId, String sessionDataKey,
                                 List<List<RequestedClaim>> claims)
            throws IdentityOAuth2Exception;


    /**
     * Update request object reference when the code or the token is generated.
     *
     * @param sessionDataKey session data key
     * @param codeId         code id
     * @throws IdentityOAuth2Exception
     */
    void updateRequestObjectReferencebyCodeId(String sessionDataKey, String codeId)
            throws IdentityOAuth2Exception;

    /**
     * Update request object reference when the code or the token is generated.
     *
     * @param sessionDataKey session data key
     * @param accessTokenId  accessTokenId
     * @throws IdentityOAuth2Exception
     */
    void updateRequestObjectReferencebyTokenId(String sessionDataKey, String accessTokenId)
            throws IdentityOAuth2Exception;

    /**
     * Delete request object reference in code revoke.
     *
     * @param codeId code id
     * @throws IdentityOAuth2Exception
     * @throws IdentityOAuthAdminException
     */

    void deleteRequestObjectReferenceByCode(String codeId) throws IdentityOAuth2Exception,
            IdentityOAuthAdminException;

    /**
     * Delete request object reference by token id in a token revoke.
     *
     * @param tokenId token id
     * @throws IdentityOAuthAdminException
     */
    void deleteRequestObjectReferenceByTokenId(String tokenId) throws IdentityOAuthAdminException;


    /**
     * Retrieve essential claims for the sessionDataKey and user info endpoint.
     *
     * @param sessionDataKey sessionDataKey
     * @param isUserInfo isUserInfo
     * @return
     * @throws IdentityOAuth2Exception
     */
    default List<RequestedClaim> getRequestedClaimsbySessionDataKey(String sessionDataKey, boolean isUserInfo) throws
            IdentityOAuth2Exception{
        return new ArrayList<>();
    }

    /**
     * Retrieve essential claims for the id token and user info endpoint.
     *
     * @param token token id
     * @param isUserInfo return true if the claims are requested from user info end point.
     * @return
     * @throws IdentityOAuth2Exception
     */
    List<RequestedClaim> getRequestedClaims(String token, boolean isUserInfo) throws
            IdentityOAuth2Exception;

    /**
     * Updates refresh token whe refresh token is issued.
     *
     * @param oldAccessToken old access token id
     * @param newAccessToken new access token id
     * @throws IdentityOAuth2Exception
     */
    void refreshRequestObjectReference(String oldAccessToken, String newAccessToken) throws IdentityOAuth2Exception;

    /**
     * Updates code to token once a token is issued.
     *
     * @param codeId code id
     * @param tokenId token id
     * @throws IdentityOAuth2Exception
     */
    void updateRequestObjectReferenceCodeToToken(String codeId, String tokenId) throws IdentityOAuth2Exception;
}
