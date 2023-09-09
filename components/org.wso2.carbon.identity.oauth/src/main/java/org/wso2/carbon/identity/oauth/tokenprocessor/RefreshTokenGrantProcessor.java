/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth.tokenprocessor;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

/**
 * Intermediate processor for handling refresh token persistence logic.
 */
public interface RefreshTokenGrantProcessor {

    /**
     * Validate the refresh token.
     *
     * @param tokenReqMessageContext Token request message context.
     * @return Refresh token validation data.
     * @throws IdentityOAuth2Exception If an error occurred while validating the refresh token.
     */
    RefreshTokenValidationDataDO validateRefreshToken(OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception;

    /**
     * Persist the new access token.
     *
     * @param tokenReqMessageContext Token request message context.
     * @param accessTokenBean        Access token data object.
     * @param userStoreDomain        User store domain.
     * @param clientId               Client ID.
     * @throws IdentityOAuth2Exception If an error occurred while persisting the new access token.
     */
    void persistNewToken(OAuthTokenReqMessageContext tokenReqMessageContext, AccessTokenDO accessTokenBean,
                         String userStoreDomain, String clientId) throws IdentityOAuth2Exception;

    /**
     * Create the access token bean.
     *
     * @param tokReqMsgCtx   Token request message context.
     * @param tokenReq       Token request.
     * @param validationBean Refresh token validation data.
     * @param tokenType      Token type.
     * @return Access token data object.
     * @throws IdentityOAuth2Exception If an error occurred while creating the access token bean.
     */
    AccessTokenDO createAccessTokenBean(OAuthTokenReqMessageContext tokReqMsgCtx, OAuth2AccessTokenReqDTO tokenReq,
                                        RefreshTokenValidationDataDO validationBean, String tokenType)
            throws IdentityOAuth2Exception;

    /**
     * Check whether the refresh token is the latest refresh token.
     *
     * @param tokenReq        Token request.
     * @param validationBean  Refresh token validation data.
     * @param userStoreDomain User store domain.
     * @return True if the refresh token is the latest refresh token.
     * @throws IdentityOAuth2Exception If an error occurred while checking whether the refresh token is the latest
     */
    boolean isLatestRefreshToken(OAuth2AccessTokenReqDTO tokenReq, RefreshTokenValidationDataDO validationBean,
                                 String userStoreDomain) throws IdentityOAuth2Exception;
}
