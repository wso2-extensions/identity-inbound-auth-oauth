/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenBindings.NONE;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.isValidTokenBinding;

/**
 * Handles oauth2 token revocation when persistence layer exists.
 */
public class DefaultOAuth2RevocationProcessor implements OAuth2RevocationProcessor {

    @Override
    public void revokeRefreshToken(OAuthRevocationRequestDTO revokeRequestDTO,
                                  RefreshTokenValidationDataDO refreshTokenDO) throws IdentityOAuth2Exception {
        String tokenBindingReference = NONE;
        if (StringUtils.isNotBlank(refreshTokenDO.getTokenBindingReference())) {
            tokenBindingReference = refreshTokenDO.getTokenBindingReference();
        }
        OAuthUtil.clearOAuthCache(revokeRequestDTO.getConsumerKey(), refreshTokenDO.getAuthorizedUser(),
                OAuth2Util.buildScopeString(refreshTokenDO.getScope()), tokenBindingReference);
        OAuthUtil.clearOAuthCache(revokeRequestDTO.getConsumerKey(), refreshTokenDO.getAuthorizedUser(),
                OAuth2Util.buildScopeString(refreshTokenDO.getScope()));
        OAuthUtil.clearOAuthCache(revokeRequestDTO.getConsumerKey(), refreshTokenDO.getAuthorizedUser());
        OAuthUtil.clearOAuthCache(refreshTokenDO.getAccessToken());
        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                .revokeAccessTokens(new String[] { refreshTokenDO.getAccessToken() });
    }

    @Override
    public void revokeAccessToken(OAuthRevocationRequestDTO revokeRequestDTO, AccessTokenDO accessTokenDO)
            throws IdentityOAuth2Exception, UserIdNotFoundException {
        String tokenBindingReference = NONE;
        if (accessTokenDO.getTokenBinding() != null && StringUtils
                .isNotBlank(accessTokenDO.getTokenBinding().getBindingReference())) {
            tokenBindingReference = accessTokenDO.getTokenBinding().getBindingReference();
        }
        OAuthUtil.clearOAuthCache(revokeRequestDTO.getConsumerKey(), accessTokenDO.getAuthzUser(),
                OAuth2Util.buildScopeString(accessTokenDO.getScope()), tokenBindingReference);
        OAuthUtil.clearOAuthCache(revokeRequestDTO.getConsumerKey(), accessTokenDO.getAuthzUser(),
                OAuth2Util.buildScopeString(accessTokenDO.getScope()));
        OAuthUtil.clearOAuthCache(revokeRequestDTO.getConsumerKey(), accessTokenDO.getAuthzUser());
        OAuthUtil.clearOAuthCache(accessTokenDO);
        String scope = OAuth2Util.buildScopeString(accessTokenDO.getScope());
        String userId = accessTokenDO.getAuthzUser().getUserId();
        synchronized ((revokeRequestDTO.getConsumerKey() + ":" + userId + ":" + scope + ":"
                + tokenBindingReference).intern()) {
            OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                    .revokeAccessTokens(new String[]{accessTokenDO.getAccessToken()});
        }
    }

    @Override
    public RefreshTokenValidationDataDO getRevocableRefreshToken(OAuthRevocationRequestDTO revokeRequestDTO)
            throws IdentityOAuth2Exception {

        RefreshTokenValidationDataDO refreshTokenDO = OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO()
                .validateRefreshToken(revokeRequestDTO.getConsumerKey(), revokeRequestDTO.getToken());
        return refreshTokenDO;
    }

    @Override
    public AccessTokenDO getRevocableAccessToken(OAuthRevocationRequestDTO revokeRequestDTO)
            throws IdentityOAuth2Exception {
        return OAuth2Util.findAccessToken(revokeRequestDTO.getToken(), true);
    }

    @Override
    public boolean validateTokenBinding(OAuthRevocationRequestDTO revokeRequestDTO, AccessTokenDO accessTokenDO)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {
       return ((OAuth2Util.getAppInformationByClientId(accessTokenDO.getConsumerKey()).
                isTokenBindingValidationEnabled()) && (!isValidTokenBinding(accessTokenDO.
                getTokenBinding(), revokeRequestDTO.getRequest())));
    }
}
