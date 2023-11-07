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
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

/**
 * Default implementation of TokenProvider for scenarios with token persistence enabled.
 * Verifies access tokens by querying the database, including optional inclusion of expired tokens.
 */
public class DefaultTokenProvider implements TokenProvider {

    @Override
    public AccessTokenDO getVerifiedAccessToken(String accessToken, boolean includeExpired)
            throws IdentityOAuth2Exception {

        return OAuth2Util.findAccessToken(accessToken, includeExpired);
    }

    @Override
    public RefreshTokenValidationDataDO getVerifiedRefreshToken(String refreshToken, String consumerKey)
            throws IdentityOAuth2Exception {

        return OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO().validateRefreshToken(consumerKey,
                refreshToken);
    }

    @Override
    public AccessTokenDO getVerifiedRefreshToken(String refreshToken) throws IdentityOAuth2Exception {

        return OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO().getRefreshToken(refreshToken);
    }
}
