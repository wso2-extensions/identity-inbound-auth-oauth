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

import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

/**
 * DefaultOAuth2RevocationProcessor is responsible for handling OAuth2 token revocation
 * when a persistence layer is in use. It provides methods to revoke access tokens and
 * refresh tokens, as well as a mechanism to revoke tokens associated with a specific user.
 */
public class DefaultOAuth2RevocationProcessor implements OAuth2RevocationProcessor {

    @Override
    public void revokeAccessToken(OAuthRevocationRequestDTO revokeRequestDTO, AccessTokenDO accessTokenDO)
            throws IdentityOAuth2Exception {

        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                .revokeAccessTokens(new String[]{accessTokenDO.getAccessToken()});
    }

    @Override
    public void revokeRefreshToken(OAuthRevocationRequestDTO revokeRequestDTO,
                                   RefreshTokenValidationDataDO refreshTokenDO) throws IdentityOAuth2Exception {

        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                .revokeAccessTokens(new String[]{refreshTokenDO.getAccessToken()});
    }

    @Override
    public boolean revokeTokens(String username, UserStoreManager userStoreManager)
            throws UserStoreException {

        return OAuthUtil.revokeTokens(username, userStoreManager);
    }
}
