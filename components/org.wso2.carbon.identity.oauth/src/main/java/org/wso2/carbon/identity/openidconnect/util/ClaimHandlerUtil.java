/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openidconnect.util;

import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.openidconnect.CustomClaimsCallbackHandler;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ENABLE_CLAIMS_SEPARATION_FOR_ACCESS_TOKEN;

/**
 * Utility methods for the claim handler related functionality.
 */
public class ClaimHandlerUtil {

    public static CustomClaimsCallbackHandler getClaimsCallbackHandler(OAuthAppDO oAuthAppDO) {

        // If JWT access token OIDC claims separation is enabled and the application is configured to separate OIDC
        // claims, use the JWTAccessTokenOIDCClaimsHandler to handle custom claims.
        if (isAccessTokenClaimsSeparationFeatureEnabled() && oAuthAppDO.isAccessTokenClaimsSeparationEnabled()) {
            return OAuthServerConfiguration.getInstance().getJWTAccessTokenOIDCClaimsHandler();
        }
        return OAuthServerConfiguration.getInstance().getOpenIDConnectCustomClaimsCallbackHandler();
    }

    private static boolean isAccessTokenClaimsSeparationFeatureEnabled() {

        return Boolean.parseBoolean(IdentityUtil.getProperty(ENABLE_CLAIMS_SEPARATION_FOR_ACCESS_TOKEN));
    }
}
