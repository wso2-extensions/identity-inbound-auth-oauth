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

package org.wso2.carbon.identity.oauth.endpoint.util.factory;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;

/**
 * Factory class for OAuth2TokenValidatorService.
 */
public class OAuth2TokenValidatorServiceFactory {

    private static final OAuth2TokenValidationService SERVICE;

    static {
        OAuth2TokenValidationService oAuth2TokenValidatorService = (OAuth2TokenValidationService)
                PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getOSGiService(OAuth2TokenValidationService.class, null);

        if (oAuth2TokenValidatorService == null) {
            throw new IllegalStateException("OAuth2TokenValidatorService is not available from OSGI context.");
        }
        SERVICE = oAuth2TokenValidatorService;
    }

    public static OAuth2TokenValidationService getOAuth2TokenValidatorService() {

        return SERVICE;
    }
}
