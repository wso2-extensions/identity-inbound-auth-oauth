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
import org.wso2.carbon.identity.oauth2.OAuth2ScopeService;

/**
 * Factory class for OAuth2ScopeService.
 */
public class Oauth2ScopeServiceFactory {

    private static final OAuth2ScopeService SERVICE;

    static {
        OAuth2ScopeService oAuth2ScopeService = (OAuth2ScopeService) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(OAuth2ScopeService.class, null);

        if (oAuth2ScopeService == null) {
            throw new IllegalStateException("OAuth2ScopeService is not available from OSGI context.");
        }
        SERVICE = oAuth2ScopeService;
    }

    public static OAuth2ScopeService getOAuth2ScopeService() {

        return SERVICE;
    }
}
