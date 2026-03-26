/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.model;

/**
 * Represents the pairing of an OAuth client ID with the tenant domain of the application that owns it.
 * Used to correctly route token operations (revocation, retrieval) to the tenant in which the app is registered,
 * including B2B SaaS scenarios where the same consumer key may exist in both sub-org and root-org tenants.
 */
public class OAuthAppInfo {

    private final String clientId;
    private final String appTenantDomain;

    public OAuthAppInfo(String clientId, String appTenantDomain) {

        this.clientId = clientId;
        this.appTenantDomain = appTenantDomain;
    }

    public String getClientId() {

        return clientId;
    }

    public String getAppTenantDomain() {

        return appTenantDomain;
    }
}
