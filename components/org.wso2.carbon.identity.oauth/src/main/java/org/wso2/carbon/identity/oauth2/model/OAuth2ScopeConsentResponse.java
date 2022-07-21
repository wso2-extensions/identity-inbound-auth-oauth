/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.model;

import java.util.List;

/**
 * OAuth scope user consent service response object.
 */
public class OAuth2ScopeConsentResponse {

    private String userId;
    private String appId;
    private int tenantId;
    private List<String> approvedScopes;
    private List<String> deniedScopes;

    public OAuth2ScopeConsentResponse(String userId, String appId, int tenantId, List<String> approvedScopes,
                                      List<String> deniedScopes) {

        this.userId = userId;
        this.appId = appId;
        this.tenantId = tenantId;
        this.approvedScopes = approvedScopes;
        this.deniedScopes = deniedScopes;
    }

    public OAuth2ScopeConsentResponse(String userId, String appId, int tenantId, List<String> approvedScopes) {

        new OAuth2ScopeConsentResponse(userId, appId, tenantId, approvedScopes, null);
    }

    public String getAppId() {

        return appId;
    }

    public String getUserId() {

        return userId;
    }

    public int getTenantId() {

        return tenantId;
    }

    public List<String> getApprovedScopes() {

        return approvedScopes;
    }

    public List<String> getDeniedScopes() {

        return deniedScopes;
    }
}
