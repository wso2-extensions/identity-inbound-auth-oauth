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

import java.util.ArrayList;
import java.util.List;

/**
 * OAuth scope user consent data object.
 */
public class UserApplicationScopeConsentDO {

    private String appId;
    private List<String> approvedScopes;
    private List<String> deniedScopes;


    public UserApplicationScopeConsentDO(String appId, List<String> approvedScopes, List<String> deniedScopes) {

        this.appId = appId;
        setApprovedScopes(approvedScopes);
        setDeniedScopes(deniedScopes);
    }

    public UserApplicationScopeConsentDO(String appId) {

        this.appId = appId;
        this.deniedScopes = new ArrayList<>();
        this.approvedScopes = new ArrayList<>();
    }

    public String getAppId() {

        return appId;
    }

    public void setAppId(String appId) {

        this.appId = appId;
    }

    public List<String> getApprovedScopes() {

        return approvedScopes;
    }

    public void setApprovedScopes(List<String> approvedScopes) {

        if (approvedScopes == null) {
            this.approvedScopes = new ArrayList<>();
        } else {
            this.approvedScopes = approvedScopes;
        }
    }

    public List<String> getDeniedScopes() {

        return deniedScopes;
    }

    public void setDeniedScopes(List<String> deniedScopes) {

        if (deniedScopes == null) {
            this.deniedScopes = new ArrayList<>();
        } else {
            this.deniedScopes = deniedScopes;
        }
    }
}
