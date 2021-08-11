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

package org.wso2.carbon.identity.oauth2.internal.cache;

import org.wso2.carbon.identity.core.cache.CacheEntry;
import org.wso2.carbon.identity.oauth2.model.UserApplicationScopeConsentDO;

/**
 * Cache entry for User Consented Scope.
 */
public class OAuthUserConsentedScopeCacheEntry extends CacheEntry {

    private String appID;
    private UserApplicationScopeConsentDO userApplicationScopeConsentDO;

    public OAuthUserConsentedScopeCacheEntry(String appId, UserApplicationScopeConsentDO userConsent) {

        this.appID = appId;
        this.userApplicationScopeConsentDO = userConsent;

    }

    public String getAppID() {

        return appID;
    }

    public void setAppID(String appID) {

        this.appID = appID;
    }

    public UserApplicationScopeConsentDO getUserApplicationScopeConsentDO() {

        return userApplicationScopeConsentDO;
    }

    public void setUserApplicationScopeConsentDO(UserApplicationScopeConsentDO userApplicationScopeConsentDO) {

        this.userApplicationScopeConsentDO = userApplicationScopeConsentDO;
    }
}
